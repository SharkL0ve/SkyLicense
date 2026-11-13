/// Memory protection primitives for hot-path data.
/// Provides XOR-encrypted caching, TTL-based key expiry, and pointer mask rotation.
/// Designed for minimal performance overhead on the JNI call hot path.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use fxhash::FxHashMap;
use zeroize::Zeroize;

// ============================================================
// XOR Cache Key — rotates with encryption key rotation
// ============================================================

/// Runtime-random key for XOR-encrypting cached values.
/// Rotated periodically so dumped memory is useless.
static CACHE_XOR_KEY: OnceLock<RwLock<CacheXorState>> = OnceLock::new();

struct CacheXorState {
    key: [u8; 32],
    generation: u64,
}

impl Drop for CacheXorState {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn get_xor_state() -> &'static RwLock<CacheXorState> {
    CACHE_XOR_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        RwLock::new(CacheXorState { key, generation: 0 })
    })
}

/// XOR-encrypt a string using the current cache key.
/// Returns (encrypted_bytes, generation) so we know which key was used.
#[inline]
pub fn xor_encrypt_string(plaintext: &str) -> (Vec<u8>, u64) {
    let state = get_xor_state().read().unwrap();
    let key = &state.key;
    let generation = state.generation;
    let bytes = plaintext.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    for (i, &b) in bytes.iter().enumerate() {
        out.push(b ^ key[i % 32]);
    }
    (out, generation)
}

/// XOR-decrypt bytes back to string using the current cache key.
/// Returns None if generation mismatch (key was rotated, cache entry is stale).
#[inline]
pub fn xor_decrypt_string(ciphertext: &[u8], stored_gen: u64) -> Option<String> {
    let state = get_xor_state().read().unwrap();
    if state.generation != stored_gen {
        return None; // Key rotated, entry is stale
    }
    let key = &state.key;
    let mut out = Vec::with_capacity(ciphertext.len());
    for (i, &b) in ciphertext.iter().enumerate() {
        out.push(b ^ key[i % 32]);
    }
    String::from_utf8(out).ok()
}

/// Rotate the XOR cache key. Call this when encryption keys rotate.
/// New key is derived from code integrity anchors — patched code = wrong key = garbage strings.
pub fn rotate_cache_xor_key() {
    let mut state = get_xor_state().write().unwrap();
    state.key.zeroize();

    // Random component
    let mut random_part = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_part);

    // Code integrity components
    let a2 = crate::integrity::anchor_2();
    let a3 = crate::integrity::anchor_3();

    // Stochastic: ~30% of rotations also include anchor_6
    let include_extra = (random_part[31] % 10) < 3;
    let a6 = if include_extra {
        crate::integrity::anchor_6()
    } else {
        a2
    };

    // Derive new XOR key: SHA256(random || a2 || a3 || a6)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&random_part);
    hasher.update(&a2);
    hasher.update(&a3);
    hasher.update(&a6);
    state.key = hasher.finalize().into();
    state.generation = state.generation.wrapping_add(1);
}

/// Get current XOR key generation (for checking staleness without locking)
pub fn current_xor_generation() -> u64 {
    get_xor_state().read().unwrap().generation
}

// ============================================================
// TTL Cache for master password
// ============================================================

/// Master password cache with automatic expiry and zeroization.
/// The password is only held in memory for `TTL` seconds, then cleared.
/// Next access re-derives it from code hash + fragments.
static MASTER_KEY_CACHE: OnceLock<Mutex<TtlSecret>> = OnceLock::new();

const MASTER_KEY_TTL_SECS: u64 = 30;

struct TtlSecret {
    value: Option<String>,
    expires_at: Instant,
}

impl Drop for TtlSecret {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.value {
            unsafe { v.as_mut_vec().iter_mut().for_each(|b| *b = 0); }
        }
    }
}

/// Get the master password, re-deriving if expired.
/// The derive_fn is only called when the cache is empty or expired.
pub fn get_master_password<F>(derive_fn: F) -> String
where
    F: FnOnce() -> String,
{
    let cache = MASTER_KEY_CACHE.get_or_init(|| {
        Mutex::new(TtlSecret {
            value: None,
            expires_at: Instant::now(),
        })
    });

    let mut guard = cache.lock().unwrap();

    // Check if cached value is still valid
    if let Some(ref val) = guard.value {
        if Instant::now() < guard.expires_at {
            return val.clone();
        }
        // Expired — zeroize
        unsafe {
            guard.value.as_mut().unwrap().as_mut_vec().iter_mut().for_each(|b| *b = 0);
        }
        guard.value = None;
    }

    // Re-derive
    let fresh = derive_fn();
    guard.value = Some(fresh.clone());
    guard.expires_at = Instant::now() + Duration::from_secs(MASTER_KEY_TTL_SECS);
    fresh
}

// ============================================================
// Pointer mask rotation
// ============================================================

/// Rotating pointer mask. Stores current and previous mask for transition period.
static POINTER_MASK_STATE: OnceLock<RwLock<PointerMaskState>> = OnceLock::new();

pub struct PointerMaskState {
    pub current: usize,
    pub previous: usize,
    pub generation: u64,
}

pub fn get_pointer_mask_state() -> &'static RwLock<PointerMaskState> {
    POINTER_MASK_STATE.get_or_init(|| {
        let mut buf = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let mask = usize::from_ne_bytes(buf);
        RwLock::new(PointerMaskState {
            current: mask,
            previous: mask,
            generation: 0,
        })
    })
}

/// Get the current pointer mask (fast path — read lock only)
#[inline]
pub fn get_current_pointer_mask() -> usize {
    get_pointer_mask_state().read().unwrap().current
}

/// Rotate the pointer mask. Returns (old_mask, new_mask) for re-encoding cached pointers.
/// The new mask is derived from code integrity anchors — patched code = wrong mask = crash.
pub fn rotate_pointer_mask() -> (usize, usize) {
    let mut state = get_pointer_mask_state().write().unwrap();
    let old = state.current;

    // Random seed
    let mut random_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_seed);

    // Mix code integrity anchors into mask derivation (NO conditional branch)
    let a1 = crate::integrity::anchor_1();
    let a3 = crate::integrity::anchor_3();

    // Every 3rd rotation, also include anchor_5 (staggered timing)
    let rotation = state.generation;
    let a5 = if rotation % 3 == 0 {
        crate::integrity::anchor_5()
    } else {
        a1
    };

    // Derive mask: HMAC(random_seed, a1 || a3 || a5)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&random_seed).unwrap();
    mac.update(&a1);
    mac.update(&a3);
    mac.update(&a5);
    let derived = mac.finalize().into_bytes();

    let new_mask = usize::from_ne_bytes(derived[0..8].try_into().unwrap());
    state.previous = old;
    state.current = new_mask;
    state.generation = state.generation.wrapping_add(1);
    (old, new_mask)
}

// ============================================================
// Violation counter with time-decay
// ============================================================

static VIOLATION_COUNTER: OnceLock<Mutex<ViolationTracker>> = OnceLock::new();

struct ViolationTracker {
    count: u32,
    last_decay: Instant,
}

const VIOLATION_THRESHOLD: u32 = 3;
const VIOLATION_DECAY_INTERVAL_SECS: u64 = 60;

pub fn get_violation_tracker() -> &'static Mutex<ViolationTracker> {
    VIOLATION_COUNTER.get_or_init(|| {
        Mutex::new(ViolationTracker {
            count: 0,
            last_decay: Instant::now(),
        })
    })
}

/// Add violations and check if threshold exceeded. Returns true if threshold hit.
pub fn add_violation(amount: u32) -> bool {
    let mut tracker = get_violation_tracker().lock().unwrap();

    // Apply decay
    let elapsed = tracker.last_decay.elapsed().as_secs();
    if elapsed >= VIOLATION_DECAY_INTERVAL_SECS {
        let decay_amount = (elapsed / VIOLATION_DECAY_INTERVAL_SECS) as u32;
        tracker.count = tracker.count.saturating_sub(decay_amount);
        tracker.last_decay = Instant::now();
    }

    tracker.count = tracker.count.saturating_add(amount);
    tracker.count >= VIOLATION_THRESHOLD
}

// ============================================================
// Hardware breakpoint detection (Windows)
// ============================================================

/// Check if hardware breakpoints are set on the current thread (DR0-DR3).
/// Returns true if any debug register is non-zero.
#[cfg(target_os = "windows")]
pub fn detect_hardware_breakpoints() -> bool {
    unsafe {
        use winapi::um::processthreadsapi::GetCurrentThread;
        use winapi::um::winnt::CONTEXT;
        use winapi::um::winnt::CONTEXT_DEBUG_REGISTERS;

        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        let thread = GetCurrentThread();
        if winapi::um::processthreadsapi::GetThreadContext(thread, &mut ctx) != 0 {
            return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
        }
    }
    false
}

#[cfg(target_os = "linux")]
pub fn detect_hardware_breakpoints() -> bool {
    // Linux: hardware breakpoints are set via ptrace, which we already detect
    // via TracerPid check. No additional check needed here.
    false
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn detect_hardware_breakpoints() -> bool { false }

// ============================================================
// Process handle monitoring (Windows)
// ============================================================

/// Check if any external process holds a handle to us with VM_READ access.
#[cfg(target_os = "windows")]
pub fn detect_external_memory_handles() -> bool {
    // Use NtQuerySystemInformation(SystemHandleInformation) to enumerate handles.
    // This is expensive, so call sparingly (every 5-10s).
    unsafe {
        use winapi::um::processthreadsapi::GetCurrentProcessId;

        let our_pid = GetCurrentProcessId();
        let mut buffer_size: u32 = 1024 * 1024; // 1MB initial
        let mut buffer = vec![0u8; buffer_size as usize];

        // SystemHandleInformation = 16
        let mut return_length: u32 = 0;
        let status = NtQuerySystemInformation(
            16,
            buffer.as_mut_ptr() as *mut _,
            buffer_size,
            &mut return_length,
        );

        // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
        if status == 0xC0000004u32 as i32 {
            buffer_size = return_length + 4096;
            buffer.resize(buffer_size as usize, 0);
            let status = NtQuerySystemInformation(
                16,
                buffer.as_mut_ptr() as *mut _,
                buffer_size,
                &mut return_length,
            );
            if status != 0 {
                return false;
            }
        } else if status != 0 {
            return false;
        }

        // Parse SYSTEM_HANDLE_INFORMATION structure
        // First 4/8 bytes = NumberOfHandles (usize on 64-bit)
        let handle_count = *(buffer.as_ptr() as *const u32);

        // Each entry is SYSTEM_HANDLE_TABLE_ENTRY_INFO (16 bytes on x64):
        // u16 ProcessId, u8 ObjectTypeNumber, u8 Flags, u16 Handle, *void Object, u32 GrantedAccess
        let entry_offset = std::mem::size_of::<usize>(); // skip count field
        let entry_size = 24; // approximate size on x64

        // PROCESS_VM_READ = 0x0010
        const PROCESS_VM_READ: u32 = 0x0010;
        // Process object type is typically 7 on Windows 10+
        const PROCESS_OBJECT_TYPE: u8 = 7;

        for i in 0..handle_count as usize {
            let offset = entry_offset + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let pid = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]);
            let obj_type = buffer[offset + 2];
            let granted_access = u32::from_ne_bytes([
                buffer[offset + 16], buffer[offset + 17],
                buffer[offset + 18], buffer[offset + 19],
            ]);

            // Skip our own process handles
            if pid as u32 == our_pid {
                continue;
            }

            // Check if another process has a handle to a process object with VM_READ
            if obj_type == PROCESS_OBJECT_TYPE && (granted_access & PROCESS_VM_READ) != 0 {
                // This could be a handle to our process — can't easily verify target
                // but the presence of VM_READ handles from other processes is suspicious
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut std::ffi::c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

#[cfg(not(target_os = "windows"))]
pub fn detect_external_memory_handles() -> bool { false }

// ============================================================
// Linux: PR_SET_DUMPABLE
// ============================================================

/// Disable core dumps and restrict /proc/pid/mem access on Linux.
/// Call once at startup.
pub fn disable_process_dump() {
    #[cfg(target_os = "linux")]
    unsafe {
        // PR_SET_DUMPABLE = 4, 0 = not dumpable
        libc::prctl(4, 0, 0, 0, 0);
    }
}

