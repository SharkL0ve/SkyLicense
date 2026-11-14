/// Memory protection primitives for hot-path data.
/// Provides XOR-encrypted caching, TTL-based key expiry, and pointer mask rotation.
/// Designed for minimal performance overhead on the JNI call hot path.
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

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
    let state = get_xor_state()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let state = get_xor_state()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let mut state = get_xor_state()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.key.zeroize();

    // Random component
    let mut random_part = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *random_part);

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
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(*random_part);
    hasher.update(a2);
    hasher.update(a3);
    hasher.update(a6);
    let mut derived = hasher.finalize();
    state.key.copy_from_slice(&derived);
    derived.zeroize();
    state.generation = state.generation.wrapping_add(1);
}

/// Get current XOR key generation (for checking staleness without locking)
pub fn current_xor_generation() -> u64 {
    get_xor_state()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .generation
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

impl Drop for PointerMaskState {
    fn drop(&mut self) {
        self.current.zeroize();
        self.previous.zeroize();
    }
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
    get_pointer_mask_state()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .current
}

/// Rotate the pointer mask. Returns (old_mask, new_mask) for re-encoding cached pointers.
/// The new mask is derived from code integrity anchors — patched code = wrong mask = crash.
pub fn rotate_pointer_mask() -> (usize, usize) {
    let mut state = get_pointer_mask_state()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let old = state.current;

    // Random seed
    let mut random_seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *random_seed);

    // Mix code integrity anchors into mask derivation (NO conditional branch)
    let a1 = crate::integrity::anchor_1();
    let a3 = crate::integrity::anchor_3();

    // Every 3rd rotation, also include anchor_5 (staggered timing)
    let rotation = state.generation;
    let a5 = if rotation.is_multiple_of(3) {
        crate::integrity::anchor_5()
    } else {
        a1
    };

    // Derive mask: HMAC(random_seed, a1 || a3 || a5)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(&*random_seed) else {
        return (old, old);
    };
    mac.update(&a1);
    mac.update(&a3);
    mac.update(&a5);
    let mut derived = mac.finalize().into_bytes();

    let new_mask = usize::from_ne_bytes([
        derived[0], derived[1], derived[2], derived[3], derived[4], derived[5], derived[6],
        derived[7],
    ]);
    derived.zeroize();
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

fn get_violation_tracker() -> &'static Mutex<ViolationTracker> {
    VIOLATION_COUNTER.get_or_init(|| {
        Mutex::new(ViolationTracker {
            count: 0,
            last_decay: Instant::now(),
        })
    })
}

/// Add violations and check if threshold exceeded. Returns true if threshold hit.
pub fn add_violation(amount: u32) -> bool {
    let mut tracker = get_violation_tracker()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

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
pub fn detect_hardware_breakpoints() -> bool {
    false
}

// ============================================================
// Process handle monitoring (Windows)
// ============================================================

/// External handle inspection is intentionally disabled until each candidate
/// handle can be duplicated and proven to target this process. The previous
/// implementation treated VM_READ handles to *any* process as an attack.
#[deprecated(note = "use a verified SystemExtendedHandleInformation implementation")]
pub fn detect_external_memory_handles() -> bool {
    false
}

// ============================================================
// Linux: PR_SET_DUMPABLE
// ============================================================

/// Disable core dumps and restrict /proc/pid/mem access on Linux.
/// Call once at startup.
pub fn disable_process_dump() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    unsafe {
        let dumpable_result = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let core_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rlimit_result = libc::setrlimit(libc::RLIMIT_CORE, &core_limit);

        if dumpable_result != 0 || rlimit_result != 0 {
            return Err(format!(
                "PR_SET_DUMPABLE={dumpable_result}, setrlimit(RLIMIT_CORE)={rlimit_result}"
            ));
        }
    }
    Ok(())
}

/// Irreversibly clear process-local cache secrets after revocation or tamper.
///
/// The surrounding security state prevents these caches from being used again.
/// Generations are advanced so any values copied before destruction are stale.
pub fn destroy_runtime_secrets() {
    if let Some(state) = CACHE_XOR_KEY.get()
        && let Ok(mut state) = state.write()
    {
        state.key.zeroize();
        state.generation = state.generation.wrapping_add(1);
    }

    if let Some(state) = POINTER_MASK_STATE.get()
        && let Ok(mut state) = state.write()
    {
        state.current = 0;
        state.previous = 0;
        state.generation = state.generation.wrapping_add(1);
    }
}
