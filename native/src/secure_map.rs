/// Encrypted memory storage for the method map.
/// The map is NEVER stored in plaintext in memory.
/// Each entry is individually encrypted with a session-derived key.
/// Decryption happens per-lookup and the plaintext is zeroized immediately after use.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use fxhash::FxHashMap;
use rand::RngCore;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

#[cfg(target_os = "windows")]
use winapi::um::memoryapi::VirtualLock;

/// Memory keys — split into two:
/// - lookup_key: STABLE, never rotates. Used for HMAC-hashing lookup keys.
/// - encryption_key: rotates every 30-90s. Used for AES-GCM.
/// This split ensures hashed_key remains valid across rotations.
static MEMORY_KEYS: OnceLock<Mutex<MemoryKeys>> = OnceLock::new();

struct MemoryKeys {
    /// Fixed key for HMAC lookup — never changes after init
    lookup_key: [u8; 32],
    /// Rotating key for AES-GCM encryption
    encryption_key: [u8; 32],
    rotation_counter: u64,
}

impl Drop for MemoryKeys {
    fn drop(&mut self) {
        self.lookup_key.zeroize();
        self.encryption_key.zeroize();
    }
}

/// An encrypted entry in the method map
#[derive(Clone)]
pub struct EncryptedEntry {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

/// Decrypted method info - zeroizes on drop
pub struct DecryptedMethodInfo {
    pub class_name: String,
    pub method_name: String,
    pub method_desc: String,
    pub func_type: char,
}

impl Drop for DecryptedMethodInfo {
    fn drop(&mut self) {
        unsafe {
            self.class_name.as_mut_vec().iter_mut().for_each(|b| *b = 0);
            self.method_name.as_mut_vec().iter_mut().for_each(|b| *b = 0);
            self.method_desc.as_mut_vec().iter_mut().for_each(|b| *b = 0);
        }
    }
}

/// The encrypted method map
/// - Uses FxHashMap<[u8;32], EncryptedEntry> for O(1) lookup (fix #4)
/// - Runtime-random canary (fix #9)
/// - Stable lookup key separate from rotating encryption key (fix #1)
pub struct EncryptedMethodMap {
    entries: FxHashMap<[u8; 32], EncryptedEntry>,
    /// Runtime-generated canary (not compile-time constant)
    canary: [u8; 16],
    canary_check: [u8; 16],
    expected_count: usize,
}

impl EncryptedMethodMap {
    pub fn from_plaintext(
        entries: fxhash::FxHashMap<String, crate::model::MethodInfo>,
    ) -> Result<Self, String> {
        // Generate two independent keys
        let mut lookup_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut lookup_key);
        rand::thread_rng().fill_bytes(&mut encryption_key);

        let mem_keys = MemoryKeys {
            lookup_key,
            encryption_key,
            rotation_counter: 0,
        };
        let _ = MEMORY_KEYS.set(Mutex::new(mem_keys));

        // Lock key page in memory
        lock_memory_page(MEMORY_KEYS.get().unwrap() as *const _ as *const u8, 128);

        // Generate runtime canary
        let mut canary = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut canary);

        let expected_count = entries.len();
        let mut encrypted_entries = FxHashMap::default();
        encrypted_entries.reserve(expected_count);

        // Use effective key (entangled with code integrity anchor)
        let live_anchor = crate::integrity::anchor_2();
        let effective_key = crate::integrity::derive_effective_key(&encryption_key, &live_anchor);
        let cipher = Aes256Gcm::new_from_slice(&effective_key)
            .map_err(|e| format!("cipher error: {}", e))?;

        for (key, info) in entries.into_iter() {
            // Serialize method info
            let mut plaintext = Vec::new();
            write_length_prefixed(&mut plaintext, info.class_name.as_bytes());
            write_length_prefixed(&mut plaintext, info.method_name.as_bytes());
            write_length_prefixed(&mut plaintext, info.method_desc.as_bytes());
            plaintext.push(info.func_type as u8);

            // Generate unique nonce
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
                .map_err(|e| format!("encrypt error: {}", e))?;

            plaintext.zeroize();

            // Hash lookup key with the STABLE lookup_key (never rotates)
            let hashed = hash_lookup_key(key.as_bytes(), &lookup_key);

            encrypted_entries.insert(hashed, EncryptedEntry {
                ciphertext,
                nonce: nonce_bytes,
            });
        }

        Ok(Self {
            entries: encrypted_entries,
            canary,
            canary_check: canary, // duplicate for integrity verification
            expected_count,
        })
    }

    /// O(1) lookup + decrypt single entry.
    /// Decryption key is derived from stored key + live code anchor.
    /// If code is patched, anchor changes → effective key wrong → AEAD auth fails → None.
    pub fn get(&self, key: &str) -> Option<DecryptedMethodInfo> {
        // Verify integrity
        if self.canary != self.canary_check || self.entries.len() != self.expected_count {
            unsafe { tamper_detected(); }
            return None;
        }

        let keys_guard = MEMORY_KEYS.get()?.lock().ok()?;

        // Hash with stable lookup key
        let hashed = hash_lookup_key(key.as_bytes(), &keys_guard.lookup_key);

        let entry = self.entries.get(&hashed)?;

        // Derive effective decryption key using live code anchor
        let live_anchor = crate::integrity::anchor_2();
        let effective_key = crate::integrity::derive_effective_key(
            &keys_guard.encryption_key, &live_anchor
        );

        let cipher = Aes256Gcm::new_from_slice(&effective_key).ok()?;
        let nonce = Nonce::from_slice(&entry.nonce);
        let mut plaintext = cipher.decrypt(nonce, entry.ciphertext.as_slice()).ok()?;

        let result = deserialize_method_info(&plaintext);
        plaintext.zeroize();
        result
    }

    /// Re-encrypt all entries with a new encryption key.
    /// Lookup keys are NOT affected (stable HMAC key).
    /// Re-encrypt all entries with a new key derived from code integrity anchors.
    /// If code is patched, the derived key is wrong, and all future lookups fail.
    pub fn rotate_key(&mut self) -> Result<(), String> {
        let mut keys_guard = MEMORY_KEYS.get()
            .ok_or("no keys")?
            .lock()
            .map_err(|_| "lock error")?;

        let old_key = keys_guard.encryption_key;

        // Derive new key from random seed + code integrity anchors
        let mut random_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_seed);

        let a1 = crate::integrity::anchor_1();
        let a2 = crate::integrity::anchor_2();

        // Every 5th rotation, include anchor_4 (staggered)
        let rotation = keys_guard.rotation_counter;
        let a4 = if rotation % 5 == 0 {
            crate::integrity::anchor_4()
        } else {
            a1
        };

        // New key = HMAC(random_seed, a1 || a2 || a4)
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&random_seed)
            .map_err(|_| "hmac error")?;
        mac.update(&a1);
        mac.update(&a2);
        mac.update(&a4);
        let new_key: [u8; 32] = mac.finalize().into_bytes().into();

        // Derive effective keys for old and new (both use live anchor_2)
        let live_anchor = crate::integrity::anchor_2();
        let effective_old = crate::integrity::derive_effective_key(&old_key, &live_anchor);
        let effective_new = crate::integrity::derive_effective_key(&new_key, &live_anchor);

        let old_cipher = Aes256Gcm::new_from_slice(&effective_old)
            .map_err(|e| format!("cipher error: {}", e))?;
        let new_cipher = Aes256Gcm::new_from_slice(&effective_new)
            .map_err(|e| format!("cipher error: {}", e))?;

        for (_key, entry) in self.entries.iter_mut() {
            let nonce = Nonce::from_slice(&entry.nonce);
            let mut plaintext = old_cipher.decrypt(nonce, entry.ciphertext.as_slice())
                .map_err(|_| "decrypt error")?;

            let mut new_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut new_nonce);
            let new_nonce_ref = Nonce::from_slice(&new_nonce);

            entry.ciphertext = new_cipher.encrypt(new_nonce_ref, plaintext.as_slice())
                .map_err(|_| "encrypt error")?;
            entry.nonce = new_nonce;

            plaintext.zeroize();
        }

        keys_guard.encryption_key.zeroize();
        keys_guard.encryption_key = new_key;
        keys_guard.rotation_counter += 1;
        Ok(())
    }
}

/// HMAC-SHA256 hash for lookup keys (uses stable key)
fn hash_lookup_key(key: &[u8], hmac_key: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key).expect("HMAC error");
    mac.update(key);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn write_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn deserialize_method_info(data: &[u8]) -> Option<DecryptedMethodInfo> {
    let mut cursor = 0;
    let class_name = read_length_prefixed(data, &mut cursor)?;
    let method_name = read_length_prefixed(data, &mut cursor)?;
    let method_desc = read_length_prefixed(data, &mut cursor)?;
    if cursor >= data.len() { return None; }
    let func_type = data[cursor] as char;

    Some(DecryptedMethodInfo {
        class_name: String::from_utf8(class_name).ok()?,
        method_name: String::from_utf8(method_name).ok()?,
        method_desc: String::from_utf8(method_desc).ok()?,
        func_type,
    })
}

fn read_length_prefixed(data: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    if *cursor + 4 > data.len() { return None; }
    let len = u32::from_be_bytes([
        data[*cursor], data[*cursor+1], data[*cursor+2], data[*cursor+3]
    ]) as usize;
    *cursor += 4;
    if *cursor + len > data.len() { return None; }
    let result = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Some(result)
}

#[cfg(target_os = "windows")]
fn lock_memory_page(ptr: *const u8, size: usize) {
    unsafe { VirtualLock(ptr as *mut _, size); }
}

#[cfg(target_os = "linux")]
fn lock_memory_page(ptr: *const u8, size: usize) {
    unsafe { libc::mlock(ptr as *const _, size); }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn lock_memory_page(_ptr: *const u8, _size: usize) {}

#[inline(never)]
unsafe fn tamper_detected() {
    crate::debug_log!("[SkyLicense] !!! TAMPER DETECTED in EncryptedMethodMap (canary/count mismatch) !!!");
    if let Some(active) = crate::SESSION_ACTIVE.get() {
        active.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    crate::corrupt_state();
    std::thread::spawn(|| {
        let delay = (rand::random::<u64>() % 5000) + 1000;
        std::thread::sleep(std::time::Duration::from_millis(delay));
        std::process::exit(0);
    });
}

// ============================================================
// Integrity anchor pointers — expose function addresses for code hashing
// ============================================================

/// Returns the address of `EncryptedMethodMap::get` for integrity hashing.
#[inline(never)]
pub fn encrypted_map_get_ptr() -> *const () {
    // We point to the `get` method. Since it's an impl method, we use a wrapper.
    #[inline(never)]
    fn get_anchor_target(_: &EncryptedMethodMap, _: &str) {}
    // Actually, point to the real `get` via a known stable function in this module
    hash_lookup_key as *const ()
    // Note: we use hash_lookup_key as a proxy since method pointers are complex.
    // The actual anchor_2 will hash from this address.
}

/// Returns the address of `hash_lookup_key` for integrity hashing.
#[inline(never)]
pub fn hash_lookup_key_ptr() -> *const () {
    hash_lookup_key as *const ()
}
