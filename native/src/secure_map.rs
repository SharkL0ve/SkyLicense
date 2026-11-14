/// Encrypted memory storage for the method map.
/// The map is NEVER stored in plaintext in memory.
/// Each entry is individually encrypted with a session-derived key.
/// Decryption happens per-lookup and the plaintext is zeroized immediately after use.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use rustc_hash::FxHashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "windows")]
use winapi::um::memoryapi::VirtualLock;

/// Memory keys — split into two:
/// - lookup_key: STABLE, never rotates. Used for HMAC-hashing lookup keys.
/// - encryption_key: rotates every 30-90s. Used for AES-GCM.
///
/// This split ensures hashed_key remains valid across rotations.
static MEMORY_KEYS: OnceLock<Mutex<Option<MemoryKeys>>> = OnceLock::new();

struct MemoryKeys {
    /// Fixed key for HMAC lookup — never changes after init
    lookup_key: [u8; 32],
    /// Rotating key for AES-GCM encryption
    encryption_key: [u8; 32],
    /// Session-bound key for authenticating embedded method/string tokens.
    method_token_key: [u8; 32],
    rotation_counter: u64,
}

impl Drop for MemoryKeys {
    fn drop(&mut self) {
        self.lookup_key.zeroize();
        self.encryption_key.zeroize();
        self.method_token_key.zeroize();
    }
}

/// An encrypted entry in the method map
#[derive(Clone)]
pub struct EncryptedEntry {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

impl Drop for EncryptedEntry {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
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
        self.class_name.zeroize();
        self.method_name.zeroize();
        self.method_desc.zeroize();
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

impl Drop for EncryptedMethodMap {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl EncryptedMethodMap {
    pub fn from_plaintext(
        entries: rustc_hash::FxHashMap<String, crate::model::MethodInfo>,
        method_token_key: &[u8; 32],
    ) -> Result<Self, String> {
        // Generate two independent keys
        let mut lookup_key = Zeroizing::new([0u8; 32]);
        let mut encryption_key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *lookup_key);
        rand::thread_rng().fill_bytes(&mut *encryption_key);

        // Generate runtime canary
        let mut canary = Zeroizing::new([0u8; 16]);
        rand::thread_rng().fill_bytes(&mut *canary);

        let expected_count = entries.len();
        let mut encrypted_entries = FxHashMap::default();
        encrypted_entries.reserve(expected_count);

        // Use effective key (entangled with code integrity anchor)
        let live_anchor = crate::integrity::anchor_2();
        let effective_key = Zeroizing::new(crate::integrity::derive_effective_key(
            &encryption_key,
            &live_anchor,
        ));
        let cipher = Aes256Gcm::new_from_slice(&*effective_key)
            .map_err(|e| format!("cipher error: {}", e))?;

        for (key, info) in entries.into_iter() {
            // Serialize method info
            let mut plaintext = Zeroizing::new(Vec::new());
            write_length_prefixed(&mut plaintext, info.class_name.as_bytes());
            write_length_prefixed(&mut plaintext, info.method_name.as_bytes());
            write_length_prefixed(&mut plaintext, info.method_desc.as_bytes());
            plaintext.push(info.func_type as u8);

            // Generate unique nonce
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_slice())
                .map_err(|e| format!("encrypt error: {}", e))?;

            // Hash lookup key with the STABLE lookup_key (never rotates)
            let hashed = hash_lookup_key(key.as_bytes(), &lookup_key);

            encrypted_entries.insert(
                hashed,
                EncryptedEntry {
                    ciphertext,
                    nonce: nonce_bytes,
                },
            );
        }

        let keys = MEMORY_KEYS.get_or_init(|| Mutex::new(None));
        let mut keys_guard = keys.lock().map_err(|_| "key lock poisoned")?;
        if keys_guard.is_some() {
            return Err("method-map keys are already initialized".to_string());
        }
        *keys_guard = Some(MemoryKeys {
            lookup_key: *lookup_key,
            encryption_key: *encryption_key,
            method_token_key: *method_token_key,
            rotation_counter: 0,
        });
        drop(keys_guard);

        if let Err(error) =
            lock_memory_page(keys as *const _ as *const u8, std::mem::size_of_val(keys))
        {
            crate::security::report(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::RuntimeFailure,
                crate::security::EvidenceConfidence::Medium,
                "secure_map.memory_lock",
                error,
            ));
        }

        Ok(Self {
            entries: encrypted_entries,
            canary: *canary,
            canary_check: *canary, // duplicate for integrity verification
            expected_count,
        })
    }

    /// O(1) lookup + decrypt single entry.
    /// Decryption key is derived from stored key + live code anchor.
    /// If code is patched, anchor changes → effective key wrong → AEAD auth fails → None.
    pub fn get(&self, key: &str) -> Option<DecryptedMethodInfo> {
        // Verify integrity
        if self.canary != self.canary_check || self.entries.len() != self.expected_count {
            tamper_detected();
            return None;
        }

        let keys_guard = MEMORY_KEYS.get()?.lock().ok()?;
        let keys = keys_guard.as_ref()?;

        // Hash with stable lookup key
        let hashed = hash_lookup_key(key.as_bytes(), &keys.lookup_key);

        let entry = self.entries.get(&hashed)?;

        // Derive effective decryption key using live code anchor
        let live_anchor = crate::integrity::anchor_2();
        let effective_key = Zeroizing::new(crate::integrity::derive_effective_key(
            &keys.encryption_key,
            &live_anchor,
        ));

        let cipher = Aes256Gcm::new_from_slice(&*effective_key).ok()?;
        let nonce = Nonce::from_slice(&entry.nonce);
        let plaintext = Zeroizing::new(cipher.decrypt(nonce, entry.ciphertext.as_slice()).ok()?);

        deserialize_method_info(&plaintext)
    }

    /// Re-encrypt all entries with a new encryption key.
    /// Lookup keys are NOT affected (stable HMAC key).
    /// Re-encrypt all entries with a new key derived from code integrity anchors.
    /// If code is patched, the derived key is wrong, and all future lookups fail.
    pub fn rotate_key(&mut self) -> Result<(), String> {
        let mut keys_guard = MEMORY_KEYS
            .get()
            .ok_or("no keys")?
            .lock()
            .map_err(|_| "lock error")?;
        let keys = keys_guard.as_mut().ok_or("keys destroyed")?;

        let old_key = Zeroizing::new(keys.encryption_key);

        // Derive new key from random seed + code integrity anchors
        let mut random_seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *random_seed);

        let a1 = crate::integrity::anchor_1();
        let a2 = crate::integrity::anchor_2();

        // Every 5th rotation, include anchor_4 (staggered)
        let rotation = keys.rotation_counter;
        let a4 = if rotation % 5 == 0 {
            crate::integrity::anchor_4()
        } else {
            a1
        };

        // New key = HMAC(random_seed, a1 || a2 || a4)
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&*random_seed).map_err(|_| "hmac error")?;
        mac.update(&a1);
        mac.update(&a2);
        mac.update(&a4);
        let mut digest = mac.finalize().into_bytes();
        let mut new_key = Zeroizing::new([0u8; 32]);
        new_key.copy_from_slice(&digest);
        digest.zeroize();

        // Derive effective keys for old and new (both use live anchor_2)
        let live_anchor = crate::integrity::anchor_2();
        let effective_old = Zeroizing::new(crate::integrity::derive_effective_key(
            &old_key,
            &live_anchor,
        ));
        let effective_new = Zeroizing::new(crate::integrity::derive_effective_key(
            &new_key,
            &live_anchor,
        ));

        let old_cipher = Aes256Gcm::new_from_slice(&*effective_old)
            .map_err(|e| format!("cipher error: {}", e))?;
        let new_cipher = Aes256Gcm::new_from_slice(&*effective_new)
            .map_err(|e| format!("cipher error: {}", e))?;

        let next_rotation = keys
            .rotation_counter
            .checked_add(1)
            .ok_or("rotation counter overflow")?;
        let mut rotated_entries = FxHashMap::default();
        rotated_entries.reserve(self.entries.len());

        // Build a complete replacement first. Any authentication/encryption
        // failure drops and zeroizes the temporary snapshot while the current
        // map and key remain mutually consistent.
        for (hashed_key, entry) in &self.entries {
            let nonce = Nonce::from_slice(&entry.nonce);
            let plaintext = Zeroizing::new(
                old_cipher
                    .decrypt(nonce, entry.ciphertext.as_slice())
                    .map_err(|_| "decrypt error")?,
            );

            let mut new_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut new_nonce);
            let new_nonce_ref = Nonce::from_slice(&new_nonce);

            let ciphertext = new_cipher
                .encrypt(new_nonce_ref, plaintext.as_slice())
                .map_err(|_| "encrypt error")?;
            rotated_entries.insert(
                *hashed_key,
                EncryptedEntry {
                    ciphertext,
                    nonce: new_nonce,
                },
            );
        }

        std::mem::swap(&mut self.entries, &mut rotated_entries);
        keys.encryption_key.zeroize();
        keys.encryption_key.copy_from_slice(&*new_key);
        keys.rotation_counter = next_rotation;
        Ok(())
    }

    /// Destroy the method-map ciphertext and its only decryption keys.
    pub fn destroy(&mut self) {
        self.entries.clear();
        self.canary.zeroize();
        self.canary_check.zeroize();
        self.expected_count = 0;

        destroy_all_keys();
    }
}

/// Return a short-lived copy of the session-bound method-token key.
pub fn method_token_key() -> Option<Zeroizing<[u8; 32]>> {
    let guard = MEMORY_KEYS.get()?.lock().ok()?;
    Some(Zeroizing::new(guard.as_ref()?.method_token_key))
}

/// Irreversibly clear all in-memory method-map and token keys.
pub fn destroy_all_keys() {
    if let Some(keys) = MEMORY_KEYS.get() {
        let mut guard = keys.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = guard.take();
    }
}

/// HMAC-SHA256 hash for lookup keys (uses stable key)
fn hash_lookup_key(key: &[u8], hmac_key: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(hmac_key) else {
        crate::security::tamper_deferred(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::RuntimeFailure,
            crate::security::EvidenceConfidence::Certain,
            "secure_map.lookup_hmac",
            "lookup HMAC initialization failed",
        ));
        return [0u8; 32];
    };
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
    if cursor >= data.len() {
        return None;
    }
    let func_type = data[cursor] as char;

    Some(DecryptedMethodInfo {
        class_name: String::from_utf8(class_name).ok()?,
        method_name: String::from_utf8(method_name).ok()?,
        method_desc: String::from_utf8(method_desc).ok()?,
        func_type,
    })
}

fn read_length_prefixed(data: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    if *cursor + 4 > data.len() {
        return None;
    }
    let len = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        return None;
    }
    let result = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Some(result)
}

#[cfg(target_os = "windows")]
fn lock_memory_page(ptr: *const u8, size: usize) -> Result<(), String> {
    let result = unsafe { VirtualLock(ptr as *mut _, size) };
    if result == 0 {
        Err(format!(
            "VirtualLock failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn lock_memory_page(ptr: *const u8, size: usize) -> Result<(), String> {
    unsafe {
        if libc::mlock(ptr.cast(), size) != 0 {
            return Err(format!("mlock failed: {}", std::io::Error::last_os_error()));
        }

        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if page_size <= 0 {
            return Err("sysconf(_SC_PAGESIZE) failed".to_string());
        }
        let page_size = page_size as usize;
        let start = (ptr as usize) & !(page_size - 1);
        let end = (ptr as usize + size + page_size - 1) & !(page_size - 1);
        if libc::madvise(
            start as *mut _,
            end.saturating_sub(start),
            libc::MADV_DONTDUMP,
        ) != 0
        {
            return Err(format!(
                "madvise(MADV_DONTDUMP) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn lock_memory_page(_ptr: *const u8, _size: usize) -> Result<(), String> {
    Err("memory locking is unsupported on this platform".to_string())
}

#[inline(never)]
fn tamper_detected() {
    crate::debug_log!(
        "[SkyLicense] !!! TAMPER DETECTED in EncryptedMethodMap (canary/count mismatch) !!!"
    );
    crate::security::tamper_deferred(crate::security::SecurityEvidence::new(
        crate::security::EvidenceKind::CodeIntegrity,
        crate::security::EvidenceConfidence::Certain,
        "secure_map.canary",
        "encrypted method-map canary or entry count mismatch",
    ));
}

// ============================================================
// Integrity anchor pointers — expose function addresses for code hashing
// ============================================================

/// Returns the address of `EncryptedMethodMap::get` for integrity hashing.
#[inline(never)]
pub fn encrypted_map_get_ptr() -> *const () {
    // Method pointers are awkward to express portably, so anchor the private
    // lookup primitive used by every map read.
    hash_lookup_key as *const ()
}

/// Returns the address of `hash_lookup_key` for integrity hashing.
#[inline(never)]
pub fn hash_lookup_key_ptr() -> *const () {
    hash_lookup_key as *const ()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MethodInfo;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    fn test_entries(count: usize) -> FxHashMap<String, MethodInfo> {
        (0..count)
            .map(|index| {
                (
                    format!("lookup-{index}"),
                    MethodInfo {
                        class_name: format!("example/Class{index}"),
                        method_name: format!("method{index}"),
                        method_desc: "()V".to_string(),
                        func_type: 'v',
                    },
                )
            })
            .collect()
    }

    fn encrypted_snapshot(map: &EncryptedMethodMap) -> Vec<([u8; 32], Vec<u8>, [u8; 12])> {
        let mut snapshot = map
            .entries
            .iter()
            .map(|(key, entry)| (*key, entry.ciphertext.clone(), entry.nonce))
            .collect::<Vec<_>>();
        snapshot.sort_by_key(|(key, _, _)| *key);
        snapshot
    }

    #[test]
    fn concurrent_lookups_survive_transactional_rotation_and_destroy_is_final() {
        const ENTRY_COUNT: usize = 16;
        const READER_COUNT: usize = 4;
        let map = Arc::new(Mutex::new(
            EncryptedMethodMap::from_plaintext(test_entries(ENTRY_COUNT), &[9; 32]).unwrap(),
        ));
        assert_eq!(*method_token_key().unwrap(), [9; 32]);
        let barrier = Arc::new(Barrier::new(READER_COUNT + 1));
        let failures = Arc::new(AtomicUsize::new(0));
        let mut readers = Vec::new();

        for _ in 0..READER_COUNT {
            let map = Arc::clone(&map);
            let barrier = Arc::clone(&barrier);
            let failures = Arc::clone(&failures);
            readers.push(std::thread::spawn(move || {
                barrier.wait();
                for iteration in 0..250 {
                    let index = iteration % ENTRY_COUNT;
                    let found = map.lock().unwrap().get(&format!("lookup-{index}"));
                    if found
                        .as_ref()
                        .is_none_or(|info| info.method_name != format!("method{index}"))
                    {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        barrier.wait();
        for _ in 0..25 {
            map.lock().unwrap().rotate_key().unwrap();
        }
        for reader in readers {
            reader.join().unwrap();
        }
        assert_eq!(failures.load(Ordering::Relaxed), 0);

        let map = Arc::try_unwrap(map).ok().unwrap().into_inner().unwrap();
        let mut map = map;

        // Authentication failure must not partially replace the ciphertext
        // snapshot or commit a new key.
        let entry = map.entries.values_mut().next().unwrap();
        entry.ciphertext[0] ^= 0x80;
        let corrupted_snapshot = encrypted_snapshot(&map);
        assert!(map.rotate_key().is_err());
        assert_eq!(encrypted_snapshot(&map), corrupted_snapshot);

        map.destroy();
        assert!(method_token_key().is_none());
        assert!(map.get("lookup-0").is_none());
        assert!(map.rotate_key().is_err());
    }
}
