/// Code integrity anchors — entangled with the cryptographic key derivation pipeline.
/// NO conditional branches. Code hashes are used as MATHEMATICAL INPUTS to key derivation.
/// Wrong hash = wrong key = silent decryption failure = JVM crash.
///
/// 6 independent anchors hash different code regions. Each is used by different subsystems.
/// Patching one anchor corrupts one subsystem. Patching all requires finding 6 scattered
/// functions with obfuscated HMAC keys.

use hmac::{Hmac, Mac};
use obfuse::obfuse;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of 4096 bytes at the given function address using the given key.
#[inline(never)]
unsafe fn hash_code_region(fn_ptr: *const u8, hmac_key: &[u8]) -> [u8; 32] {
    let code_bytes = std::slice::from_raw_parts(fn_ptr, 4096);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .expect("hmac key error");
    mac.update(code_bytes);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ============================================================
// 6 Hash Anchors — each targets a different function
// ============================================================

/// Anchor 1: hash of `dispatch_cached` (lib.rs hot path)
/// Used by: pointer mask rotation, AES key rotation, pointer lookup adjustment
/// Cached to ensure consistency across encode/decode operations.
#[inline(never)]
pub fn anchor_1() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("A1k9Xm2pQ7wR4vLn");
        unsafe {
            hash_code_region(
                crate::dispatch_cached as *const () as *const u8,
                key.as_bytes(),
            )
        }
    })
}

/// Anchor 2: hash of `EncryptedMethodMap::get` (secure_map.rs lookup)
/// Used by: XOR cache key, AES key rotation, map lookup effective key
/// Cached to ensure consistency between encrypt and decrypt operations.
#[inline(never)]
pub fn anchor_2() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("B3jF8sNcY6tH1wZq");
        unsafe {
            hash_code_region(
                crate::secure_map::encrypted_map_get_ptr() as *const u8,
                key.as_bytes(),
            )
        }
    })
}

/// Anchor 3: hash of `xor_encrypt_string` (mem_protect.rs)
/// Used by: pointer mask rotation, XOR cache key rotation
/// Cached for consistency.
#[inline(never)]
pub fn anchor_3() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("C5gD0rKe8mP2xUaW");
        unsafe {
            hash_code_region(
                crate::mem_protect::xor_encrypt_string as *const () as *const u8,
                key.as_bytes(),
            )
        }
    })
}

/// Anchor 4: hash of `HeartbeatClient::send_heartbeat` (heartbeat.rs)
/// Used by: AES key rotation (every 5th rotation only — delayed detection)
#[inline(never)]
pub fn anchor_4() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("D7iL4oSb1nV9yJcF");
        unsafe {
            hash_code_region(
                crate::heartbeat::heartbeat_send_ptr() as *const u8,
                key.as_bytes(),
            )
        }
    })
}

/// Anchor 5: hash of `hash_lookup_key` (secure_map.rs)
/// Used by: pointer mask rotation (every 3rd rotation — staggered)
#[inline(never)]
pub fn anchor_5() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("E2fA6uMh3qT8wXpG");
        unsafe {
            hash_code_region(
                crate::secure_map::hash_lookup_key_ptr() as *const u8,
                key.as_bytes(),
            )
        }
    })
}

/// Anchor 6: hash of `EncryptUtil::derive_key` (encrypt.rs)
/// Used by: XOR cache key rotation (stochastic — ~30% of rotations)
#[inline(never)]
pub fn anchor_6() -> [u8; 32] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<[u8; 32]> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let key = obfuse!("F9cR1vOj5kB7zNdI");
        unsafe {
            hash_code_region(
                crate::encrypt::derive_key_ptr() as *const u8,
                key.as_bytes(),
            )
        }
    })
}

// ============================================================
// Helper functions — used by other modules to entangle with anchors
// ============================================================

/// Derive an effective encryption key by mixing a base key with a live anchor hash.
/// If code is unpatched: produces the correct effective key.
/// If code is patched: produces a wrong key → AES-GCM auth failure.
#[inline(never)]
pub fn derive_effective_key(base_key: &[u8; 32], anchor: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(base_key)
        .expect("hmac error");
    mac.update(anchor);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive a pointer adjustment value from anchor_1.
/// Cached after first computation to ensure encode/decode consistency.
/// If code is patched AFTER first call, the cached value remains correct for existing entries,
/// but new entries will use the (now different) anchor — creating a mismatch on next rotation.
#[inline(never)]
pub fn get_pointer_anchor_adjustment() -> usize {
    use std::sync::OnceLock;
    static CACHED_ADJ: OnceLock<usize> = OnceLock::new();
    *CACHED_ADJ.get_or_init(|| {
        let anchor = anchor_1();
        // Use only lower bits to keep the adjustment small enough
        // that XOR'd pointers remain in valid address space.
        // Take 4 bytes and mask to ensure high bits don't corrupt pointer space.
        let raw = u32::from_ne_bytes(anchor[0..4].try_into().unwrap()) as usize;
        // Mask to lower 32 bits on 64-bit systems to avoid corrupting the upper pointer bits
        // which contain important address space information on Windows x64
        raw & 0x0000_0000_FFFF_FFFF
    })
}

