/// Compile-time string encryption utilities
/// Uses `obfuse` crate for polymorphic AES-256-GCM compile-time encryption
/// with secure memory wiping after use.
/// Combined with `rust-native-obf` for control flow flattening on critical functions.

use obfuse::obfuse;

/// Second independent key fragment — compile-time random seed
const KEY_FRAGMENT_B: [u8; 16] = [
    0x91, 0xA3, 0x5D, 0xE7, 0x2F, 0x84, 0xC6, 0x0B,
    0x73, 0xF9, 0x1E, 0x4A, 0xB8, 0x65, 0xD2, 0x07,
];

/// Assemble the master key from multiple independent fragments.
/// - Fragment A: obfuse-encrypted constant (polymorphic AES-256-GCM, unique per build)
/// - Fragment B: independent compile-time seed
/// - Fragment C: derived from code section hash (changes if binary is patched)

/// Derive the master key. Code hash is used as a MATHEMATICAL INPUT to the derivation.
/// NO conditional branch — wrong hash = wrong derivation = wrong password = silent failure.
pub fn derive_master_key() -> String {
    use std::sync::OnceLock;

    let frag_c = compute_code_hash();

    // Capture baseline on first call. If code is unpatched, baseline == frag_c always.
    // If code is patched after first call, baseline != frag_c, XOR produces non-zero,
    // password is corrupted silently (no branch to patch).
    static BASELINE_HASH: OnceLock<[u8; 32]> = OnceLock::new();
    let baseline = BASELINE_HASH.get_or_init(|| frag_c);

    let raw_password = get_padding_password();
    let pw_bytes = raw_password.as_bytes();

    // Apply correction: baseline XOR current. Zero if unpatched, non-zero if patched.
    let mut result_bytes = Vec::with_capacity(pw_bytes.len());
    for (i, &b) in pw_bytes.iter().enumerate() {
        result_bytes.push(b ^ (baseline[i % 32] ^ frag_c[i % 32]));
    }

    String::from_utf8(result_bytes).unwrap_or_default()
}

/// Compute a hash of our own code section to detect binary patching
#[inline(never)]

fn compute_code_hash() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();

    let code_ptr = compute_code_hash as *const () as *const u8;
    unsafe {
        let code_slice = std::slice::from_raw_parts(code_ptr, 4096);
        hasher.update(code_slice);
    }
    hasher.update(&KEY_FRAGMENT_B);
    hasher.finalize().into()
}

// === Sensitive strings — all protected by obfuse (polymorphic AES-256-GCM) ===
// Each string gets unique inline decryption code with random transformations.
// Memory is securely wiped after the returned value is dropped.

/// master password (16 bytes, matches server PADDING_PASSWORD)

pub fn get_padding_password() -> String {
    obfuse!("Kx#9vL!mQ2$wZ7pF").to_string()
}

/// "ACCEPT"
pub fn get_accept_string() -> String {
    obfuse!("ACCEPT").to_string()
}

/// "defineClass"
pub fn get_define_class_string() -> String {
    obfuse!("defineClass").to_string()
}

/// "java/lang/ClassLoader"
pub fn get_classloader_path() -> String {
    obfuse!("java/lang/ClassLoader").to_string()
}

/// "(Ljava/lang/String;[BII)Ljava/lang/Class;"
pub fn get_define_class_sig() -> String {
    obfuse!("(Ljava/lang/String;[BII)Ljava/lang/Class;").to_string()
}
