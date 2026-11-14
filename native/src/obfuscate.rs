//! Compile-time string encryption utilities using `obfuse`.
use obfuse::obfuse;

// === Sensitive strings — all protected by obfuse (polymorphic AES-256-GCM) ===
// Each string gets unique inline decryption code with random transformations.
// Memory is securely wiped after the returned value is dropped.

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
