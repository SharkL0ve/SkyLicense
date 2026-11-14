//! Memory protection verification.

#[cfg(test)]
mod tests {
    use crate::mem_protect;

    #[test]
    fn test_xor_encrypt_decrypt() {
        let plaintext = "com/example/MyClass";
        let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(plaintext);

        // Encrypted should not equal plaintext bytes
        assert_ne!(encrypted, plaintext.as_bytes());

        // Decrypt should recover original
        let decrypted = mem_protect::xor_decrypt_string(&encrypted, xor_gen).unwrap();
        assert_eq!(decrypted, plaintext);

        println!("[PASS] XOR encrypt/decrypt works");
    }

    #[test]
    fn test_xor_key_rotation_invalidates_cache() {
        let plaintext = "secret_method_name";
        let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(plaintext);

        // Rotate key
        mem_protect::rotate_cache_xor_key();

        // Old encrypted data should fail to decrypt (generation mismatch)
        let result = mem_protect::xor_decrypt_string(&encrypted, xor_gen);
        assert!(
            result.is_none(),
            "Stale cache entry should return None after rotation"
        );

        println!("[PASS] Key rotation invalidates old cache entries");
    }

    #[test]
    fn test_pointer_mask_rotation() {
        let mask1 = mem_protect::get_current_pointer_mask();
        assert_ne!(mask1, 0, "Mask should not be zero");

        let (old, new) = mem_protect::rotate_pointer_mask();
        assert_eq!(old, mask1);
        assert_ne!(new, old, "New mask should differ from old");

        let mask2 = mem_protect::get_current_pointer_mask();
        assert_eq!(mask2, new);

        println!("[PASS] Pointer mask rotation works");
    }

    #[test]
    fn test_violation_tracker_decay() {
        // Add violations below threshold
        let triggered = mem_protect::add_violation(2);
        assert!(!triggered, "Should not trigger at count=2 (threshold=3)");

        // Add one more to hit threshold
        let triggered = mem_protect::add_violation(1);
        assert!(triggered, "Should trigger at count=3 (threshold=3)");

        println!("[PASS] Violation tracker threshold works");
    }

    #[test]
    fn test_hardware_breakpoint_detection() {
        // In normal execution, no hardware breakpoints should be set
        let detected = mem_protect::detect_hardware_breakpoints();
        assert!(!detected, "No hardware breakpoints should be set in test");

        println!("[PASS] Hardware breakpoint detection returns false in clean env");
    }
}
