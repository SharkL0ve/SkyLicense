use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// ECDH key pair for ephemeral key exchange
pub struct KeyExchange {
    pub public_key: [u8; 32],
    secret: EphemeralSecret,
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange {
    /// Generate a new ephemeral ECDH key pair
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&secret);
        Self {
            public_key: public_key.to_bytes(),
            secret,
        }
    }

    /// Derive shared secret from server's public key
    pub fn derive_shared_secret(
        self,
        server_public_key: &[u8; 32],
    ) -> Result<SharedSecret, String> {
        let their_public = PublicKey::from(*server_public_key);
        let shared = self.secret.diffie_hellman(&their_public);
        let key = shared.to_bytes();
        if key.iter().all(|byte| *byte == 0) {
            Err("X25519 produced an all-zero shared secret".to_string())
        } else {
            Ok(SharedSecret { key })
        }
    }
}

/// Shared secret derived from ECDH, auto-zeroizes on drop
pub struct SharedSecret {
    key: [u8; 32],
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Derive a session key from the shared secret + nonces
    pub fn derive_session_key(
        &self,
        client_nonce: &[u8],
        server_nonce: &[u8],
    ) -> Result<[u8; 32], String> {
        use sha2::Digest;

        let mut salt_hasher = sha2::Sha256::new();
        salt_hasher.update(b"SkyLicense-HKDF-Salt");
        salt_hasher.update(client_nonce);
        salt_hasher.update(server_nonce);
        let mut salt = salt_hasher.finalize();

        let mut extract = HmacSha256::new_from_slice(&salt)
            .map_err(|_| "HKDF extract initialization failed".to_string())?;
        extract.update(&self.key);
        let mut pseudo_random_key = extract.finalize().into_bytes();

        let mut expand = HmacSha256::new_from_slice(&pseudo_random_key)
            .map_err(|_| "HKDF expand initialization failed".to_string())?;
        expand.update(b"SkyLicense v4 session");
        expand.update(client_nonce);
        expand.update(server_nonce);
        expand.update(&[1]);
        let session_key = expand.finalize().into_bytes().into();

        salt.zeroize();
        pseudo_random_key.zeroize();
        Ok(session_key)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Challenge-Response protocol messages
pub struct ChallengeResponse;

impl ChallengeResponse {
    /// Compute HMAC response to server challenge
    pub fn compute_response(
        session_key: &[u8; 32],
        challenge: &[u8],
        client_nonce: &[u8],
        session_id: &[u8; 32],
        security_epoch: u32,
        build_id: &[u8; 32],
        timestamp: u64,
    ) -> Result<Vec<u8>, String> {
        let mut mac = HmacSha256::new_from_slice(session_key)
            .map_err(|_| "challenge HMAC initialization failed".to_string())?;
        mac.update(b"SkyLicense v4 challenge\0");
        mac.update(challenge);
        mac.update(client_nonce);
        mac.update(session_id);
        mac.update(&security_epoch.to_be_bytes());
        mac.update(build_id);
        mac.update(&timestamp.to_be_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verify server's response to our challenge
    pub fn verify_server_response(
        session_key: &[u8; 32],
        server_response: &[u8],
        expected_data: &[u8],
    ) -> bool {
        let Ok(mut mac) = HmacSha256::new_from_slice(session_key) else {
            return false;
        };
        mac.update(expected_data);
        let expected = mac.finalize().into_bytes();
        // Constant-time comparison
        constant_time_eq(server_response, &expected)
    }

    pub fn derive_resource_transport_key(
        session_key: &[u8; 32],
        session_id: &[u8; 32],
        security_epoch: u32,
        build_id: &[u8; 32],
        plugin_name: &str,
        plugin_version: &str,
    ) -> Result<[u8; 32], String> {
        derive_context_key(
            b"SkyLicense v4 resource key\0",
            session_key,
            session_id,
            security_epoch,
            build_id,
            plugin_name,
            plugin_version,
        )
    }

    pub fn derive_method_key(
        session_key: &[u8; 32],
        session_id: &[u8; 32],
        security_epoch: u32,
        build_id: &[u8; 32],
        plugin_name: &str,
        plugin_version: &str,
    ) -> Result<[u8; 32], String> {
        derive_context_key(
            b"SkyLicense v4 method key\0",
            session_key,
            session_id,
            security_epoch,
            build_id,
            plugin_name,
            plugin_version,
        )
    }

    pub fn build_resource_associated_data(
        session_id: &[u8; 32],
        security_epoch: u32,
        build_id: &[u8; 32],
        plugin_name: &str,
        plugin_version: &str,
    ) -> Result<Vec<u8>, String> {
        let context = build_resource_context(
            session_id,
            security_epoch,
            build_id,
            plugin_name,
            plugin_version,
        )?;
        let mut associated_data =
            Vec::with_capacity(b"SkyLicense v4 resource aad\0".len() + context.len());
        associated_data.extend_from_slice(b"SkyLicense v4 resource aad\0");
        associated_data.extend_from_slice(&context);
        Ok(associated_data)
    }

    pub fn compute_delivery_acknowledgement(
        session_key: &[u8; 32],
        session_id: &[u8; 32],
        timestamp: u64,
        status: u8,
    ) -> Result<[u8; 32], String> {
        let mut mac = HmacSha256::new_from_slice(session_key)
            .map_err(|_| "delivery-ack HMAC initialization failed".to_string())?;
        mac.update(b"SkyLicense v4 delivery ack\0");
        mac.update(session_id);
        mac.update(&timestamp.to_be_bytes());
        mac.update(&[status]);
        Ok(mac.finalize().into_bytes().into())
    }
}

fn derive_context_key(
    label: &[u8],
    session_key: &[u8; 32],
    session_id: &[u8; 32],
    security_epoch: u32,
    build_id: &[u8; 32],
    plugin_name: &str,
    plugin_version: &str,
) -> Result<[u8; 32], String> {
    let mut context = build_resource_context(
        session_id,
        security_epoch,
        build_id,
        plugin_name,
        plugin_version,
    )?;
    let mut mac = HmacSha256::new_from_slice(session_key)
        .map_err(|_| "resource-key HMAC initialization failed".to_string())?;
    mac.update(label);
    mac.update(&context);
    context.zeroize();
    Ok(mac.finalize().into_bytes().into())
}

fn build_resource_context(
    session_id: &[u8; 32],
    security_epoch: u32,
    build_id: &[u8; 32],
    plugin_name: &str,
    plugin_version: &str,
) -> Result<Vec<u8>, String> {
    if security_epoch == 0 || plugin_name.is_empty() || plugin_version.is_empty() {
        return Err("invalid resource-key context".to_string());
    }
    let plugin_length = u32::try_from(plugin_name.len())
        .map_err(|_| "resource-key context field is too long".to_string())?;
    let version_length = u32::try_from(plugin_version.len())
        .map_err(|_| "resource-key context field is too long".to_string())?;
    if plugin_length > 4096 || version_length > 4096 {
        return Err("resource-key context field is too long".to_string());
    }
    let mut context =
        Vec::with_capacity(32 + 4 + 32 + 4 + plugin_name.len() + 4 + plugin_version.len());
    context.extend_from_slice(session_id);
    context.extend_from_slice(&security_epoch.to_be_bytes());
    context.extend_from_slice(build_id);
    context.extend_from_slice(&plugin_length.to_be_bytes());
    context.extend_from_slice(plugin_name.as_bytes());
    context.extend_from_slice(&version_length.to_be_bytes());
    context.extend_from_slice(plugin_version.as_bytes());
    Ok(context)
}

/// Constant-time byte comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_all_zero_x25519_shared_secret() {
        let exchange = KeyExchange::new();
        assert!(exchange.derive_shared_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn hkdf_session_key_is_stable_for_fixed_inputs() {
        let secret = SharedSecret { key: [7u8; 32] };
        let first = secret.derive_session_key(&[8u8; 32], &[9u8; 32]).unwrap();
        let second = secret.derive_session_key(&[8u8; 32], &[9u8; 32]).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32]);
        assert_eq!(
            first,
            [
                0x7c, 0x23, 0xae, 0x74, 0x8e, 0xe6, 0x15, 0x93, 0x2f, 0x22, 0xa1, 0xfe, 0x2a, 0xe7,
                0xa1, 0x50, 0x45, 0xd4, 0xa8, 0x23, 0x90, 0x82, 0xfb, 0x99, 0x5d, 0xb1, 0x05, 0x65,
                0x89, 0x53, 0xe8, 0xed,
            ]
        );
    }

    #[test]
    fn v4_challenge_transcript_matches_java_vector() {
        let response = ChallengeResponse::compute_response(
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            7,
            &[5; 32],
            0x0102_0304_0506_0708,
        )
        .unwrap();
        assert_eq!(
            response,
            [
                0x1a, 0xdd, 0x0d, 0xe5, 0xd6, 0x95, 0x96, 0x27, 0xa9, 0xa5, 0x46, 0x06, 0x89, 0x84,
                0xcd, 0x13, 0x3b, 0x30, 0xd1, 0xf1, 0x08, 0x70, 0xec, 0x9e, 0x4c, 0x68, 0x53, 0x90,
                0x83, 0xae, 0xea, 0xe7,
            ]
        );
    }

    #[test]
    fn v4_resource_keys_match_java_vectors() {
        assert_eq!(
            ChallengeResponse::derive_resource_transport_key(
                &[1; 32], &[2; 32], 7, &[3; 32], "plugin", "1.2.3",
            )
            .unwrap(),
            [
                0x65, 0xc5, 0xf2, 0xda, 0xd7, 0xeb, 0x61, 0x58, 0x3e, 0x7a, 0xb3, 0x0d, 0xf7, 0xeb,
                0xef, 0xcd, 0x26, 0x0e, 0x09, 0x2f, 0x2b, 0xf8, 0xa8, 0x53, 0x7c, 0x90, 0xea, 0x1a,
                0xd6, 0x5f, 0xb4, 0xb0,
            ]
        );
        assert_eq!(
            ChallengeResponse::derive_method_key(
                &[1; 32], &[2; 32], 7, &[3; 32], "plugin", "1.2.3",
            )
            .unwrap(),
            [
                0x21, 0xe9, 0x20, 0xe1, 0x17, 0x96, 0x3a, 0x01, 0x34, 0x64, 0x11, 0x1f, 0x67, 0x2e,
                0x1d, 0x37, 0x46, 0x49, 0xb0, 0x9e, 0xc1, 0x9b, 0x92, 0x42, 0xc1, 0xe9, 0x77, 0x75,
                0xf3, 0x14, 0x23, 0x96,
            ]
        );
        assert_eq!(
            ChallengeResponse::build_resource_associated_data(
                &[2; 32], 7, &[3; 32], "plugin", "1.2.3",
            )
            .unwrap(),
            [
                b"SkyLicense v4 resource aad\0".as_slice(),
                &[2; 32],
                &7u32.to_be_bytes(),
                &[3; 32],
                &6u32.to_be_bytes(),
                b"plugin",
                &5u32.to_be_bytes(),
                b"1.2.3",
            ]
            .concat()
        );
    }

    #[test]
    fn delivery_acknowledgement_matches_java_vector() {
        assert_eq!(
            ChallengeResponse::compute_delivery_acknowledgement(
                &[1; 32],
                &[2; 32],
                0x0102_0304_0506_0708,
                1,
            )
            .unwrap(),
            [
                0x10, 0xaf, 0x39, 0xd5, 0x61, 0xce, 0xf7, 0xe8, 0x96, 0x17, 0x84, 0x01, 0xf4, 0xbb,
                0xee, 0x7a, 0x61, 0x3f, 0xf9, 0xbf, 0x44, 0x07, 0x71, 0xde, 0xf5, 0xe4, 0xbe, 0x19,
                0xdd, 0x2f, 0x1c, 0x7f,
            ]
        );
    }
}
