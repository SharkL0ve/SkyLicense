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
    pub fn derive_shared_secret(self, server_public_key: &[u8; 32]) -> SharedSecret {
        let their_public = PublicKey::from(*server_public_key);
        let shared = self.secret.diffie_hellman(&their_public);
        SharedSecret {
            key: shared.to_bytes(),
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
    pub fn derive_session_key(&self, client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
        // PLACEHOLDER_DERIVE_KEY
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(&self.key);
        hasher.update(client_nonce);
        hasher.update(server_nonce);
        hasher.finalize().into()
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
        timestamp: u64,
    ) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(session_key)
            .expect("HMAC key length error");
        mac.update(challenge);
        mac.update(client_nonce);
        mac.update(&timestamp.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify server's response to our challenge
    pub fn verify_server_response(
        session_key: &[u8; 32],
        server_response: &[u8],
        expected_data: &[u8],
    ) -> bool {
        let mut mac = HmacSha256::new_from_slice(session_key)
            .expect("HMAC key length error");
        mac.update(expected_data);
        let expected = mac.finalize().into_bytes();
        // Constant-time comparison
        constant_time_eq(server_response, &expected)
    }
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
