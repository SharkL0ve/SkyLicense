use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use generic_array::GenericArray;
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Params, Pbkdf2,
};
use std::error::Error;
use std::io::Read;
use flate2::bufread::GzDecoder;
use rand::RngCore;

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const ITERATIONS: u32 = 300;

pub struct EncryptUtil;

impl EncryptUtil {
    fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let pad_len = block_size - (data.len() % block_size);
        let pad_byte = pad_len as u8;

        let mut padded = Vec::with_capacity(data.len() + pad_len);
        padded.extend_from_slice(data);
        padded.resize(data.len() + pad_len, pad_byte);
        padded
    }

    fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let pad_byte = *data.last().unwrap();
        let pad_len = pad_byte as usize;

        if pad_len == 0 || pad_len > data.len() {
            return Err("Error".into());
        }

        for i in (data.len() - pad_len)..data.len() {
            if data[i] != pad_byte {
                return Err("Error".into());
            }
        }

        Ok(data[..data.len() - pad_len].to_vec())
    }

    pub fn aes_encrypt(p_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if key.len() != 16 {
            return Err("Error".into());
        }

        let cipher = Aes128::new(GenericArray::from_slice(key));

        let block_size = 16;
        let padded_data = EncryptUtil::pkcs7_pad(p_bytes, block_size);

        let mut ciphertext = Vec::with_capacity(padded_data.len());
        for chunk in padded_data.chunks(block_size) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            ciphertext.extend_from_slice(&block);
        }

        Ok(ciphertext)
    }

    pub fn aes_decrypt(c_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if key.len() != 16 {
            return Err("Error".into());
        }

        if c_bytes.len() % 16 != 0 {
            return Err("Error".into());
        }

        let cipher = Aes128::new(GenericArray::from_slice(key));

        let mut plaintext = Vec::with_capacity(c_bytes.len());
        for chunk in c_bytes.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            plaintext.extend_from_slice(&block);
        }

        EncryptUtil::pkcs7_unpad(&plaintext)
    }

    pub fn encode(plaintext: &[u8], password: &str) -> Result<Vec<u8>, String> {
        let mut salt = [0u8; SALT_LENGTH];
        rand::thread_rng().fill_bytes(&mut salt);

        let key = EncryptUtil::derive_key(password, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Error: {}", e))?;

        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("Error: {}", e))?;

        let mut output = Vec::with_capacity(SALT_LENGTH + NONCE_LENGTH + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decode(ciphertext: &[u8], password: &str) -> Result<Vec<u8>, String> {
        if ciphertext.len() < SALT_LENGTH + NONCE_LENGTH {
            return Err("Error".into());
        }

        let salt = &ciphertext[0..SALT_LENGTH];
        let nonce = Nonce::from_slice(&ciphertext[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH]);
        let ciphertext = &ciphertext[SALT_LENGTH + NONCE_LENGTH..];

        let key = EncryptUtil::derive_key(&password, salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Error: {}", e))?;

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Error: {}", e))?;

        Ok(plaintext)
    }

    /// Fast decode using a pre-derived key — skips PBKDF2 entirely.
    /// The caller must provide the already-derived 32-byte AES key.
    /// Use this on the hot path after deriving the key once with `derive_key`.
    pub fn decode_with_key(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < SALT_LENGTH + NONCE_LENGTH {
            return Err("Error".into());
        }

        // Salt is still present in the ciphertext format but we skip re-deriving
        let nonce = Nonce::from_slice(&ciphertext[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH]);
        let ct = &ciphertext[SALT_LENGTH + NONCE_LENGTH..];

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Error: {}", e))?;

        let plaintext = cipher.decrypt(nonce, ct).map_err(|e| format!("Error: {}", e))?;

        Ok(plaintext)
    }

    /// Derive key and return it for caching. Same as internal derive_key but public.
    pub fn derive_key_for_caching(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
        EncryptUtil::derive_key(password, salt)
    }

    /// Extract the salt from an encrypted payload (first 32 bytes)
    pub fn extract_salt(ciphertext: &[u8]) -> Result<&[u8], String> {
        if ciphertext.len() < SALT_LENGTH {
            return Err("Error".into());
        }
        Ok(&ciphertext[0..SALT_LENGTH])
    }

    pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
        let params = Params {
            rounds: ITERATIONS,
            output_length: 32,
        };

        let salt = SaltString::b64_encode(salt)
            .map_err(|e| format!("Error: {}", e))?;

        let hash = Pbkdf2.hash_password_customized(
            password.as_bytes(),
            None,
            None,
            params,
            &salt,
        ).map_err(|e| format!("Error: {}", e))?;

        Ok(hash.hash.ok_or("Error")?.as_bytes().to_vec())
    }

    pub fn byte_array_to_int(bytes: &[u8]) -> Result<i32, Box<dyn Error>> {
        if bytes.len() != 4 {
            return Err("Error".into());
        }

        let value = ((bytes[0] as i32) << 24) |
            ((bytes[1] as i32) << 16) |
            ((bytes[2] as i32) << 8) |
            (bytes[3] as i32);

        Ok(value)
    }

    pub fn decompress(compressed_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if compressed_bytes.is_empty() {
            return Ok(Vec::new());
        }

        let mut decoder = GzDecoder::new(compressed_bytes);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)?;

        Ok(decompressed_data)
    }
}

// Integrity anchor pointer
#[inline(never)]
pub fn derive_key_ptr() -> *const () {
    EncryptUtil::derive_key as *const ()
}
