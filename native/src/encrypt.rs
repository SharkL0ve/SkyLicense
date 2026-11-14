use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use flate2::bufread::GzDecoder;
use std::error::Error;
use std::io::Read;

const RESOURCE_MAGIC: &[u8; 8] = b"SKYRES04";
const METHOD_LOOKUP_MAGIC: &[u8; 8] = b"SKYMTH04";
const METHOD_STRING_MAGIC: &[u8; 8] = b"SKYSTR04";
const METHOD_LOOKUP_AAD: &[u8] = b"SkyLicense v4 method lookup\0";
const METHOD_STRING_AAD: &[u8] = b"SkyLicense v4 method string\0";
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

pub struct EncryptUtil;

impl EncryptUtil {
    pub fn decrypt_resource(
        envelope: &[u8],
        key: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::decrypt_envelope(envelope, key, associated_data, RESOURCE_MAGIC)
    }

    pub fn decrypt_method_lookup(envelope: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        Self::decrypt_envelope(envelope, key, METHOD_LOOKUP_AAD, METHOD_LOOKUP_MAGIC)
    }

    pub fn decrypt_method_string(envelope: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        Self::decrypt_envelope(envelope, key, METHOD_STRING_AAD, METHOD_STRING_MAGIC)
    }

    fn decrypt_envelope(
        envelope: &[u8],
        key: &[u8],
        associated_data: &[u8],
        expected_magic: &[u8; 8],
    ) -> Result<Vec<u8>, String> {
        if key.len() != KEY_LENGTH {
            return Err("AEAD key must contain 32 bytes".to_string());
        }
        if envelope.len() < expected_magic.len() + NONCE_LENGTH + TAG_LENGTH {
            return Err("encrypted envelope is truncated".to_string());
        }
        if envelope.get(..expected_magic.len()) != Some(expected_magic) {
            return Err("encrypted envelope has an invalid magic".to_string());
        }

        let nonce_start = expected_magic.len();
        let ciphertext_start = nonce_start + NONCE_LENGTH;
        let nonce = Nonce::from_slice(&envelope[nonce_start..ciphertext_start]);
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "AEAD key initialization failed".to_string())?;
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &envelope[ciphertext_start..],
                    aad: associated_data,
                },
            )
            .map_err(|_| "encrypted envelope authentication failed".to_string())
    }

    pub fn byte_array_to_int(bytes: &[u8]) -> Result<i32, Box<dyn Error>> {
        if bytes.len() != 4 {
            return Err("integer must contain exactly four bytes".into());
        }
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn decompress_exact(
        compressed_bytes: &[u8],
        expected_length: usize,
        maximum_length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if expected_length > maximum_length {
            return Err("decompressed data exceeds the configured limit".into());
        }
        if compressed_bytes.is_empty() {
            return if expected_length == 0 {
                Ok(Vec::new())
            } else {
                Err("compressed data is empty".into())
            };
        }

        let decoder = GzDecoder::new(compressed_bytes);
        let mut limited = decoder.take(expected_length.saturating_add(1) as u64);
        let mut decompressed_data = Vec::with_capacity(expected_length);
        limited.read_to_end(&mut decompressed_data)?;
        if decompressed_data.len() != expected_length {
            return Err("decompressed length does not match the declared length".into());
        }
        Ok(decompressed_data)
    }
}

// Integrity anchor pointer.
#[inline(never)]
pub fn decrypt_resource_ptr() -> *const () {
    EncryptUtil::decrypt_resource as *const ()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn resource_envelope_matches_java_protocol_vector() {
        let key = hex("65c5f2dad7eb61583e7ab30df7ebefcd260e092f2bf8a8537c90ea1ad65fb4b0");
        let associated_data = hex(concat!(
            "536b794c6963656e7365207634207265736f757263652061616400",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "00000007",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "00000006706c7567696e00000005312e322e33"
        ));
        let envelope = hex(concat!(
            "534b595245533034000102030405060708090a0b",
            "5e037fde97dcb8d1c77718b7f5cfadaac9bce06ded38748d987055c6a5146f",
            "bc4bf07f79511d8dbc0ca55bbbfc0f"
        ));
        assert_eq!(
            EncryptUtil::decrypt_resource(&envelope, &key, &associated_data).unwrap(),
            b"cross-language resource vector"
        );
    }

    #[test]
    fn method_envelopes_match_java_protocol_vectors() {
        let key = hex("21e920e117963a013464111f672e1d374649b09ec19b9242c1e97775f3142396");
        let lookup = hex(
            "534b594d54483034000102030405060708090a0b99114bd1ea5c390bec1f0086100ac117b359b19d118db46c19e3f8cc",
        );
        let string = hex(
            "534b595354523034000102030405060708090a0b861b47c8fa58390cf7060c86b583f9c0b2450018362367b168e0d3173b",
        );
        assert_eq!(
            EncryptUtil::decrypt_method_lookup(&lookup, &key).unwrap(),
            b"lookup-token"
        );
        assert_eq!(
            EncryptUtil::decrypt_method_string(&string, &key).unwrap(),
            b"secret-string"
        );
    }

    #[test]
    fn rejects_wrong_magic_and_tampering() {
        let mut envelope = vec![0u8; 8 + NONCE_LENGTH + TAG_LENGTH];
        envelope[..8].copy_from_slice(RESOURCE_MAGIC);
        assert!(EncryptUtil::decrypt_resource(&envelope, &[7; 32], b"aad").is_err());

        envelope[0] ^= 1;
        assert!(EncryptUtil::decrypt_resource(&envelope, &[7; 32], b"aad").is_err());
    }
}
