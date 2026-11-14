//! Detached Ed25519 integrity manifest for the native library on disk.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};

#[path = "release_identity.rs"]
mod release_identity;

pub const MANIFEST_MAGIC: &[u8; 8] = b"SKYINT02";
pub const PRODUCT_ID: &[u8; 16] = b"SkyLicense\0\0\0\0\0\0";
pub const MANIFEST_HEADER_LENGTH: usize = 96;
pub const MANIFEST_LENGTH: usize = MANIFEST_HEADER_LENGTH + 64;
pub const SIGNING_DOMAIN: &[u8] = b"SkyLicense artifact v2\0";
const PUBLIC_KEY: Option<&str> = option_env!("SKYLICENSE_MANIFEST_PUBLIC_KEY");
const MIN_SECURITY_EPOCH: Option<&str> = option_env!("SKYLICENSE_MIN_SECURITY_EPOCH");
const COMPILED_SECURITY_EPOCH: Option<&str> = option_env!("SKYLICENSE_SECURITY_EPOCH");
const COMPILED_BUILD_ID: Option<&str> = option_env!("SKYLICENSE_BUILD_ID");

pub const PLATFORM_WINDOWS: u8 = 1;
pub const PLATFORM_LINUX: u8 = 2;
pub const ARCH_X86_64: u8 = 1;
pub const ARCH_AARCH64: u8 = 2;
pub const ARCH_X86: u8 = 3;

pub fn verify_current_library(require_manifest: bool) -> Result<(), String> {
    let Some(public_key) = PUBLIC_KEY else {
        return if require_manifest {
            Err("SKYLICENSE_MANIFEST_PUBLIC_KEY was not provided at build time".to_string())
        } else {
            Ok(())
        };
    };
    let minimum_epoch = match MIN_SECURITY_EPOCH {
        Some(value) => parse_security_epoch(value, "SKYLICENSE_MIN_SECURITY_EPOCH")?,
        None if require_manifest => {
            return Err("SKYLICENSE_MIN_SECURITY_EPOCH was not provided at build time".to_string());
        }
        None => 0,
    };
    let expected_epoch = match COMPILED_SECURITY_EPOCH {
        Some(value) => parse_security_epoch(value, "SKYLICENSE_SECURITY_EPOCH")?,
        None if require_manifest => {
            return Err("SKYLICENSE_SECURITY_EPOCH was not provided at build time".to_string());
        }
        None => 0,
    };
    let expected_build_id = match COMPILED_BUILD_ID {
        Some(value) => parse_hex_32(value, "SKYLICENSE_BUILD_ID")?,
        None if require_manifest => {
            return Err("SKYLICENSE_BUILD_ID was not provided at build time".to_string());
        }
        None => [0; 32],
    };
    if expected_epoch < minimum_epoch {
        return Err(format!(
            "compiled security epoch {expected_epoch} is below required epoch {minimum_epoch}"
        ));
    }
    if require_manifest && expected_build_id.iter().all(|byte| *byte == 0) {
        return Err("SKYLICENSE_BUILD_ID must not be all zero".to_string());
    }
    let artifact = current_library_path()?;
    verify_artifact_with_expectations(
        &artifact,
        &manifest_path(&artifact),
        &parse_public_key(public_key)?,
        minimum_epoch,
        (expected_epoch != 0).then_some(expected_epoch),
        (expected_build_id != [0; 32]).then_some(&expected_build_id),
    )
}

pub fn verify_artifact(
    artifact: &Path,
    manifest: &Path,
    public_key: &VerifyingKey,
) -> Result<(), String> {
    verify_artifact_with_minimum(artifact, manifest, public_key, 0)
}

pub fn verify_artifact_with_minimum(
    artifact: &Path,
    manifest: &Path,
    public_key: &VerifyingKey,
    minimum_security_epoch: u32,
) -> Result<(), String> {
    verify_artifact_with_expectations(
        artifact,
        manifest,
        public_key,
        minimum_security_epoch,
        None,
        None,
    )
}

pub fn verify_artifact_with_expectations(
    artifact: &Path,
    manifest: &Path,
    public_key: &VerifyingKey,
    minimum_security_epoch: u32,
    expected_security_epoch: Option<u32>,
    expected_build_id: Option<&[u8; 32]>,
) -> Result<(), String> {
    let manifest_bytes = std::fs::read(manifest)
        .map_err(|error| format!("failed to read {}: {error}", manifest.display()))?;
    if manifest_bytes.len() != MANIFEST_LENGTH
        || &manifest_bytes[..MANIFEST_MAGIC.len()] != MANIFEST_MAGIC
    {
        return Err("invalid artifact-integrity manifest format".to_string());
    }

    if &manifest_bytes[8..24] != PRODUCT_ID {
        return Err("artifact manifest product id does not match SkyLicense".to_string());
    }
    if manifest_bytes[24] != current_platform()? || manifest_bytes[25] != current_architecture()? {
        return Err("artifact manifest platform or architecture mismatch".to_string());
    }
    if manifest_bytes[26..28] != [0, 0] {
        return Err("artifact manifest reserved bytes are not zero".to_string());
    }
    let manifest_build_id: [u8; 32] = manifest_bytes[32..64]
        .try_into()
        .map_err(|_| "invalid artifact build id encoding".to_string())?;
    if manifest_build_id.iter().all(|byte| *byte == 0) {
        return Err("artifact manifest build id must not be zero".to_string());
    }
    let security_epoch = u32::from_be_bytes(
        manifest_bytes[28..32]
            .try_into()
            .map_err(|_| "invalid security epoch encoding".to_string())?,
    );
    if security_epoch == 0 || security_epoch < minimum_security_epoch {
        return Err(format!(
            "artifact security epoch {security_epoch} is below required epoch {minimum_security_epoch}"
        ));
    }
    if expected_security_epoch.is_some_and(|expected| security_epoch != expected) {
        return Err("artifact security epoch does not match the compiled binary".to_string());
    }
    if expected_build_id.is_some_and(|expected| !constant_time_equal(&manifest_build_id, expected))
    {
        return Err("artifact build id does not match the compiled binary".to_string());
    }

    let expected_hash: [u8; 32] = manifest_bytes[64..96]
        .try_into()
        .map_err(|_| "invalid manifest hash length".to_string())?;
    let actual_hash = hash_file(artifact)?;
    if !constant_time_equal(&expected_hash, &actual_hash) {
        return Err("native library SHA-256 does not match its signed manifest".to_string());
    }

    let signature = Signature::from_slice(&manifest_bytes[96..160])
        .map_err(|_| "invalid Ed25519 signature encoding".to_string())?;
    let message = signing_message(&manifest_bytes[..MANIFEST_HEADER_LENGTH]);
    public_key
        .verify_strict(&message, &signature)
        .map_err(|_| "artifact-integrity signature verification failed".to_string())
}

pub fn compiled_security_epoch() -> Result<u32, String> {
    let value = COMPILED_SECURITY_EPOCH
        .ok_or_else(|| "SKYLICENSE_SECURITY_EPOCH was not provided at build time".to_string())?;
    parse_security_epoch(value, "SKYLICENSE_SECURITY_EPOCH")
}

pub fn compiled_minimum_security_epoch() -> Result<u32, String> {
    let value = MIN_SECURITY_EPOCH.ok_or_else(|| {
        "SKYLICENSE_MIN_SECURITY_EPOCH was not provided at build time".to_string()
    })?;
    parse_security_epoch(value, "SKYLICENSE_MIN_SECURITY_EPOCH")
}

pub fn compiled_build_id() -> Result<[u8; 32], String> {
    let value = COMPILED_BUILD_ID
        .ok_or_else(|| "SKYLICENSE_BUILD_ID was not provided at build time".to_string())?;
    let build_id = parse_hex_32(value, "SKYLICENSE_BUILD_ID")?;
    if build_id.iter().all(|byte| *byte == 0) {
        return Err("SKYLICENSE_BUILD_ID must not be all zero".to_string());
    }
    Ok(build_id)
}

pub fn compiled_manifest_public_key() -> Result<[u8; 32], String> {
    let value = PUBLIC_KEY.ok_or_else(|| {
        "SKYLICENSE_MANIFEST_PUBLIC_KEY was not provided at build time".to_string()
    })?;
    let bytes = parse_hex_32(value, "SKYLICENSE_MANIFEST_PUBLIC_KEY")?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "SKYLICENSE_MANIFEST_PUBLIC_KEY is not a valid Ed25519 key".to_string())?;
    Ok(bytes)
}

pub fn validate_compiled_release_identity(
    public_key: &[u8; 32],
    minimum_security_epoch: u32,
    security_epoch: u32,
    build_id: &[u8; 32],
) -> Result<(), String> {
    if compiled_manifest_public_key()? != *public_key
        || compiled_minimum_security_epoch()? != minimum_security_epoch
        || compiled_security_epoch()? != security_epoch
        || compiled_build_id()? != *build_id
    {
        return Err(
            "runtime release identity does not match the values compiled into the tool".to_string(),
        );
    }
    Ok(())
}

pub fn validate_artifact_channel(
    channel: &str,
    build_id: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<(), String> {
    let ci_build_id = parse_hex_32(release_identity::CI_TEST_BUILD_ID_HEX, "CI test Build ID")?;
    let ci_public_key = parse_hex_32(
        release_identity::CI_TEST_PUBLIC_KEY_HEX,
        "CI test public key",
    )?;
    let uses_ci_identity = build_id == &ci_build_id || public_key == &ci_public_key;

    match channel {
        "production" if uses_ci_identity => {
            Err("known CI test identity cannot be used for a production artifact".to_string())
        }
        "production" => Ok(()),
        "ci-test" if build_id == &ci_build_id && public_key == &ci_public_key => Ok(()),
        "ci-test" => Err(
            "ci-test channel must use the pinned CI Build ID and manifest public key".to_string(),
        ),
        _ => Err("SKYLICENSE_ARTIFACT_CHANNEL must be either production or ci-test".to_string()),
    }
}

pub fn hash_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

pub fn signing_message(header: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + header.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(header);
    message
}

pub fn build_manifest_header(
    platform: u8,
    architecture: u8,
    security_epoch: u32,
    build_id: &[u8; 32],
    artifact_hash: &[u8; 32],
) -> Result<[u8; MANIFEST_HEADER_LENGTH], String> {
    if security_epoch == 0 {
        return Err("artifact security epoch must be greater than zero".to_string());
    }
    if build_id.iter().all(|byte| *byte == 0) {
        return Err("artifact build id must not be zero".to_string());
    }
    let mut header = [0u8; MANIFEST_HEADER_LENGTH];
    header[..8].copy_from_slice(MANIFEST_MAGIC);
    header[8..24].copy_from_slice(PRODUCT_ID);
    header[24] = platform;
    header[25] = architecture;
    header[28..32].copy_from_slice(&security_epoch.to_be_bytes());
    header[32..64].copy_from_slice(build_id);
    header[64..96].copy_from_slice(artifact_hash);
    Ok(header)
}

pub fn current_platform() -> Result<u8, String> {
    if cfg!(target_os = "windows") {
        Ok(PLATFORM_WINDOWS)
    } else if cfg!(target_os = "linux") {
        Ok(PLATFORM_LINUX)
    } else {
        Err("artifact manifests support only Windows and Linux".to_string())
    }
}

pub fn current_architecture() -> Result<u8, String> {
    if cfg!(target_arch = "x86_64") {
        Ok(ARCH_X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(ARCH_AARCH64)
    } else if cfg!(target_arch = "x86") {
        Ok(ARCH_X86)
    } else {
        Err("unsupported artifact architecture".to_string())
    }
}

fn parse_security_epoch(value: &str, name: &str) -> Result<u32, String> {
    let epoch = value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a positive 32-bit integer"))?;
    if epoch == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(epoch)
}

pub fn manifest_path(artifact: &Path) -> PathBuf {
    let mut path = OsString::from(artifact.as_os_str());
    path.push(".integrity");
    PathBuf::from(path)
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, String> {
    let bytes = parse_hex_32(value, "SKYLICENSE_MANIFEST_PUBLIC_KEY")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 public key".to_string())
}

pub fn parse_hex_32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid {name}"))?;
    }
    Ok(output)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(target_os = "windows")]
fn current_library_path() -> Result<PathBuf, String> {
    use winapi::shared::minwindef::HMODULE;
    use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleExW};

    const FROM_ADDRESS: u32 = 0x0000_0004;
    const UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
    let mut module: HMODULE = std::ptr::null_mut();
    let address = crate::JNI_OnLoad as *const () as *const u16;
    let found =
        unsafe { GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, address, &mut module) };
    if found == 0 || module.is_null() {
        return Err("failed to locate the current native module".to_string());
    }

    let mut buffer = vec![0u16; 32 * 1024];
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("failed to resolve the current native module path".to_string());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..length as usize],
    )))
}

#[cfg(target_os = "linux")]
fn current_library_path() -> Result<PathBuf, String> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let address = crate::JNI_OnLoad as *const () as *const std::ffi::c_void;
    if unsafe { libc::dladdr(address, &mut info) } == 0 || info.dli_fname.is_null() {
        return Err("failed to locate the current native module".to_string());
    }
    let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
    Ok(PathBuf::from(path.to_string_lossy().into_owned()))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn current_library_path() -> Result<PathBuf, String> {
    Err("signed artifact verification is unsupported on this operating system".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn signed_manifest_detects_artifact_mutation() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("sky-integrity-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let artifact = directory.join("library.bin");
        let manifest = manifest_path(&artifact);
        std::fs::write(&artifact, b"trusted artifact").unwrap();

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let hash = hash_file(&artifact).unwrap();
        let header = build_manifest_header(
            current_platform().unwrap(),
            current_architecture().unwrap(),
            7,
            &[9u8; 32],
            &hash,
        )
        .unwrap();
        let signature = signing_key.sign(&signing_message(&header));
        let mut bytes = Vec::with_capacity(MANIFEST_LENGTH);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&signature.to_bytes());
        std::fs::write(&manifest, bytes).unwrap();

        assert!(
            verify_artifact_with_minimum(&artifact, &manifest, &signing_key.verifying_key(), 7)
                .is_ok()
        );
        assert!(
            verify_artifact_with_expectations(
                &artifact,
                &manifest,
                &signing_key.verifying_key(),
                7,
                Some(7),
                Some(&[8; 32]),
            )
            .is_err()
        );
        assert!(
            verify_artifact_with_minimum(&artifact, &manifest, &signing_key.verifying_key(), 8)
                .is_err()
        );
        std::fs::write(&artifact, b"mutated artifact").unwrap();
        assert!(verify_artifact(&artifact, &manifest, &signing_key.verifying_key()).is_err());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn manifest_header_rejects_zero_epoch_and_build_id() {
        let platform = current_platform().unwrap();
        let architecture = current_architecture().unwrap();
        assert!(build_manifest_header(platform, architecture, 0, &[1; 32], &[2; 32]).is_err());
        assert!(build_manifest_header(platform, architecture, 1, &[0; 32], &[2; 32]).is_err());
    }

    #[test]
    fn artifact_channels_keep_ci_and_production_identities_separate() {
        let ci_build_id =
            parse_hex_32(release_identity::CI_TEST_BUILD_ID_HEX, "CI test Build ID").unwrap();
        let ci_public_key = parse_hex_32(
            release_identity::CI_TEST_PUBLIC_KEY_HEX,
            "CI test public key",
        )
        .unwrap();
        let production_build_id = [8u8; 32];
        let production_public_key = [7u8; 32];

        assert!(
            validate_artifact_channel("production", &production_build_id, &production_public_key)
                .is_ok()
        );
        assert!(
            validate_artifact_channel("production", &ci_build_id, &production_public_key).is_err()
        );
        assert!(
            validate_artifact_channel("production", &production_build_id, &ci_public_key).is_err()
        );
        assert!(validate_artifact_channel("ci-test", &ci_build_id, &ci_public_key).is_ok());
        assert!(
            validate_artifact_channel("ci-test", &production_build_id, &production_public_key)
                .is_err()
        );
        assert!(
            validate_artifact_channel("unexpected", &production_build_id, &production_public_key)
                .is_err()
        );
    }

    #[test]
    fn compiled_release_identity_rejects_runtime_drift() {
        let public_key = compiled_manifest_public_key().unwrap();
        let minimum_epoch = compiled_minimum_security_epoch().unwrap();
        let security_epoch = compiled_security_epoch().unwrap();
        let build_id = compiled_build_id().unwrap();

        assert!(
            validate_compiled_release_identity(
                &public_key,
                minimum_epoch,
                security_epoch,
                &build_id
            )
            .is_ok()
        );

        let mut changed_build_id = build_id;
        changed_build_id[0] ^= 1;
        assert!(
            validate_compiled_release_identity(
                &public_key,
                minimum_epoch,
                security_epoch,
                &changed_build_id
            )
            .is_err()
        );
    }

    #[test]
    fn current_module_path_can_be_resolved() {
        let path = current_library_path().unwrap();
        assert!(
            path.is_file(),
            "resolved module does not exist: {}",
            path.display()
        );
    }
}
