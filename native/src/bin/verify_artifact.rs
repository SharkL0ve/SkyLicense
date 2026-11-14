use SkyLicense_64::artifact_integrity::{
    ARCH_AARCH64, ARCH_X86, ARCH_X86_64, MANIFEST_LENGTH, PLATFORM_LINUX, PLATFORM_WINDOWS,
    current_architecture, current_platform, manifest_path, parse_hex_32, validate_artifact_channel,
    validate_compiled_release_identity, verify_artifact_with_expectations,
};
use ed25519_dalek::VerifyingKey;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("verify_artifact: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let artifact = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: verify_artifact <native-library>".to_string())?;
    if arguments.next().is_some() {
        return Err("usage: verify_artifact <native-library>".to_string());
    }
    if !artifact.is_file() {
        return Err(format!(
            "native artifact does not exist: {}",
            artifact.display()
        ));
    }

    let public_key_bytes = parse_hex_32(
        &required_environment("SKYLICENSE_MANIFEST_PUBLIC_KEY")?,
        "SKYLICENSE_MANIFEST_PUBLIC_KEY",
    )?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| "SKYLICENSE_MANIFEST_PUBLIC_KEY is not a valid Ed25519 key".to_string())?;
    let minimum_epoch = parse_epoch(
        &required_environment("SKYLICENSE_MIN_SECURITY_EPOCH")?,
        "SKYLICENSE_MIN_SECURITY_EPOCH",
    )?;
    let expected_epoch = parse_epoch(
        &required_environment("SKYLICENSE_SECURITY_EPOCH")?,
        "SKYLICENSE_SECURITY_EPOCH",
    )?;
    if expected_epoch < minimum_epoch {
        return Err(format!(
            "expected security epoch {expected_epoch} is below minimum {minimum_epoch}"
        ));
    }
    let expected_build_id = parse_hex_32(
        &required_environment("SKYLICENSE_BUILD_ID")?,
        "SKYLICENSE_BUILD_ID",
    )?;
    if expected_build_id.iter().all(|byte| *byte == 0) {
        return Err("SKYLICENSE_BUILD_ID must not be all zero".to_string());
    }
    validate_compiled_release_identity(
        &public_key_bytes,
        minimum_epoch,
        expected_epoch,
        &expected_build_id,
    )?;
    let artifact_channel =
        std::env::var("SKYLICENSE_ARTIFACT_CHANNEL").unwrap_or_else(|_| "production".to_string());
    validate_artifact_channel(&artifact_channel, &expected_build_id, &public_key_bytes)?;

    let manifest = manifest_path(&artifact);
    verify_artifact_with_expectations(
        &artifact,
        &manifest,
        &public_key,
        minimum_epoch,
        Some(expected_epoch),
        Some(&expected_build_id),
    )?;

    let manifest_bytes = std::fs::read(&manifest)
        .map_err(|error| format!("failed to read {}: {error}", manifest.display()))?;
    if manifest_bytes.len() != MANIFEST_LENGTH {
        return Err("verified manifest changed during inspection".to_string());
    }
    let manifest_hash = encode_hex(&manifest_bytes[64..96]);
    let platform = current_platform()?;
    let architecture = current_architecture()?;

    println!("artifact={}", artifact.display());
    println!("manifest={}", manifest.display());
    println!("platform={}", platform_name(platform)?);
    println!("architecture={}", architecture_name(architecture)?);
    println!("artifact_channel={artifact_channel}");
    println!("security_epoch={expected_epoch}");
    println!("build_id={}", encode_hex(&expected_build_id));
    println!("artifact_sha256={manifest_hash}");
    println!(
        "allowed_client_build_ids=[\"{}\"]",
        encode_hex(&expected_build_id)
    );
    println!("verified=true");
    Ok(())
}

fn required_environment(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn parse_epoch(value: &str, name: &str) -> Result<u32, String> {
    let epoch = value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a positive 32-bit integer"))?;
    if epoch == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(epoch)
}

fn platform_name(value: u8) -> Result<&'static str, String> {
    match value {
        PLATFORM_WINDOWS => Ok("windows"),
        PLATFORM_LINUX => Ok("linux"),
        _ => Err(format!("unsupported platform code {value}")),
    }
}

fn architecture_name(value: u8) -> Result<&'static str, String> {
    match value {
        ARCH_X86_64 => Ok("x86_64"),
        ARCH_AARCH64 => Ok("aarch64"),
        ARCH_X86 => Ok("x86"),
        _ => Err(format!("unsupported architecture code {value}")),
    }
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
