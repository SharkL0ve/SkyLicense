use SkyLicense_64::artifact_integrity::{
    ARCH_AARCH64, ARCH_X86, ARCH_X86_64, MANIFEST_HEADER_LENGTH, MANIFEST_LENGTH, MANIFEST_MAGIC,
    PLATFORM_LINUX, PLATFORM_WINDOWS, build_manifest_header, hash_file, signing_message,
    validate_artifact_channel, validate_compiled_release_identity,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("sign_artifact: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let argument = std::env::args_os()
        .nth(1)
        .ok_or_else(|| "usage: sign_artifact <native-library> | --print-public-key".to_string())?;
    let private_key_hex = Zeroizing::new(
        std::env::var("SKYLICENSE_MANIFEST_PRIVATE_KEY")
            .map_err(|_| "SKYLICENSE_MANIFEST_PRIVATE_KEY is required".to_string())?,
    );
    let private_key = Zeroizing::new(parse_private_key(&private_key_hex)?);
    let signing_key = SigningKey::from_bytes(&private_key);
    if argument == "--print-public-key" {
        println!(
            "public_key={}",
            encode_hex(&signing_key.verifying_key().to_bytes())
        );
        return Ok(());
    }

    let public_key = validate_declared_public_key(
        &signing_key,
        &required_environment("SKYLICENSE_MANIFEST_PUBLIC_KEY")?,
    )?;

    let artifact = PathBuf::from(argument);
    let minimum_security_epoch = parse_security_epoch(
        &required_environment("SKYLICENSE_MIN_SECURITY_EPOCH")?,
        "SKYLICENSE_MIN_SECURITY_EPOCH",
    )?;
    let security_epoch = parse_security_epoch(
        &required_environment("SKYLICENSE_SECURITY_EPOCH")?,
        "SKYLICENSE_SECURITY_EPOCH",
    )?;
    if security_epoch < minimum_security_epoch {
        return Err(format!(
            "SKYLICENSE_SECURITY_EPOCH {security_epoch} is below minimum {minimum_security_epoch}"
        ));
    }
    let build_id_hex = required_environment("SKYLICENSE_BUILD_ID")?;
    let build_id = parse_hex_32_named(&build_id_hex, "SKYLICENSE_BUILD_ID")?;
    if build_id.iter().all(|byte| *byte == 0) {
        return Err("SKYLICENSE_BUILD_ID must not be all zero".to_string());
    }
    validate_compiled_release_identity(
        &public_key,
        minimum_security_epoch,
        security_epoch,
        &build_id,
    )?;
    let artifact_channel =
        std::env::var("SKYLICENSE_ARTIFACT_CHANNEL").unwrap_or_else(|_| "production".to_string());
    validate_artifact_channel(&artifact_channel, &build_id, &public_key)?;

    let hash = hash_file(&artifact)?;
    let (platform, architecture) = detect_artifact_target(&artifact)?;

    let header = build_manifest_header(platform, architecture, security_epoch, &build_id, &hash)?;
    let message = signing_message(&header);
    let signature = signing_key.sign(&message);

    let mut manifest = Vec::with_capacity(MANIFEST_LENGTH);
    manifest.extend_from_slice(&header);
    manifest.extend_from_slice(&signature.to_bytes());
    let mut output = artifact.as_os_str().to_os_string();
    output.push(".integrity");
    std::fs::write(&output, manifest).map_err(|error| {
        format!(
            "failed to write {}: {error}",
            PathBuf::from(&output).display()
        )
    })?;

    let written = std::fs::read(&output).map_err(|error| error.to_string())?;
    if written.len() != MANIFEST_LENGTH
        || written[..MANIFEST_HEADER_LENGTH] != header
        || &written[..8] != MANIFEST_MAGIC
    {
        return Err("written manifest failed its structural self-check".to_string());
    }
    let written_signature =
        Signature::from_slice(&written[MANIFEST_HEADER_LENGTH..MANIFEST_LENGTH])
            .map_err(|_| "written signature is malformed".to_string())?;
    signing_key
        .verifying_key()
        .verify_strict(&message, &written_signature)
        .map_err(|_| "written manifest signature did not verify".to_string())?;
    if hash_file(&artifact)? != hash {
        let _ = std::fs::remove_file(&output);
        return Err("native artifact changed while its manifest was being written".to_string());
    }

    println!("manifest={}", PathBuf::from(output).display());
    println!(
        "public_key={}",
        encode_hex(&signing_key.verifying_key().to_bytes())
    );
    println!("artifact_channel={artifact_channel}");
    println!("security_epoch={security_epoch}");
    println!("build_id={}", encode_hex(&build_id));
    println!("verified=true");
    Ok(())
}

fn required_environment(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    parse_hex_32_named(value, "private key")
}

fn parse_private_key(value: &str) -> Result<[u8; 32], String> {
    let private_key = parse_hex_32(value)?;
    if private_key.iter().all(|byte| *byte == 0) {
        return Err("SKYLICENSE_MANIFEST_PRIVATE_KEY must not be all zero".to_string());
    }
    Ok(private_key)
}

fn validate_declared_public_key(
    signing_key: &SigningKey,
    declared_public_key: &str,
) -> Result<[u8; 32], String> {
    let public_key = parse_hex_32_named(declared_public_key, "SKYLICENSE_MANIFEST_PUBLIC_KEY")?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "SKYLICENSE_MANIFEST_PUBLIC_KEY is not a valid Ed25519 key".to_string())?;
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(
            "SKYLICENSE_MANIFEST_PRIVATE_KEY does not match SKYLICENSE_MANIFEST_PUBLIC_KEY"
                .to_string(),
        );
    }
    Ok(public_key)
}

fn parse_hex_32_named(value: &str, name: &str) -> Result<[u8; 32], String> {
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

fn parse_security_epoch(value: &str, name: &str) -> Result<u32, String> {
    let epoch = value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a positive 32-bit integer"))?;
    if epoch == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(epoch)
}

fn detect_artifact_target(path: &std::path::Path) -> Result<(u8, u8), String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut header = vec![0u8; 4096];
    let read = file
        .read(&mut header)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    header.truncate(read);

    if header.starts_with(b"MZ") {
        let pe_offset = read_u32_le(&header, 0x3c)? as usize;
        if header.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            return Err("invalid PE signature".to_string());
        }
        let machine = read_u16_le(&header, pe_offset + 4)?;
        return Ok((PLATFORM_WINDOWS, architecture_from_pe(machine)?));
    }

    if header.starts_with(b"\x7fELF") {
        if header.get(5) != Some(&1) {
            return Err("only little-endian ELF artifacts are supported".to_string());
        }
        let machine = read_u16_le(&header, 18)?;
        return Ok((PLATFORM_LINUX, architecture_from_elf(machine)?));
    }

    Err("artifact is neither a PE image nor an ELF object".to_string())
}

fn architecture_from_pe(machine: u16) -> Result<u8, String> {
    match machine {
        0x8664 => Ok(ARCH_X86_64),
        0xAA64 => Ok(ARCH_AARCH64),
        0x014C => Ok(ARCH_X86),
        _ => Err(format!("unsupported PE machine type {machine:#06x}")),
    }
}

fn architecture_from_elf(machine: u16) -> Result<u8, String> {
    match machine {
        62 => Ok(ARCH_X86_64),
        183 => Ok(ARCH_AARCH64),
        3 => Ok(ARCH_X86),
        _ => Err(format!("unsupported ELF machine type {machine}")),
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated artifact header".to_string())?
        .try_into()
        .map_err(|_| "invalid two-byte field".to_string())?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated artifact header".to_string())?
        .try_into()
        .map_err(|_| "invalid four-byte field".to_string())?;
    Ok(u32::from_le_bytes(bytes))
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_seed_must_be_nonzero() {
        assert!(parse_private_key(&"00".repeat(32)).is_err());
        assert_eq!(parse_private_key(&"07".repeat(32)).unwrap(), [7u8; 32]);
    }

    #[test]
    fn declared_public_key_must_match_private_seed() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        assert!(
            validate_declared_public_key(
                &signing_key,
                "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
            )
            .is_ok()
        );
        assert!(validate_declared_public_key(&signing_key, &"01".repeat(32)).is_err());
    }

    #[test]
    fn epoch_errors_name_the_invalid_variable() {
        let error = parse_security_epoch("invalid", "SKYLICENSE_MIN_SECURITY_EPOCH").unwrap_err();
        assert!(error.contains("SKYLICENSE_MIN_SECURITY_EPOCH"));
    }
}
