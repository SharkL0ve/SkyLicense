use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256};

const MAX_IDENTIFIER_BYTES: usize = 1_024;

/// Collect stable machine identifiers without launching attacker-controlled
/// helper executables. Authentication fails closed if every source is absent.
pub fn get_hwid() -> Result<String, String> {
    let components = platform_components();
    fingerprint_components(&components)
}

fn fingerprint_components(components: &[(&'static str, String)]) -> Result<String, String> {
    if components.is_empty() {
        return Err("no stable hardware identifier is available".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"SkyLicense hardware fingerprint v2\0");
    hasher.update((components.len() as u32).to_be_bytes());
    for (label, value) in components {
        let label = label.as_bytes();
        let value = value.as_bytes();
        let label_length = u16::try_from(label.len())
            .map_err(|_| "hardware identifier label is too long".to_string())?;
        let value_length = u32::try_from(value.len())
            .map_err(|_| "hardware identifier value is too long".to_string())?;
        hasher.update(label_length.to_be_bytes());
        hasher.update(label);
        hasher.update(value_length.to_be_bytes());
        hasher.update(value);
    }
    Ok(BASE64_STANDARD.encode(hasher.finalize()))
}

#[cfg(target_os = "windows")]
fn platform_components() -> Vec<(&'static str, String)> {
    let mut components = Vec::new();
    push_registry_value(
        &mut components,
        "machine_guid",
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
    );
    push_registry_value(
        &mut components,
        "cpu_identifier",
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "Identifier",
    );
    push_registry_value(
        &mut components,
        "cpu_name",
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    );
    push_registry_value(
        &mut components,
        "baseboard_product",
        r"HARDWARE\DESCRIPTION\System\BIOS",
        "BaseBoardProduct",
    );
    push_registry_value(
        &mut components,
        "system_product",
        r"HARDWARE\DESCRIPTION\System\BIOS",
        "SystemProductName",
    );
    components
}

#[cfg(target_os = "windows")]
fn push_registry_value(
    components: &mut Vec<(&'static str, String)>,
    label: &'static str,
    path: &str,
    name: &str,
) {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = machine.open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY) else {
        return;
    };
    let Ok(value) = key.get_value::<String, _>(name) else {
        return;
    };
    if let Some(value) = normalize_identifier(&value) {
        components.push((label, value));
    }
}

#[cfg(target_os = "linux")]
fn platform_components() -> Vec<(&'static str, String)> {
    let mut components = Vec::new();
    push_file_identifier(
        &mut components,
        "machine_id",
        &["/etc/machine-id", "/var/lib/dbus/machine-id"],
    );
    push_file_identifier(
        &mut components,
        "product_uuid",
        &["/sys/class/dmi/id/product_uuid"],
    );
    push_file_identifier(
        &mut components,
        "board_serial",
        &["/sys/class/dmi/id/board_serial"],
    );
    if let Some(cpu) = read_cpu_identifier() {
        components.push(("cpu", cpu));
    }
    if let Some(disk) = read_disk_identifier() {
        components.push(("disk", disk));
    }
    components
}

#[cfg(target_os = "linux")]
fn push_file_identifier(
    components: &mut Vec<(&'static str, String)>,
    label: &'static str,
    candidates: &[&str],
) {
    if let Some(value) = candidates
        .iter()
        .find_map(|path| read_identifier_file(path))
    {
        components.push((label, value));
    }
}

#[cfg(target_os = "linux")]
fn read_cpu_identifier() -> Option<String> {
    let content = read_bounded_file("/proc/cpuinfo", 1024 * 1024)?;
    let text = std::str::from_utf8(&content).ok()?;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(name.trim(), "Serial" | "model name" | "Hardware") {
            if let Some(value) = normalize_identifier(value) {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_disk_identifier() -> Option<String> {
    let mut devices = std::fs::read_dir("/sys/block")
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with("loop") && !name.starts_with("ram"))
        })
        .take(64)
        .collect::<Vec<_>>();
    devices.sort();
    for device in devices {
        for relative in ["device/serial", "serial"] {
            if let Some(value) = read_identifier_file(&device.join(relative)) {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_identifier_file(path: impl AsRef<std::path::Path>) -> Option<String> {
    let content = read_bounded_file(path, MAX_IDENTIFIER_BYTES)?;
    let value = std::str::from_utf8(&content).ok()?;
    normalize_identifier(value)
}

#[cfg(target_os = "linux")]
fn read_bounded_file(path: impl AsRef<std::path::Path>, maximum: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path).ok()?;
    let limit = u64::try_from(maximum).ok()?.checked_add(1)?;
    let mut content = Vec::with_capacity(maximum.min(8 * 1024));
    file.take(limit).read_to_end(&mut content).ok()?;
    (content.len() <= maximum).then_some(content)
}

fn normalize_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return None;
    }
    let normalized = value.to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "unknown"
            | "none"
            | "default string"
            | "system serial number"
            | "to be filled by o.e.m."
            | "00000000-0000-0000-0000-000000000000"
    ) || normalized
        .bytes()
        .all(|byte| matches!(byte, b'0' | b'-' | b' '))
    {
        return None;
    }
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_boundaries_prevent_concatenation_ambiguity() {
        let first = fingerprint_components(&[("a", "bc".to_string())]).unwrap();
        let second = fingerprint_components(&[("ab", "c".to_string())]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn empty_or_placeholder_components_are_rejected() {
        assert!(fingerprint_components(&[]).is_err());
        assert!(normalize_identifier("unknown").is_none());
        assert!(normalize_identifier("0000-0000").is_none());
        assert_eq!(
            normalize_identifier(" stable-id ").as_deref(),
            Some("stable-id")
        );
    }
}
