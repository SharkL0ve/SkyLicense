use sha2::{Sha256, Digest};
use std::process::Command;

/// Collect hardware identifiers and generate a unique fingerprint
pub fn get_hwid() -> String {
    let mut hasher = Sha256::new();

    // CPU ID
    if let Some(cpu_id) = get_cpu_id() {
        hasher.update(cpu_id.as_bytes());
    }

    // Motherboard serial
    if let Some(mb_serial) = get_motherboard_serial() {
        hasher.update(mb_serial.as_bytes());
    }

    // Disk serial number
    if let Some(disk_serial) = get_disk_serial() {
        hasher.update(disk_serial.as_bytes());
    }

    // Machine GUID (Windows) or machine-id (Linux)
    if let Some(machine_id) = get_machine_id() {
        hasher.update(machine_id.as_bytes());
    }

    let result = hasher.finalize();
    base64::encode(&result[..])
}

#[cfg(target_os = "windows")]
fn get_cpu_id() -> Option<String> {
    let output = Command::new("wmic")
        .args(["cpu", "get", "ProcessorId"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn get_cpu_id() -> Option<String> {
    let output = Command::new("cat")
        .arg("/proc/cpuinfo")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.starts_with("model name") || line.starts_with("Serial") {
            return Some(line.to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_motherboard_serial() -> Option<String> {
    let output = Command::new("wmic")
        .args(["baseboard", "get", "SerialNumber"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn get_motherboard_serial() -> Option<String> {
    std::fs::read_to_string("/sys/class/dmi/id/board_serial").ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "windows")]
fn get_disk_serial() -> Option<String> {
    let output = Command::new("wmic")
        .args(["diskdrive", "get", "SerialNumber"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn get_disk_serial() -> Option<String> {
    let output = Command::new("lsblk")
        .args(["-no", "SERIAL", "/dev/sda"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Some(text.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn get_machine_id() -> Option<String> {
    let output = Command::new("reg")
        .args(["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains("MachineGuid") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts.last()?.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_machine_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
}
