//! JVM attach and native-agent monitoring.
//!
//! The default implementation is deliberately non-invasive. It does not patch
//! HotSpot, mutate the process DACL, replace SIGQUIT, suspend JVM threads, or
//! interfere with system-wide named pipes. Those techniques are version-specific
//! and unsafe inside a shared host JVM. Strong attach prevention must be enabled
//! with JVM launch flags; runtime observations are collected as evidence here.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static MODULE_BASELINE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[cfg(target_os = "windows")]
const JDWP_PORTS: &[u16] = &[5005, 8000, 8787, 5050, 4000, 9999, 5555, 8453];
const AGENT_MODULE_PATTERNS: &[&str] = &[
    "libjdwp",
    "libinstrument",
    "libasyncprofiler",
    "libjprofilerti",
    "libyjpagent",
    "libhprof",
    "jdwp.dll",
    "instrument.dll",
    "asyncprofiler",
    "jprofiler",
    "yourkit",
    "arthas",
    "byte-buddy-agent",
];
const SUSPICIOUS_MODULE_PATTERNS: &[&str] = &[
    "frida",
    "dynamorio",
    "inject",
    "hook",
    "payload",
    "profiler",
];
const SUSPICIOUS_ENV_VARS: &[&str] = &["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];
const SUSPICIOUS_ENV_PATTERNS: &[&str] =
    &["-agentlib", "-agentpath", "-javaagent", "-xrunjdwp", "jdwp"];

pub struct AntiAttachGuard {
    _private: (),
}

impl AntiAttachGuard {
    pub fn start() -> Result<Self, String> {
        crate::security::spawn_monitor("sky-attach-monitor", monitor_loop)?;
        Ok(Self { _private: () })
    }
}

fn monitor_loop(stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        if detect_new_agent_module() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::JavaAgent,
                crate::security::EvidenceConfidence::High,
                "attach.module",
                "a known JVM agent module appeared after the trusted baseline",
            ));
            break;
        }

        if detect_suspicious_new_module() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::AttachAttempt,
                crate::security::EvidenceConfidence::Medium,
                "attach.module",
                "a suspicious native module appeared after the trusted baseline",
            ));
        }

        if detect_attach_artifacts() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::AttachAttempt,
                crate::security::EvidenceConfidence::Medium,
                "attach.artifact",
                "a JVM attach handshake artifact was observed",
            ));
        }

        if detect_process_owned_jdwp_listener() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::Debugger,
                crate::security::EvidenceConfidence::Medium,
                "attach.jdwp_port",
                "the current process owns a listener on a common JDWP port",
            ));
        }

        if crate::security::wait_for_stop(&stop, crate::security::policy().attach_scan_interval) {
            break;
        }
    }
}

pub fn check_suspicious_env_vars() -> bool {
    SUSPICIOUS_ENV_VARS.iter().any(|name| {
        std::env::var(name)
            .ok()
            .map(|value| {
                let lower = value.to_ascii_lowercase();
                SUSPICIOUS_ENV_PATTERNS
                    .iter()
                    .any(|pattern| lower.contains(pattern))
            })
            .unwrap_or(false)
    })
}

pub fn check_cmdline_for_agents() -> bool {
    current_command_line()
        .map(|command_line| {
            let lower = command_line.to_ascii_lowercase();
            SUSPICIOUS_ENV_PATTERNS
                .iter()
                .any(|pattern| lower.contains(pattern))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn current_command_line() -> Option<String> {
    std::fs::read("/proc/self/cmdline")
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
}

#[cfg(target_os = "windows")]
fn current_command_line() -> Option<String> {
    unsafe {
        let ptr = winapi::um::processenv::GetCommandLineW();
        if ptr.is_null() {
            return None;
        }
        let len = (0..).take_while(|index| *ptr.add(*index) != 0).count();
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            ptr, len,
        )))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn current_command_line() -> Option<String> {
    None
}

/// Best-effort self-attach properties. These are not a substitute for
/// `-XX:+DisableAttachMechanism` and `-XX:-EnableDynamicAgentLoading`.
pub fn disable_attach_via_jni(env: &jni::JNIEnv) {
    let mut env = unsafe { env.unsafe_clone() };
    for (key, value) in [
        ("jdk.attach.allowAttachSelf", "false"),
        ("jdk.attach.disabled", "true"),
    ] {
        let result = (|| {
            let key = env.new_string(key).ok()?;
            let value = env.new_string(value).ok()?;
            env.call_static_method(
                "java/lang/System",
                "setProperty",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                &[
                    jni::objects::JValue::from(&key),
                    jni::objects::JValue::from(&value),
                ],
            )
            .ok()?;
            Some(())
        })();
        if result.is_none() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::RuntimeFailure,
                crate::security::EvidenceConfidence::Low,
                "attach.jvm_property",
                format!("failed to set best-effort JVM property {key}"),
            ));
            let _ = env.exception_clear();
        }
    }
}

pub fn capture_module_baseline() -> Result<(), String> {
    let current = enumerate_loaded_modules();
    if current.is_empty() {
        return Err("loaded-module enumeration returned an empty baseline".to_string());
    }
    match MODULE_BASELINE.get() {
        Some(baseline) => {
            let mut baseline = baseline
                .lock()
                .map_err(|_| "module-baseline lock is poisoned".to_string())?;
            *baseline = current;
        }
        None => {
            MODULE_BASELINE
                .set(Mutex::new(current))
                .map_err(|_| "module baseline was initialized concurrently".to_string())?;
        }
    }
    Ok(())
}

fn new_modules() -> Vec<String> {
    let current = enumerate_loaded_modules();
    let Some(baseline) = MODULE_BASELINE.get() else {
        return Vec::new();
    };
    let Ok(baseline) = baseline.lock() else {
        return Vec::new();
    };
    current.difference(&baseline).cloned().collect::<Vec<_>>()
}

fn detect_new_agent_module() -> bool {
    new_modules().iter().any(|module| {
        let lower = module.to_ascii_lowercase();
        AGENT_MODULE_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
    })
}

fn detect_suspicious_new_module() -> bool {
    new_modules().iter().any(|module| {
        let lower = module.to_ascii_lowercase();
        SUSPICIOUS_MODULE_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
    })
}

#[cfg(target_os = "linux")]
fn enumerate_loaded_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return modules;
    };

    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let permissions = fields[1];
        let path = fields[5..].join(" ");
        if permissions.contains('x') && path.starts_with('/') {
            modules.insert(path);
        }
    }
    modules
}

#[cfg(target_os = "windows")]
fn enumerate_loaded_modules() -> HashSet<String> {
    use winapi::shared::minwindef::HMODULE;
    use winapi::um::libloaderapi::GetModuleFileNameW;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::psapi::EnumProcessModules;

    let mut modules = HashSet::new();
    unsafe {
        let mut handles: [HMODULE; 2048] = std::mem::zeroed();
        let mut bytes_needed = 0;
        if EnumProcessModules(
            GetCurrentProcess(),
            handles.as_mut_ptr(),
            std::mem::size_of_val(&handles) as u32,
            &mut bytes_needed,
        ) == 0
        {
            return modules;
        }

        let count = ((bytes_needed as usize) / std::mem::size_of::<HMODULE>()).min(handles.len());
        for handle in handles.iter().take(count) {
            let mut name = [0u16; 1024];
            let len = GetModuleFileNameW(*handle, name.as_mut_ptr(), name.len() as u32);
            if len > 0 {
                modules.insert(String::from_utf16_lossy(&name[..len as usize]));
            }
        }
    }
    modules
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn enumerate_loaded_modules() -> HashSet<String> {
    HashSet::new()
}

#[cfg(target_os = "linux")]
fn detect_attach_artifacts() -> bool {
    let pid = unsafe { libc::getpid() };
    [
        format!("/tmp/.attach_pid{pid}"),
        format!("/proc/{pid}/cwd/.attach_pid{pid}"),
    ]
    .iter()
    .any(|path| std::path::Path::new(path).exists())
}

#[cfg(target_os = "windows")]
fn detect_attach_artifacts() -> bool {
    use std::ffi::CString;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::winbase::OpenFileMappingA;

    const FILE_MAP_READ: u32 = 0x0004;
    unsafe {
        let Ok(name) = CString::new(format!("JSharedMem_{}", GetCurrentProcessId())) else {
            return false;
        };
        let handle = OpenFileMappingA(FILE_MAP_READ, 0, name.as_ptr());
        if handle.is_null() {
            false
        } else {
            CloseHandle(handle);
            true
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn detect_attach_artifacts() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn detect_process_owned_jdwp_listener() -> bool {
    process_owned_listening_ports()
        .iter()
        .any(|port| JDWP_PORTS.contains(port))
}

#[cfg(not(target_os = "windows"))]
fn detect_process_owned_jdwp_listener() -> bool {
    // `/proc/self/net/tcp` is network-namespace scoped, not process scoped.
    false
}

#[cfg(target_os = "windows")]
fn process_owned_listening_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    unsafe {
        let pid = winapi::um::processthreadsapi::GetCurrentProcessId();
        let mut size = 0u32;
        let first = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, 2, 3, 0);
        if first != 122 || size < 4 {
            return ports;
        }

        let mut buffer = vec![0u8; size as usize];
        if GetExtendedTcpTable(buffer.as_mut_ptr().cast(), &mut size, 0, 2, 3, 0) != 0 {
            return ports;
        }

        let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        const ENTRY_SIZE: usize = 24;
        for index in 0..count {
            let offset = 4 + index * ENTRY_SIZE;
            let Some(entry) = buffer.get(offset..offset + ENTRY_SIZE) else {
                break;
            };
            let owner = u32::from_ne_bytes([entry[20], entry[21], entry[22], entry[23]]);
            if owner == pid {
                ports.push(u16::from_be_bytes([entry[8], entry[9]]));
            }
        }
    }
    ports
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut std::ffi::c_void,
        size: *mut u32,
        order: i32,
        address_family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_environment_patterns_are_specific() {
        assert!(SUSPICIOUS_ENV_PATTERNS.contains(&"-javaagent"));
        assert!(!SUSPICIOUS_ENV_PATTERNS.contains(&"java"));
    }

    #[test]
    fn module_patterns_do_not_use_broad_runtime_words() {
        assert!(!SUSPICIOUS_MODULE_PATTERNS.contains(&"java"));
        assert!(!SUSPICIOUS_MODULE_PATTERNS.contains(&"net"));
    }
}
