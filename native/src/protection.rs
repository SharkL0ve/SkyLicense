//! Cross-platform protection orchestration.
//!
//! Definitive signals fail closed by transitioning the central security state.
//! Process names and other weak heuristics are recorded only; they never kill
//! the shared host JVM.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use sysinfo::{ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::mem::size_of;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::HMODULE;
#[cfg(target_os = "windows")]
use winapi::um::debugapi::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::GetCurrentProcess;

pub struct ProtectionManager {
    is_activated: bool,
}

impl ProtectionManager {
    pub fn new() -> Self {
        Self {
            is_activated: false,
        }
    }

    pub fn enable_protection(&mut self) -> Result<(), String> {
        if self.is_activated {
            return Err("E001".to_string());
        }

        if detect_analysis_tool_names() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::Debugger,
                crate::security::EvidenceConfidence::Low,
                "environment.process_name",
                "an analysis-tool process-name heuristic matched",
            ));
        }

        validate_attach_environment()?;
        if let Err(error) = check_debugger() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::Debugger,
                crate::security::EvidenceConfidence::Certain,
                "protection.debugger",
                error.clone(),
            ));
            if crate::security::state().is_terminal() {
                return Err(error);
            }
        }
        if let Err(error) = check_hooks() {
            crate::security::submit(crate::security::SecurityEvidence::new(
                crate::security::EvidenceKind::CodeIntegrity,
                crate::security::EvidenceConfidence::High,
                "protection.hook_heuristic",
                error,
            ));
        }
        start_integrity_monitor()?;
        start_environment_monitor()?;

        self.is_activated = true;
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if !self.is_activated {
            return;
        }
        self.is_activated = false;
        crate::security::shutdown();
        crate::security::join_monitors();
    }
}

impl Default for ProtectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProtectionManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn validate_attach_environment() -> Result<(), String> {
    if crate::anti_attach::check_suspicious_env_vars() {
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::JavaAgent,
            crate::security::EvidenceConfidence::High,
            "attach.environment",
            "a JVM agent/debug option was found in a launch environment variable",
        ));
    }
    if crate::anti_attach::check_cmdline_for_agents() {
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::JavaAgent,
            crate::security::EvidenceConfidence::High,
            "attach.command_line",
            "a JVM agent/debug option was found in the process command line",
        ));
    }
    if crate::security::state().is_terminal() {
        return Err("E020".to_string());
    }
    Ok(())
}

/// Perform bounded checks as soon as the JVM loads the native library. This
/// intentionally starts no threads and performs no network or class-loading
/// work; the full protection transaction still begins after authentication.
pub fn run_early_load_checks() -> Result<(), crate::security::SecurityEvidence> {
    if !crate::integrity::runtime_anchors_match() {
        return Err(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::CodeIntegrity,
            crate::security::EvidenceConfidence::Certain,
            "jni.onload.integrity",
            "a native runtime code anchor changed during early initialization",
        ));
    }
    if crate::anti_attach::check_suspicious_env_vars()
        || crate::anti_attach::check_cmdline_for_agents()
    {
        return Err(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::JavaAgent,
            crate::security::EvidenceConfidence::High,
            "jni.onload.agent_arguments",
            "the JVM launch environment contains an explicit agent/debug option",
        ));
    }
    check_debugger().map_err(|error| {
        crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::Debugger,
            crate::security::EvidenceConfidence::Certain,
            "jni.onload.debugger",
            format!("an operating-system debugger indicator matched: {error}"),
        )
    })?;
    Ok(())
}

/// Establish controls that must precede authentication and resource loading.
pub fn prepare_early_environment() -> Result<(), String> {
    crate::anti_attach::capture_module_baseline()?;
    if crate::security::policy().profile != crate::security::SecurityProfile::Compatible {
        crate::mem_protect::disable_process_dump()?;
    }
    Ok(())
}

fn detect_analysis_tool_names() -> bool {
    const WINDOWS_TOOLS: &[&str] = &[
        "ollydbg",
        "x64dbg",
        "windbg",
        "cheatengine",
        "frida",
        "binaryninja",
        "ghidra",
        "jvisualvm",
        "visualvm",
        "jconsole",
        "drrun",
        "dynamorio",
        "arthas",
    ];
    const UNIX_TOOLS: &[&str] = &[
        "gdb",
        "lldb",
        "strace",
        "ltrace",
        "radare2",
        "frida",
        "binaryninja",
        "ghidra",
        "jvisualvm",
        "drrun",
        "dynamorio",
        "arthas",
    ];

    let patterns = if cfg!(target_os = "windows") {
        WINDOWS_TOOLS
    } else {
        UNIX_TOOLS
    };
    let mut system =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    system.refresh_processes();
    system.processes().values().any(|process| {
        let name = process.name().to_ascii_lowercase();
        patterns.iter().any(|pattern| name.contains(pattern))
    })
}

#[cfg(target_os = "windows")]
fn check_debugger() -> Result<(), String> {
    unsafe {
        if IsDebuggerPresent() != 0 {
            return Err("E003".to_string());
        }

        let process = GetCurrentProcess();
        let mut remote_present = 0;
        if CheckRemoteDebuggerPresent(process, &mut remote_present) != 0 && remote_present != 0 {
            return Err("E004".to_string());
        }

        let mut return_length = 0u32;
        let mut debug_port = 0usize;
        let status = ntapi::ntpsapi::NtQueryInformationProcess(
            process,
            7,
            (&mut debug_port as *mut usize).cast(),
            size_of::<usize>() as u32,
            &mut return_length,
        );
        if status == 0 && debug_port != 0 {
            return Err("E006".to_string());
        }

        let mut debug_object = 0usize;
        let status = ntapi::ntpsapi::NtQueryInformationProcess(
            process,
            0x1E,
            (&mut debug_object as *mut usize).cast(),
            size_of::<usize>() as u32,
            &mut return_length,
        );
        if status == 0 && debug_object != 0 {
            return Err("E007".to_string());
        }

        let mut debug_flags = 1u32;
        let status = ntapi::ntpsapi::NtQueryInformationProcess(
            process,
            0x1F,
            (&mut debug_flags as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut return_length,
        );
        if status == 0 && debug_flags == 0 {
            return Err("E023".to_string());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_debugger() -> Result<(), String> {
    if linux_tracer_pid().unwrap_or_default() != 0 {
        Err("E005".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn check_debugger() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_tracer_pid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("TracerPid:")
            .and_then(|value| value.trim().parse().ok())
    })
}

#[cfg(target_os = "windows")]
fn check_hooks() -> Result<(), String> {
    for (module, function) in [
        ("ntdll.dll", "NtOpenProcess"),
        ("ntdll.dll", "ZwOpenProcess"),
        ("user32.dll", "SetWindowsHookExA"),
    ] {
        let module_name = CString::new(module).map_err(|_| "invalid module name".to_string())?;
        let function_name =
            CString::new(function).map_err(|_| "invalid function name".to_string())?;
        unsafe {
            let module_handle = GetModuleHandleA(module_name.as_ptr());
            if module_handle.is_null() {
                continue;
            }
            let address = GetProcAddress(module_handle, function_name.as_ptr());
            if address.is_null() {
                continue;
            }
            let prefix = std::slice::from_raw_parts(address as *const u8, 16);
            if begins_with_unconditional_transfer(prefix) {
                return Err(format!("inline hook heuristic matched {module}!{function}"));
            }
            if module_for_address(address as usize) != Some(module_handle) {
                return Err(format!("export address escaped module {module}!{function}"));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn begins_with_unconditional_transfer(prefix: &[u8]) -> bool {
    prefix.starts_with(&[0xE9])
        || prefix.starts_with(&[0xEB])
        || prefix.starts_with(&[0xFF, 0x25])
        || (prefix.len() >= 12
            && prefix.starts_with(&[0x48, 0xB8])
            && prefix[10..12] == [0xFF, 0xE0])
}

#[cfg(target_os = "windows")]
unsafe fn module_for_address(address: usize) -> Option<HMODULE> {
    use winapi::um::psapi::{EnumProcessModules, GetModuleInformation, MODULEINFO};

    let process = unsafe { GetCurrentProcess() };
    let mut modules: [HMODULE; 2048] = unsafe { std::mem::zeroed() };
    let mut bytes_needed = 0u32;
    if unsafe {
        EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut bytes_needed,
        )
    } == 0
    {
        return None;
    }

    let count = ((bytes_needed as usize) / size_of::<HMODULE>()).min(modules.len());
    for module in modules.into_iter().take(count) {
        let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
        if unsafe {
            GetModuleInformation(process, module, &mut info, size_of::<MODULEINFO>() as u32)
        } == 0
        {
            continue;
        }
        let start = info.lpBaseOfDll as usize;
        let end = start.saturating_add(info.SizeOfImage as usize);
        if (start..end).contains(&address) {
            return Some(module);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn check_hooks() -> Result<(), String> {
    if std::env::var_os("LD_PRELOAD").is_some_and(|value| !value.is_empty()) {
        return Err("LD_PRELOAD is set".to_string());
    }

    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    for pattern in [
        "libfrida-agent",
        "libdynamorio",
        "libasyncprofiler",
        "libyjpagent",
        "libjprofilerti",
    ] {
        if maps.to_ascii_lowercase().contains(pattern) {
            return Err(format!("suspicious executable mapping: {pattern}"));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn check_hooks() -> Result<(), String> {
    Ok(())
}

fn start_integrity_monitor() -> Result<(), String> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *key);
    if !crate::integrity::runtime_anchors_match() {
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::CodeIntegrity,
            crate::security::EvidenceConfidence::Certain,
            "integrity.anchor_initialization",
            "a trusted runtime code anchor changed during initialization",
        ));
        return Err("trusted runtime code anchors changed during initialization".to_string());
    }
    let Some(baseline) = compute_integrity_hmac(&key) else {
        return Err("unable to safely read executable integrity regions".to_string());
    };

    crate::security::spawn_monitor("sky-integrity-monitor", move |stop| {
        while !stop.load(Ordering::Acquire) {
            if crate::security::wait_for_stop(&stop, Duration::from_secs(30)) {
                return;
            }
            if !crate::integrity::runtime_anchors_match()
                || compute_integrity_hmac(&key) != Some(baseline)
            {
                crate::security::submit(crate::security::SecurityEvidence::new(
                    crate::security::EvidenceKind::CodeIntegrity,
                    crate::security::EvidenceConfidence::Certain,
                    "integrity.runtime",
                    "protected runtime code changed after initialization",
                ));
                return;
            }
        }
    })
}

fn start_environment_monitor() -> Result<(), String> {
    crate::security::spawn_monitor("sky-environment-monitor", |stop| {
        while !stop.load(Ordering::Acquire) {
            if detect_analysis_tool_names() {
                crate::security::submit(crate::security::SecurityEvidence::new(
                    crate::security::EvidenceKind::Debugger,
                    crate::security::EvidenceConfidence::Low,
                    "environment.periodic_process_name",
                    "an analysis-tool process-name heuristic matched",
                ));
            }
            if crate::security::wait_for_stop(
                &stop,
                crate::security::policy().environment_scan_interval,
            ) {
                break;
            }
        }
    })
}

#[inline(never)]
fn compute_integrity_hmac(key: &[u8; 32]) -> Option<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return None;
    };
    let anchors = [
        enable_global_protection as *const () as *const u8,
        compute_integrity_hmac as *const () as *const u8,
        ProtectionManager::enable_protection as *const () as *const u8,
    ];
    for anchor in anchors {
        let bytes = crate::integrity::bounded_executable_code_region(anchor, 512)?;
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(bytes);
    }
    Some(mac.finalize().into_bytes().into())
}

static GLOBAL_PROTECTION: OnceLock<Mutex<ProtectionManager>> = OnceLock::new();

fn global_protection() -> &'static Mutex<ProtectionManager> {
    GLOBAL_PROTECTION.get_or_init(|| Mutex::new(ProtectionManager::new()))
}

pub fn enable_global_protection() -> Result<(), String> {
    global_protection()
        .lock()
        .map_err(|_| "global protection lock is poisoned".to_string())?
        .enable_protection()
}

pub fn activate_all_protections(env: &jni::JNIEnv) -> Result<(), String> {
    let initialization = crate::security::InitializationGuard::begin()?;
    let result = (|| {
        crate::agent_detect::initial_agent_check(env)?;
        enable_global_protection()?;
        crate::anti_dump::start_memory_monitor()?;
        crate::anti_attach::disable_attach_via_jni(env);
        let _attach_guard = crate::anti_attach::AntiAttachGuard::start()?;
        let vm = env
            .get_java_vm()
            .map_err(|error| format!("failed to acquire JavaVM: {error}"))?;
        crate::agent_detect::start_agent_monitor(vm)?;
        initialization.commit()
    })();

    if result.is_err()
        && let Ok(mut manager) = global_protection().lock()
    {
        manager.is_activated = false;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn detects_common_absolute_jump_prefixes() {
        assert!(begins_with_unconditional_transfer(&[0xE9, 0, 0, 0, 0]));
        assert!(begins_with_unconditional_transfer(&[
            0xFF, 0x25, 0, 0, 0, 0
        ]));
        assert!(!begins_with_unconditional_transfer(&[
            0x4C, 0x8B, 0xD1, 0xB8
        ]));
    }

    #[test]
    fn protection_manager_defaults_to_inactive() {
        let manager = ProtectionManager::new();
        assert!(!manager.is_activated);
    }
}
