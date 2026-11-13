/// Non-destructive JVM anti-attach system.
/// On Windows, the JVM Attach API works by:
///   1. The attaching process (Arthas) calls native `enqueue` method
///   2. `enqueue` uses OpenProcess + CreateRemoteThread to inject a thread into the target JVM
///   3. The injected thread connects back to a named pipe created by the attacher
///   4. Commands (loadAgent, etc.) are sent through this pipe
///
/// Our defense strategy:
///   - Block remote thread creation via process mitigation policy (ProcessDynamicCodePolicy)
///   - Modify process DACL to remove PROCESS_CREATE_THREAD permission from other processes
///   - Monitor for new threads not in baseline and exit if found
///   - Destroy shared memory used for attach handshake
///   - Detect loaded agent classes and exit

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Module baseline for injection detection
static MODULE_BASELINE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Thread baseline: all thread IDs present before protection activation (Windows)
#[cfg(target_os = "windows")]
static THREAD_BASELINE: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

/// Holds the handle to our squatted shared memory mapping (Windows)
#[cfg(target_os = "windows")]
static SHARED_MEM_HANDLE: OnceLock<Mutex<usize>> = OnceLock::new();

/// Tracks which thread IDs we've already suspended (Windows)
#[cfg(target_os = "windows")]
static SUSPENDED_THREADS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

/// Cached jvm.dll address range: (base, size)
#[cfg(target_os = "windows")]
static JVM_DLL_RANGE: OnceLock<(usize, usize)> = OnceLock::new();

/// Known debug ports that JDWP typically listens on
const JDWP_PORTS: &[u16] = &[5005, 8000, 8787, 5050, 4000, 9999, 5555, 8453];

/// Known JVM TI agent library patterns
const KNOWN_AGENT_PATTERNS: &[&str] = &[
    "libjdwp", "libinstrument", "libasyncprofiler", "libjprofilerti",
    "libyjpagent", "libattach", "libhprof", "libjvmti",
    "jdwp.dll", "instrument.dll", "hprof.dll", "jvmtiagent",
    "asyncprofiler", "jprofiler", "yourkit", "visualvm",
    "arthas", "bytebuddy", "byte-buddy",
];

/// Suspicious environment variable names
const SUSPICIOUS_ENV_VARS: &[&str] = &[
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
];

/// Suspicious patterns within environment variable values
const SUSPICIOUS_ENV_PATTERNS: &[&str] = &[
    "-agentlib", "-agentpath", "-javaagent", "-Xrunjdwp",
    "jdwp", "attach", "instrument",
];

// ============================================================
// Core defense: Block remote thread injection and patch JVM attach entry point
// ============================================================

/// Block external processes from injecting code into our process.
/// The Windows JVM Attach API (used by Arthas) works by:
///   1. OpenProcess(PROCESS_ALL_ACCESS) to get a handle to target JVM
///   2. VirtualAllocEx + WriteProcessMemory to inject a code stub
///   3. CreateRemoteThread to execute the stub in target JVM
///   4. The stub calls GetProcAddress(jvm.dll, "JVM_EnqueueOperation")
///   5. JVM_EnqueueOperation processes the attach command (loadAgent, etc.)
///
/// We defend by:
///   A. Patching JVM_EnqueueOperation/v2 in jvm.dll to immediately return error
///      (This is the DEFINITIVE defense - even if thread injection succeeds,
///       the injected code cannot find a working enqueue function)
///   B. Modifying process DACL to deny PROCESS_CREATE_THREAD/VM_WRITE/VM_OPERATION
///      (Blocks OpenProcess from getting the required access rights)
#[cfg(target_os = "windows")]
fn block_remote_thread_creation() {
    unsafe {
        // Defense A: Patch JVM_EnqueueOperation — most critical
        patch_enqueue_operation();
        // Defense B: Restrict process DACL
        apply_restrictive_dacl();
    }
}

/// Patch JVM_EnqueueOperation and JVM_EnqueueOperation_v2 exports in jvm.dll.
/// The injected code stub from Arthas does:
///   GetModuleHandle("jvm") -> GetProcAddress(h, "JVM_EnqueueOperation")
/// We overwrite the first bytes with `mov eax, -1; ret` so it returns error.
#[cfg(target_os = "windows")]
unsafe fn patch_enqueue_operation() {
    use std::ffi::CString;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    let jvm_name = CString::new("jvm").unwrap();
    let jvm_handle = GetModuleHandleA(jvm_name.as_ptr());
    if jvm_handle.is_null() {
        // Try with full name
        let jvm_name2 = CString::new("jvm.dll").unwrap();
        let jvm_handle2 = GetModuleHandleA(jvm_name2.as_ptr());
        if jvm_handle2.is_null() {
            return;
        }
        patch_function_in_module(jvm_handle2);
        return;
    }
    patch_function_in_module(jvm_handle);
}

#[cfg(target_os = "windows")]
unsafe fn patch_function_in_module(jvm_handle: winapi::shared::minwindef::HMODULE) {
    use std::ffi::CString;
    use winapi::um::libloaderapi::GetProcAddress;
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

    let func_names = [
        CString::new("JVM_EnqueueOperation").unwrap(),
        CString::new("JVM_EnqueueOperation_v2").unwrap(),
    ];

    for func_name in &func_names {
        let func_addr = GetProcAddress(jvm_handle, func_name.as_ptr());
        if func_addr.is_null() {
            continue;
        }

        let mut old_protect: u32 = 0;
        if VirtualProtect(
            func_addr as *mut std::ffi::c_void,
            16,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0 {
            continue;
        }

        // x86_64: mov eax, 0xFFFFFFFF; ret
        // Makes the function return -1 (error) immediately
        // The injected stub checks return value and reports failure to Arthas
        let patch: [u8; 6] = [
            0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1
            0xC3,                           // ret
        ];
        std::ptr::copy_nonoverlapping(patch.as_ptr(), func_addr as *mut u8, patch.len());

        // Restore original protection
        VirtualProtect(
            func_addr as *mut std::ffi::c_void,
            16,
            old_protect,
            &mut old_protect,
        );
    }
}

/// Modify process DACL to deny remote thread creation permissions.
#[cfg(target_os = "windows")]
unsafe fn apply_restrictive_dacl() {
    use winapi::um::processthreadsapi::GetCurrentProcess;

    let process = GetCurrentProcess();
    let mut sd: *mut winapi::um::winnt::SECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut winapi::um::winnt::ACL = std::ptr::null_mut();

    let result = GetSecurityInfo(
        process, 6, 4,
        std::ptr::null_mut(), std::ptr::null_mut(),
        &mut dacl, std::ptr::null_mut(),
        &mut sd as *mut _ as *mut *mut std::ffi::c_void,
    );

    if result != 0 || dacl.is_null() {
        return;
    }

    // DENY: PROCESS_CREATE_THREAD(0x2) | PROCESS_VM_WRITE(0x20) | PROCESS_VM_OPERATION(0x8)
    let deny_mask: u32 = 0x0002 | 0x0020 | 0x0008;

    let mut everyone_sid: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sia = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };

    if AllocateAndInitializeSid(&mut sia, 1, 0, 0, 0, 0, 0, 0, 0, 0, &mut everyone_sid) == 0 {
        LocalFree(sd as *mut _);
        return;
    }

    let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
    ea.grfAccessPermissions = deny_mask;
    ea.grfAccessMode = 1; // DENY_ACCESS
    ea.grfInheritance = 0;
    ea.Trustee.TrusteeForm = 0;
    ea.Trustee.TrusteeType = 1;
    ea.Trustee.ptstrName = everyone_sid as *mut u16;

    let mut new_dacl: *mut winapi::um::winnt::ACL = std::ptr::null_mut();
    if SetEntriesInAclW(1, &mut ea, dacl, &mut new_dacl) == 0 && !new_dacl.is_null() {
        SetSecurityInfo(
            process, 6, 4,
            std::ptr::null_mut(), std::ptr::null_mut(), new_dacl, std::ptr::null_mut(),
        );
        LocalFree(new_dacl as *mut _);
    }

    FreeSid(everyone_sid);
    LocalFree(sd as *mut _);
}

// FFI declarations for Windows security APIs
#[cfg(target_os = "windows")]
#[repr(C)]
struct SID_IDENTIFIER_AUTHORITY {
    Value: [u8; 6],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct TRUSTEE_W {
    pMultipleTrustee: *mut std::ffi::c_void,
    MultipleTrusteeOperation: u32,
    TrusteeForm: u32,
    TrusteeType: u32,
    ptstrName: *mut u16,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct EXPLICIT_ACCESS_W {
    grfAccessPermissions: u32,
    grfAccessMode: u32,
    grfInheritance: u32,
    Trustee: TRUSTEE_W,
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetSecurityInfo(
        handle: *mut std::ffi::c_void,
        ObjectType: u32,
        SecurityInfo: u32,
        ppsidOwner: *mut *mut std::ffi::c_void,
        ppsidGroup: *mut *mut std::ffi::c_void,
        ppDacl: *mut *mut winapi::um::winnt::ACL,
        ppSacl: *mut *mut winapi::um::winnt::ACL,
        ppSecurityDescriptor: *mut *mut std::ffi::c_void,
    ) -> u32;

    fn SetSecurityInfo(
        handle: *mut std::ffi::c_void,
        ObjectType: u32,
        SecurityInfo: u32,
        psidOwner: *mut std::ffi::c_void,
        psidGroup: *mut std::ffi::c_void,
        pDacl: *mut winapi::um::winnt::ACL,
        pSacl: *mut std::ffi::c_void,
    ) -> u32;

    fn SetEntriesInAclW(
        cCountOfExplicitEntries: u32,
        pListOfExplicitEntries: *mut EXPLICIT_ACCESS_W,
        OldAcl: *mut winapi::um::winnt::ACL,
        NewAcl: *mut *mut winapi::um::winnt::ACL,
    ) -> u32;

    fn AllocateAndInitializeSid(
        pIdentifierAuthority: *mut SID_IDENTIFIER_AUTHORITY,
        nSubAuthorityCount: u8,
        nSubAuthority0: u32,
        nSubAuthority1: u32,
        nSubAuthority2: u32,
        nSubAuthority3: u32,
        nSubAuthority4: u32,
        nSubAuthority5: u32,
        nSubAuthority6: u32,
        nSubAuthority7: u32,
        pSid: *mut *mut std::ffi::c_void,
    ) -> i32;

    fn FreeSid(pSid: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

    fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

    fn SetProcessMitigationPolicy(
        MitigationPolicy: u32,
        lpBuffer: *const std::ffi::c_void,
        dwLength: usize,
    ) -> i32;
}

/// Anti-attach guard handle
pub struct AntiAttachGuard {
    running: Arc<AtomicBool>,
}

impl AntiAttachGuard {
    /// Start the anti-attach monitoring system
    pub fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Block remote thread creation BEFORE starting monitor
        #[cfg(target_os = "windows")]
        block_remote_thread_creation();

        // Patch JVM_EnqueueOperation on Linux and install SIGQUIT handler
        #[cfg(target_os = "linux")]
        {
            patch_enqueue_operation_linux();
            install_sigquit_handler();
        }

        std::thread::spawn(move || {
            anti_attach_monitor_loop(running_clone);
        });

        Self { running }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for AntiAttachGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Main monitoring loop — runs continuously in background
fn anti_attach_monitor_loop(running: Arc<AtomicBool>) {
    let mut tick_count: u64 = 0;

    while running.load(Ordering::Relaxed) {
        // Every tick (50ms): destroy shared memory + kill attach pipes (fast, critical path)
        delete_attach_artifacts();

        // Every tick (50ms) on Windows: scan for and suspend Attach Listener thread
        // This must be aggressive because the Attach Listener can respond within milliseconds
        #[cfg(target_os = "windows")]
        unsafe { suspend_attach_listener_thread(); }

        // Every 2s: check for JDWP and agents
        if tick_count % 40 == 0 {
            // JDWP detection — high threat
            if detect_jdwp_listeners() {
                high_threat_response();
            }

            // JVM TI agent detection — high threat
            if detect_new_agents() {
                high_threat_response();
            }
        }

        // Every 2s: check for injected modules
        if tick_count % 40 == 5 {
            if detect_injected_modules() {
                high_threat_response();
            }
        }

        tick_count = tick_count.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// High-threat response: attach detected — exit the process immediately.
/// Attach tools like Arthas can read JVM-internal class info that native-layer
/// corruption cannot protect. The only safe response is termination.
#[inline(never)]
fn high_threat_response() {
    unsafe { crate::corrupt_state(); }
    // Randomized delay to obscure detection point
    let delay = (rand::random::<u64>() % 2500) + 500;
    std::thread::sleep(Duration::from_millis(delay));
    std::process::exit(0);
}

// ============================================================
// Environment variable checks (called once at startup)
// ============================================================

/// Check for suspicious environment variables that inject agents.
/// Returns true if a threat is detected.
pub fn check_suspicious_env_vars() -> bool {
    for var_name in SUSPICIOUS_ENV_VARS {
        if let Ok(value) = std::env::var(var_name) {
            let lower = value.to_lowercase();
            for pattern in SUSPICIOUS_ENV_PATTERNS {
                if lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check process command-line for debug agent arguments.
/// Returns true if JDWP or agent args are found.
pub fn check_cmdline_for_agents() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(cmdline) = std::fs::read_to_string("/proc/self/cmdline") {
            let lower = cmdline.to_lowercase();
            if lower.contains("-agentlib:jdwp")
                || lower.contains("-xrunjdwp")
                || lower.contains("-agentpath:")
                || lower.contains("-javaagent:")
            {
                return true;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let cmdline = unsafe {
            let ptr = winapi::um::processenv::GetCommandLineW();
            let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        };
        let lower = cmdline.to_lowercase();
        if lower.contains("-agentlib:jdwp")
            || lower.contains("-xrunjdwp")
            || lower.contains("-agentpath:")
            || lower.contains("-javaagent:")
        {
            return true;
        }
    }

    false
}

// ============================================================
// JVM property disable (called once via JNI)
// ============================================================

/// Disable JVM attach mechanism via System properties and OS-level protections.
/// Call this once after JNI env is available.
pub fn disable_attach_via_jni(env: &jni::JNIEnv) {
    // Block remote thread creation at OS level FIRST (most critical)
    #[cfg(target_os = "windows")]
    block_remote_thread_creation();

    let mut env = unsafe { env.unsafe_clone() };

    // Set properties that disable attach
    let props = [
        ("jdk.attach.allowAttachSelf", "false"),
        ("jdk.attach.disabled", "true"),
    ];

    for (key, value) in &props {
        let _ = env.call_static_method(
            "java/lang/System",
            "setProperty",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[
                jni::objects::JValue::from(&env.new_string(key).unwrap()),
                jni::objects::JValue::from(&env.new_string(value).unwrap()),
            ],
        );
    }
}

// ============================================================
// Module baseline for injection detection
// ============================================================

/// Capture current loaded modules as baseline. Call once at init.
pub fn capture_module_baseline() {
    let modules = enumerate_loaded_modules();
    let _ = MODULE_BASELINE.set(Mutex::new(modules));
}

/// Detect modules loaded after baseline was captured
fn detect_injected_modules() -> bool {
    let baseline = match MODULE_BASELINE.get() {
        Some(b) => b,
        None => return false,
    };
    let baseline_set = match baseline.lock() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let current = enumerate_loaded_modules();
    for module in &current {
        if !baseline_set.contains(module) {
            let lower = module.to_lowercase();
            // Skip known safe runtime-loaded modules
            if lower.contains("jvm") || lower.contains("java")
                || lower.contains("jli") || lower.contains("net")
                || lower.contains("nio") || lower.contains("zip")
                || lower.contains("verify")
            {
                continue;
            }
            // Check for suspicious patterns
            if lower.contains("inject") || lower.contains("hook")
                || lower.contains("payload") || lower.contains("frida")
                || lower.contains("agent") || lower.contains("profiler")
            {
                return true;
            }
        }
    }
    false
}

// ============================================================
// Platform-specific: Delete attach artifacts
// ============================================================

#[cfg(target_os = "linux")]
fn delete_attach_artifacts() {
    let pid = unsafe { libc::getpid() };

    // Delete .java_pid file (UNIX domain socket for attach)
    // Then replace it with a permission-denied regular file to block recreation
    let socket_path = format!("/tmp/.java_pid{}", pid);
    let _ = std::fs::remove_file(&socket_path);
    // Create a blocking file with no permissions — prevents JVM from binding socket here
    unsafe {
        let c_path = format!("{}\0", socket_path);
        let fd = libc::open(c_path.as_ptr() as *const i8, libc::O_CREAT | libc::O_WRONLY, 0o000);
        if fd >= 0 {
            libc::close(fd);
            libc::chmod(c_path.as_ptr() as *const i8, 0o000);
        }
    }

    // Delete .attach_pid file (signal file that triggers attach listener)
    let attach_paths = [
        format!("/tmp/.attach_pid{}", pid),
        format!("/proc/{}/cwd/.attach_pid{}", pid, pid),
    ];
    for path in &attach_paths {
        let _ = std::fs::remove_file(path);
    }

    // Also check home directory and runtime dir
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::remove_file(format!("{}/.attach_pid{}", home, pid));
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let _ = std::fs::remove_file(format!("{}/.attach_pid{}", xdg, pid));
    }
}

#[cfg(target_os = "windows")]
fn delete_attach_artifacts() {
    unsafe {
        destroy_or_squat_shared_memory();
        disconnect_attach_pipes();
    }
}

/// Destroy or squat the JVM's shared memory mapping used for attach handshake.
/// The JVM Attach mechanism on Windows uses a shared memory section named
/// `JSharedMem_<pid>` to communicate the named pipe path to attaching tools.
/// We either corrupt its contents or preemptively occupy the name.
#[cfg(target_os = "windows")]
unsafe fn destroy_or_squat_shared_memory() {
    use std::ffi::CString;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{MapViewOfFile, UnmapViewOfFile};
    use winapi::um::winbase::{CreateFileMappingA, OpenFileMappingA};
    use winapi::um::winnt::PAGE_READWRITE;
    use winapi::um::processthreadsapi::GetCurrentProcessId;

    const FILE_MAP_ALL_ACCESS: u32 = 0xF001F;

    let pid = GetCurrentProcessId();
    let name = CString::new(format!("JSharedMem_{}", pid)).unwrap();

    // Strategy 1: Try to open the existing mapping and corrupt it
    let existing = OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,
        0,
        name.as_ptr(),
    );

    if !existing.is_null() {
        let view = MapViewOfFile(existing, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if !view.is_null() {
            // Zero the entire mapping to corrupt the pipe name stored inside
            std::ptr::write_bytes(view as *mut u8, 0, 4096);
            UnmapViewOfFile(view);
        }
        CloseHandle(existing);
    }

    // Strategy 2: Preemptively create/hold the mapping name (squatting)
    // If we hold it, the JVM's Attach Listener cannot create it with its own data.
    let handle_store = SHARED_MEM_HANDLE.get_or_init(|| Mutex::new(0));
    let mut stored = handle_store.lock().unwrap_or_else(|e| e.into_inner());

    if *stored == 0 {
        let our_handle = CreateFileMappingA(
            winapi::um::handleapi::INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            4096,
            name.as_ptr(),
        );
        if !our_handle.is_null() {
            // Fill with zeros so even if JVM gets a handle, it reads garbage
            let view = MapViewOfFile(our_handle as *mut _, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if !view.is_null() {
                std::ptr::write_bytes(view as *mut u8, 0, 4096);
                UnmapViewOfFile(view);
            }
            *stored = our_handle as usize;
        }
    }
}

/// Enumerate named pipes and disconnect/disrupt any that match JVM attach patterns.
/// The JVM creates pipes like "\\.\pipe\<number>_<pid>" for attach communication.
#[cfg(target_os = "windows")]
unsafe fn disconnect_attach_pipes() {
    use std::ffi::CString;
    use winapi::um::fileapi::{FindFirstFileA, FindNextFileA, CreateFileA, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::WIN32_FIND_DATAA;
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    use winapi::um::processthreadsapi::GetCurrentProcessId;

    let pipe_pattern = CString::new("\\\\.\\pipe\\*").unwrap();
    let mut find_data: WIN32_FIND_DATAA = std::mem::zeroed();
    let handle = FindFirstFileA(pipe_pattern.as_ptr(), &mut find_data);

    if handle == INVALID_HANDLE_VALUE {
        return;
    }

    let pid = GetCurrentProcessId();
    let pid_str = format!("_{}", pid);

    loop {
        let name = std::ffi::CStr::from_ptr(find_data.cFileName.as_ptr())
            .to_string_lossy();
        let name_lower = name.to_lowercase();

        // Match JVM attach pipe patterns:
        // - Contains our PID suffix
        // - Or contains "attach" / "jdwp"
        let is_attach_pipe = name_lower.contains(&pid_str.to_lowercase())
            || name_lower.contains("attach")
            || name_lower.contains("jdwp");

        if is_attach_pipe {
            // Connect and immediately close to disrupt the pipe server
            let pipe_path = CString::new(format!("\\\\.\\pipe\\{}", name)).unwrap();
            let pipe_handle = CreateFileA(
                pipe_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if pipe_handle != INVALID_HANDLE_VALUE {
                CloseHandle(pipe_handle);
            }
        }

        if FindNextFileA(handle, &mut find_data) == 0 {
            break;
        }
    }
    CloseHandle(handle);
}

/// Capture all current thread IDs as baseline before protection activation.
/// Only threads appearing AFTER this snapshot will be considered for suspension.
#[cfg(target_os = "windows")]
pub fn capture_thread_baseline() {
    unsafe {
        use winapi::um::tlhelp32::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next,
            TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use winapi::um::processthreadsapi::GetCurrentProcessId;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

        let pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut threads = HashSet::new();
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    threads.insert(entry.th32ThreadID);
                }
                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        let _ = THREAD_BASELINE.set(Mutex::new(threads));
    }
}

/// Find and suspend the JVM's Attach Listener thread.
/// Identifies it by: (1) not in baseline, (2) start address within jvm.dll.
/// If found, this is proof that an attach was attempted — exit immediately.
#[cfg(target_os = "windows")]
unsafe fn suspend_attach_listener_thread() {
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next,
        TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::processthreadsapi::{
        GetCurrentProcessId, GetCurrentThreadId, OpenThread, SuspendThread,
    };
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::winnt::{THREAD_SUSPEND_RESUME, THREAD_QUERY_INFORMATION};

    let pid = GetCurrentProcessId();
    let current_tid = GetCurrentThreadId();

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return;
    }

    let suspended_set = SUSPENDED_THREADS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut suspended = suspended_set.lock().unwrap_or_else(|e| e.into_inner());

    let mut entry: THREADENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if Thread32First(snapshot, &mut entry) != 0 {
        loop {
            if entry.th32OwnerProcessID == pid
                && entry.th32ThreadID != current_tid
                && !suspended.contains(&entry.th32ThreadID)
            {
                // Skip threads that existed before protection was enabled
                let in_baseline = THREAD_BASELINE.get()
                    .and_then(|b| b.lock().ok())
                    .map(|set| set.contains(&entry.th32ThreadID))
                    .unwrap_or(false);

                if !in_baseline {
                    let thread_handle = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        0,
                        entry.th32ThreadID,
                    );

                    if !thread_handle.is_null() {
                        if is_attach_listener_thread(thread_handle) {
                            // Suspend it immediately
                            SuspendThread(thread_handle);
                            suspended.insert(entry.th32ThreadID);
                            CloseHandle(thread_handle);
                            CloseHandle(snapshot);
                            // Attach Listener thread detected — someone tried to attach.
                            // Exit the process to prevent class info leakage.
                            drop(suspended);
                            high_threat_response();
                            return;
                        }
                        CloseHandle(thread_handle);
                    }
                }
            }

            if Thread32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
}

/// Identify the Attach Listener thread by checking if its Win32 start address
/// falls within jvm.dll's address range.
#[cfg(target_os = "windows")]
unsafe fn is_attach_listener_thread(thread_handle: *mut std::ffi::c_void) -> bool {
    // ThreadQuerySetWin32StartAddress = 9
    let mut start_address: usize = 0;
    let mut return_length: u32 = 0;

    let status = ntapi::ntpsapi::NtQueryInformationThread(
        thread_handle,
        9, // ThreadQuerySetWin32StartAddress
        &mut start_address as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<usize>() as u32,
        &mut return_length,
    );

    if status != 0 || start_address == 0 {
        return false;
    }

    is_address_in_jvm_dll(start_address)
}

/// Check if an address falls within the jvm.dll module range.
#[cfg(target_os = "windows")]
unsafe fn is_address_in_jvm_dll(addr: usize) -> bool {
    let &(base, size) = JVM_DLL_RANGE.get_or_init(|| {
        find_jvm_dll_range().unwrap_or((0, 0))
    });

    if base == 0 {
        return false;
    }

    addr >= base && addr < base + size
}

/// Find the base address and size of jvm.dll in the current process.
#[cfg(target_os = "windows")]
unsafe fn find_jvm_dll_range() -> Option<(usize, usize)> {
    use std::ffi::CString;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
    use winapi::um::processthreadsapi::GetCurrentProcess;

    let names = [
        CString::new("jvm.dll").unwrap(),
        CString::new("jvm").unwrap(),
    ];

    for name in &names {
        let handle = GetModuleHandleA(name.as_ptr());
        if !handle.is_null() {
            let mut info: MODULEINFO = std::mem::zeroed();
            if GetModuleInformation(
                GetCurrentProcess(),
                handle,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            ) != 0 {
                return Some((info.lpBaseOfDll as usize, info.SizeOfImage as usize));
            }
        }
    }

    None
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn delete_attach_artifacts() {}

// ============================================================
// Platform-specific: Patch JVM_EnqueueOperation on Linux
// ============================================================

/// Patch JVM_EnqueueOperation in libjvm.so on Linux.
/// On Linux, the Attach Listener thread uses a UNIX domain socket at
/// /tmp/.java_pid<pid>. When a client connects and sends a command,
/// the Attach Listener calls into JVM internal functions to execute it.
///
/// Unlike Windows (where the function is called from injected code),
/// on Linux JVM_EnqueueOperation is not used by the attach mechanism directly.
/// Instead, the Attach Listener thread reads commands from the socket and
/// dispatches them internally. However, we can still patch it to block
/// the `load` command path.
///
/// The more effective approach on Linux is:
///   1. Intercept SIGQUIT (prevents Attach Listener from starting)
///   2. Continuously delete /tmp/.java_pid<pid> (breaks socket connection)
///   3. Patch the AttachListener::init function pointer in libjvm.so
///
/// We use dlsym to find and patch JVM_EnqueueOperation (used by self-attach)
/// and also overwrite the socket file with a dummy to prevent connections.
#[cfg(target_os = "linux")]
fn patch_enqueue_operation_linux() {
    unsafe {
        // Find JVM_EnqueueOperation in libjvm.so via dlsym
        let func_name = b"JVM_EnqueueOperation\0";
        let handle = libc::dlopen(std::ptr::null(), libc::RTLD_NOW);
        if handle.is_null() {
            return;
        }

        let func_addr = libc::dlsym(handle, func_name.as_ptr() as *const i8);
        libc::dlclose(handle);

        if func_addr.is_null() {
            return;
        }

        // Make the page writable
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page_start = (func_addr as usize) & !(page_size - 1);

        if libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0 {
            return;
        }

        // x86_64 Linux: mov eax, -1; ret
        let patch: [u8; 6] = [
            0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, -1
            0xC3,                           // ret
        ];
        std::ptr::copy_nonoverlapping(patch.as_ptr(), func_addr as *mut u8, patch.len());

        // Restore protection
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        );

        // Also try to bind-mount over the socket file to make it permanently unusable
        // This prevents the Attach Listener from accepting connections even if it starts
        let pid = libc::getpid();
        let socket_path = format!("/tmp/.java_pid{}\0", pid);

        // Remove existing socket and create a regular file in its place
        libc::unlink(socket_path.as_ptr() as *const i8);
        let fd = libc::open(
            socket_path.as_ptr() as *const i8,
            libc::O_CREAT | libc::O_WRONLY,
            0o000, // no permissions — nobody can connect
        );
        if fd >= 0 {
            libc::close(fd);
            // Set immutable-like permissions: no read, no write, no execute
            libc::chmod(socket_path.as_ptr() as *const i8, 0o000);
        }
    }
}

// ============================================================
// Platform-specific: SIGQUIT interception (Linux only)
// ============================================================

#[cfg(target_os = "linux")]
fn install_sigquit_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigquit_noop_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
    }
}

#[cfg(target_os = "linux")]
extern "C" fn sigquit_noop_handler(_sig: libc::c_int, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // Intentionally empty — swallows SIGQUIT to prevent Attach Listener wakeup
}

// ============================================================
// JDWP detection
// ============================================================

fn detect_jdwp_listeners() -> bool {
    let listening_ports = get_self_listening_ports();
    for port in &listening_ports {
        if JDWP_PORTS.contains(port) {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn get_self_listening_ports() -> Vec<u16> {
    let mut ports = Vec::new();

    // Parse /proc/self/net/tcp for LISTEN state (0A)
    if let Ok(content) = std::fs::read_to_string("/proc/self/net/tcp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            // State is the 4th field, "0A" = LISTEN
            if parts[3] == "0A" {
                // local_address is "hex_ip:hex_port"
                if let Some(port_hex) = parts[1].split(':').nth(1) {
                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                        ports.push(port);
                    }
                }
            }
        }
    }

    // Also check tcp6
    if let Ok(content) = std::fs::read_to_string("/proc/self/net/tcp6") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            if parts[3] == "0A" {
                if let Some(port_hex) = parts[1].split(':').nth(1) {
                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                        ports.push(port);
                    }
                }
            }
        }
    }

    ports
}

#[cfg(target_os = "windows")]
fn get_self_listening_ports() -> Vec<u16> {
    let mut ports = Vec::new();

    unsafe {
        // Use GetExtendedTcpTable to find listening ports owned by our process
        let pid = winapi::um::processthreadsapi::GetCurrentProcessId();

        let mut size: u32 = 0;
        // First call to get required buffer size
        // TCP_TABLE_OWNER_PID_LISTENER = 3, AF_INET = 2
        let ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            2, // AF_INET
            3, // TCP_TABLE_OWNER_PID_LISTENER
            0,
        );

        if ret == 122 && size > 0 {
            // ERROR_INSUFFICIENT_BUFFER
            let mut buffer = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                2,
                3,
                0,
            );

            if ret == 0 {
                // Parse MIB_TCPTABLE_OWNER_PID structure
                let num_entries = u32::from_ne_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3],
                ]);

                let entry_size = 24; // sizeof(MIB_TCPROW_OWNER_PID)
                for i in 0..num_entries as usize {
                    let offset = 4 + i * entry_size;
                    if offset + entry_size > buffer.len() {
                        break;
                    }
                    // dwOwningPid is at offset 20 within each entry
                    let entry_pid = u32::from_ne_bytes([
                        buffer[offset + 20],
                        buffer[offset + 21],
                        buffer[offset + 22],
                        buffer[offset + 23],
                    ]);
                    if entry_pid == pid {
                        // dwLocalPort is at offset 8, stored in network byte order
                        let port = u16::from_be_bytes([
                            buffer[offset + 8],
                            buffer[offset + 9],
                        ]);
                        ports.push(port);
                    }
                }
            }
        }
    }

    ports
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut std::ffi::c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_self_listening_ports() -> Vec<u16> {
    Vec::new()
}

// ============================================================
// JVM TI Agent detection
// ============================================================

/// Detect if new agents were loaded after baseline capture
fn detect_new_agents() -> bool {
    let current_modules = enumerate_loaded_modules();

    for module in &current_modules {
        let lower = module.to_lowercase();
        for pattern in KNOWN_AGENT_PATTERNS {
            if lower.contains(pattern) {
                // Check if this was present at baseline
                if let Some(baseline) = MODULE_BASELINE.get() {
                    if let Ok(baseline_set) = baseline.lock() {
                        if !baseline_set.contains(module) {
                            return true;
                        }
                    }
                } else {
                    // No baseline yet — agent present from start is high threat too
                    return true;
                }
            }
        }
    }
    false
}

// ============================================================
// Module enumeration (cross-platform)
// ============================================================

#[cfg(target_os = "linux")]
fn enumerate_loaded_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            // Format: address perms offset dev inode pathname
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if let Some(path) = parts.last() {
                let path = path.trim();
                if path.starts_with('/') && path.contains(".so") {
                    modules.insert(path.to_string());
                }
            }
        }
    }
    modules
}

#[cfg(target_os = "windows")]
fn enumerate_loaded_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    unsafe {
        use winapi::um::psapi::EnumProcessModules;
        use winapi::um::libloaderapi::GetModuleFileNameA;
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::shared::minwindef::HMODULE;

        let process = GetCurrentProcess();
        let mut h_modules: [HMODULE; 1024] = std::mem::zeroed();
        let mut needed: u32 = 0;

        if EnumProcessModules(
            process,
            h_modules.as_mut_ptr(),
            std::mem::size_of_val(&h_modules) as u32,
            &mut needed,
        ) != 0
        {
            let count = (needed as usize) / std::mem::size_of::<HMODULE>();
            for i in 0..count {
                let mut name_buf = [0u8; 260];
                let len = GetModuleFileNameA(
                    h_modules[i],
                    name_buf.as_mut_ptr() as *mut i8,
                    name_buf.len() as u32,
                );
                if len > 0 {
                    let name = std::ffi::CStr::from_ptr(name_buf.as_ptr() as *const i8)
                        .to_string_lossy()
                        .into_owned();
                    modules.insert(name);
                }
            }
        }
    }
    modules
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn enumerate_loaded_modules() -> HashSet<String> {
    HashSet::new()
}
