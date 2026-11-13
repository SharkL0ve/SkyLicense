// 错误代号表:

#![allow(unused_qualifications)]
// E001: 保护系统已经启动
// E002: 检测到调试环境，拒绝启动
// E003: 检测到调试器 (IsDebuggerPresent)
// E004: 检测到远程调试器
// E005: ptrace检测触发
// E006: 检测到调试端口
// E007: 检测到调试对象
// E008: Linux内存保护失败
// E009: Linux栈保护设置失败
// E010: Linux栈保护权限设置失败
// E011: Linux堆保护设置失败
// E012: Linux堆保护权限设置失败
// E013: 内存查询失败
// E014: 代码段权限异常
// E015: 内存保护被破坏
// E016: 保护页未找到或权限被更改
// E017: 无法读取内存映射
// E018: 代码段被修改
// E019: 多次心跳失败 可能被调试器暂停
// 备注: 所有对外抛出的错误均返回代号字符串，如 Err("E001".to_string())

use libc::{self, c_void};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, thread};
use sysinfo::{ProcessExt, System, SystemExt};
#[cfg(target_os = "windows")]
use winapi::um::{
    debugapi::{CheckRemoteDebuggerPresent, IsDebuggerPresent},
    libloaderapi::{GetModuleHandleA, GetProcAddress},
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    processthreadsapi::GetCurrentProcess,
    winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE},
};

/// 跨平台保护系统主类
pub struct ProtectionManager {
    is_activated: bool,
    last_heartbeat: Arc<Mutex<SystemTime>>,
    debugger_detected: Arc<Mutex<bool>>,
    monitoring_thread: Option<thread::JoinHandle<()>>,
}

impl ProtectionManager {
    pub fn new() -> Self {
        Self {
            is_activated: false,
            last_heartbeat: Arc::new(Mutex::new(SystemTime::now())),
            debugger_detected: Arc::new(Mutex::new(false)),
            monitoring_thread: None,
        }
    }

    /// 启用反Hook保护
    fn enable_anti_hook(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            if let Err(e) = self.detect_windows_hooks() {
                return Err(e);
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Err(e) = self.detect_linux_hooks() {
                return Err(e);
            }
        }

        Ok(())
    }

    /// 一键开启所有保护功能
    pub fn enable_protection(&mut self) -> Result<(), String> {
        if self.is_activated {
            return Err("E001".to_string());
        }

        // 1. 环境检测 - 检查调试器和分析工具
        if self.detect_debugging_tools() {
            return Err("E002".to_string());
        }

        // 2. 反调试保护
        self.enable_anti_debug()?;

        // 3. 反Hook保护
        self.enable_anti_hook()?;

        // 4. 内存保护
        self.enable_memory_protection()?;

        // 5. 完整性校验
        self.enable_integrity_checks()?;

        // 6. 启动监控线程
        self.start_protection_monitor();

        // 7. 启动attach防御
        self.enable_anti_attach()?;

        self.is_activated = true;
        Ok(())
    }

    /// 启用防调试器附加保护（非破坏性方案）
    pub fn enable_anti_attach(&self) -> Result<(), String> {
        // Delegate to the new anti_attach module which uses file/pipe monitoring
        // instead of killing threads. The guard is started in lib.rs after JNI is available.
        // Here we only do the initial environment variable check.
        if crate::anti_attach::check_suspicious_env_vars() {
            return Err("E022".to_string());
        }
        if crate::anti_attach::check_cmdline_for_agents() {
            return Err("E020".to_string());
        }
        Ok(())
    }

    /// 检测调试器和分析工具
    fn detect_debugging_tools(&self) -> bool {
        use sysinfo::{ProcessRefreshKind, RefreshKind};
        let mut system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new())
        );
        system.refresh_processes();

        let suspicious_processes = if cfg!(target_os = "windows") {
            vec![
                "ollydbg.exe", "x64dbg.exe", "idaq.exe", "ida64.exe",
                "windbg.exe", "immunitydebugger.exe", "cheatengine-x86_64.exe",
                "cheatengine-i386.exe", "wireshark.exe",
                "procmon.exe", "apimonitor.exe", "hookexplorer.exe", "frida",
                "dnspy.exe", "binaryninja.exe", "ghidra", "ghidrarun.exe",
                "jvisualvm.exe", "visualvm.exe", "jconsole.exe", "jmc.exe",
                "pin.exe", "drrun.exe", "drconfig.exe", "dynamorio",
                "arthas", "async-profiler",
            ]
        } else {
            vec![
                "gdb", "lldb", "strace", "ltrace", "radare2", "r2",
                "idaq", "hopper", "cheatengine", "wireshark", "frida",
                "dnspy", "binaryninja", "ghidra", "ghidrarun",
                "jvisualvm", "visualvm", "jconsole", "jmc",
                "pin", "drrun", "drconfig", "dynamorio",
                "arthas", "async-profiler",
            ]
        };

        for process in system.processes().values() {
            let name = process.name().to_lowercase();
            for suspicious in &suspicious_processes {
                if name.contains(suspicious) {
                    return true;
                }
            }
            // Also check command-line arguments for agent injection
            let cmd = process.cmd();
            for arg in cmd {
                let lower_arg = arg.to_lowercase();
                if lower_arg.contains("-agentlib:jdwp")
                    || lower_arg.contains("frida-server")
                    || lower_arg.contains("pin -t")
                    || lower_arg.contains("-agentpath:")
                {
                    return true;
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(current_pid) = system.get_current_pid() {
                if let Some(current_process) = system.process(current_pid) {
                    if let Some(parent_pid) = current_process.parent() {
                        if let Some(parent_process) = system.process(parent_pid) {
                            let parent_name = parent_process.name().to_lowercase();
                            if parent_name.contains("gdb") || parent_name.contains("lldb") {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// 启用反调试保护
    fn enable_anti_debug(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                if IsDebuggerPresent() != 0 {
                    return Err("E003".to_string());
                }

                let mut debugger_present = 0;
                let current_process = GetCurrentProcess();
                if CheckRemoteDebuggerPresent(current_process, &mut debugger_present) != 0 {
                    if debugger_present != 0 {
                        return Err("E004".to_string());
                    }
                }

                if let Err(e) = self.check_nt_debug_port() {
                    return Err(e);
                }

                if let Err(e) = self.check_debug_object() {
                    return Err(e);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
                for line in content.lines() {
                    if line.starts_with("TracerPid:") {
                        let tracer_pid = line.split_whitespace().nth(1).unwrap_or("0");
                        if tracer_pid != "0" {
                            return Err("E005".to_string());
                        }
                        break;
                    }
                }
            }

            if self.ptrace_self_detect() {
                return Err("E005".to_string());
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    unsafe fn check_nt_debug_port(&self) -> Result<(), String> {
        const PROCESS_DEBUG_PORT: u32 = 7;
        let mut debug_port = 0u32;
        let mut return_length = 0u32;
        let status = unsafe {
            ntapi::ntpsapi::NtQueryInformationProcess(
                GetCurrentProcess(),
                PROCESS_DEBUG_PORT,
                &mut debug_port as *mut _ as *mut c_void,
                size_of::<u32>() as u32,
                &mut return_length,
            )
        };
        if status == 0 && debug_port != 0 {
            return Err("E006".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    unsafe fn check_debug_object(&self) -> Result<(), String> {
        const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 0x1E;
        let mut debug_handle = 0usize;
        let mut return_length = 0u32;
        let status = unsafe {
            ntapi::ntpsapi::NtQueryInformationProcess(
                GetCurrentProcess(),
                PROCESS_DEBUG_OBJECT_HANDLE,
                &mut debug_handle as *mut _ as *mut c_void,
                size_of::<usize>() as u32,
                &mut return_length,
            )
        };
        if status == 0 && debug_handle != 0 {
            return Err("E007".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ptrace_self_detect(&self) -> bool {
        unsafe {
            let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            if result == -1 {
                return true; // Already being traced
            }
            // Detach
            libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
            false
        }
    }

    #[cfg(target_os = "windows")]
    fn detect_windows_hooks(&self) -> Result<(), String> {
        use std::ffi::CString;
        unsafe {
            let critical_apis = [
                //("kernel32.dll", "CreateFileA"),
                //("kernel32.dll", "ReadProcessMemory"),
                //("kernel32.dll", "WriteProcessMemory"),
                //("kernel32.dll", "OpenProcess"),
                //("ntdll.dll", "NtQuerySystemInformation"),
                //("ntdll.dll", "NtReadVirtualMemory"),
                ("ntdll.dll", "NtOpenProcess"),
                ("ntdll.dll", "ZwOpenProcess"),
                ("user32.dll", "SetWindowsHookExA"),
            ];
            for (module, function) in &critical_apis {
                let module_c = CString::new(*module).unwrap();
                let func_c = CString::new(*function).unwrap();
                let module_handle = GetModuleHandleA(module_c.as_ptr());
                if !module_handle.is_null() {
                    let func_addr = GetProcAddress(module_handle, func_c.as_ptr());
                    if !func_addr.is_null() {
                        let code_start = func_addr as *const u8;
                        let first_bytes = std::slice::from_raw_parts(code_start, 8);
                        if first_bytes[0] == 0xE9 || (first_bytes[0] == 0xFF && first_bytes[1] == 0x25) {
                            return Err(format!("检测到API Hook: {}!{}", module, function));
                        }
                        let func_module = Self::get_module_from_address(func_addr as *const c_void);
                        // 比较时只取文件名部分，忽略大小写
                        let func_module_name = func_module
                            .rsplit(['\\', '/'])
                            .next()
                            .unwrap_or(&func_module)
                            .to_lowercase();
                        if func_module_name != module.to_lowercase() {
                            return Err(format!("检测到IAT Hook: {}!{} -> {}", module, function, func_module));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_module_from_address(addr: *const c_void) -> String {
        unsafe {
            use winapi::um::psapi::GetModuleInformation;
            use winapi::um::libloaderapi::GetModuleFileNameA;
            use winapi::um::processthreadsapi::GetCurrentProcess;
            use winapi::shared::minwindef::HMODULE;
            use winapi::um::psapi::MODULEINFO;

            let mut modules: [HMODULE; 1024] = std::mem::zeroed();
            let mut needed: u32 = 0;

            // 获取所有加载的模块
            if winapi::um::psapi::EnumProcessModules(
                GetCurrentProcess(),
                modules.as_mut_ptr(),
                size_of_val(&modules) as u32,
                &mut needed,
            ) != 0 {
                let module_count = (needed / size_of::<HMODULE>() as u32) as usize;

                // 遍历模块找到包含指定地址的那个
                for i in 0..module_count {
                    let mut mod_info: MODULEINFO = std::mem::zeroed();
                    if GetModuleInformation(
                        GetCurrentProcess(),
                        modules[i],
                        &mut mod_info,
                        size_of::<MODULEINFO>() as u32,
                    ) != 0 {
                        let start = mod_info.lpBaseOfDll as usize;
                        let end = start + mod_info.SizeOfImage as usize;
                        if (addr as usize) >= start && (addr as usize) < end {
                            let mut module_name = [0u8; 260];
                            let result = GetModuleFileNameA(
                                modules[i],
                                module_name.as_mut_ptr() as *mut i8,
                                module_name.len() as u32,
                            );
                            if result > 0 {
                                return std::ffi::CStr::from_ptr(module_name.as_ptr() as *const i8)
                                    .to_string_lossy()
                                    .into_owned();
                            }
                        }
                    }
                }
            }

            "unknown".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_hooks(&self) -> Result<(), String> {
        // 检查LD_PRELOAD环境变量
        if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
            if !ld_preload.is_empty() {
                return Err(format!("检测到LD_PRELOAD Hook: {}", ld_preload));
            }
        }

        // 检查/proc/self/maps中的可疑模块
        if let Ok(maps_content) = std::fs::read_to_string("/proc/self/maps") {
            let suspicious_patterns = [
                "libinj.so", "libhook.so", "substrate", "xposed", "frida", "libriru",
                "libpin.so", "libdynamorio.so", "libdrutil.so", "libdrmgr.so",
                "libfrida-agent", "libasyncprofiler", "libyjpagent", "libjprofilerti",
            ];

            for line in maps_content.lines() {
                for pattern in &suspicious_patterns {
                    if line.contains(pattern) {
                        return Err(format!("检测到可疑内存映射: {}", line));
                    }
                }
            }
        }

        // 检查/proc/self/fd中的可疑文件描述符
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let target_str = target.to_string_lossy();
                    if target_str.contains("frida") || target_str.contains("gdb") {
                        return Err(format!("检测到可疑文件描述符: {}", target_str));
                    }
                }
            }
        }

        Ok(())
    }

    /// 启用内存保护
    fn enable_memory_protection(&self) -> Result<(), String> {
        //println!("[保护系统] 启用内存保护...");

        // 保护关键数据区域
        self.protect_critical_memory()?;

        // 设置内存保护页
        self.setup_memory_guards()?;

        Ok(())
    }

    fn protect_critical_memory(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE};
                use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};

                // 使用固定的页面大小（Windows一般是4KB）
                let page_size = 4096;

                // 分配按页对齐的内存（额外分配一页作为保护页）
                let size = (8192 + page_size) & !(page_size - 1);
                let data_ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                if data_ptr.is_null() {
                    return Err(format!("Memory Error: {}", io::Error::last_os_error()));
                }

                // 初始化内存
                let random_value = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u8;
                std::ptr::write_bytes(data_ptr as *mut u8, random_value, size - page_size);

                // 先设置保护页
                let guard_ptr = (data_ptr as usize + size - page_size) as *mut _;
                let mut old_protect: u32 = 0;
                if VirtualProtect(
                    guard_ptr,
                    page_size,
                    PAGE_NOACCESS,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(data_ptr, 0, MEM_RELEASE);
                    return Err(format!("Error: {}", err));
                }

                // 设置主数据区域为不可访问
                if VirtualProtect(
                    data_ptr,
                    size - page_size,
                    PAGE_NOACCESS,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(data_ptr, 0, MEM_RELEASE);
                    return Err(format!("Memory Error: {}", err));
                }

                //println!("[保护系统] 敏感数据区域已保护");
            }
        }

        /*#[cfg(target_os = "linux")]
        {
            unsafe {
                let data_ptr = SENSITIVE_DATA.as_mut_ptr() as usize;
                let page_size = 4096;
                let aligned_ptr = (data_ptr & !(page_size - 1)) as *mut c_void;
                let protected_size = (SENSITIVE_DATA.len() + page_size - 1) & !(page_size - 1);

                if libc::mprotect(aligned_ptr, protected_size, libc::PROT_NONE) == -1 {
                    return Err("E008".to_string());
                }

                println!("[保护系统] 敏感数据区域已保护");
            }
        }*/

        Ok(())
    }

    fn setup_memory_guards(&self) -> Result<(), String> {
        // 设置内存保护页，检测内存访问
        //println!("[保护系统] 设置内存保护页...");

        // 设置栈保护
        #[cfg(target_os = "windows")]
        {
            unsafe {
                use winapi::um::winnt::PAGE_READONLY;

                // 分配栈保护页（分配两页：一页作为保护页，一页作为警戒区）
                let guard_size = 4096 * 2;
                let guard_ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    guard_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                if guard_ptr.is_null() {
                    return Err(format!("Memory Error: {}", io::Error::last_os_error()));
                }

                // 初始化内存为随机值增加安全性
                let random_value = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u8;
                std::ptr::write_bytes(guard_ptr as *mut u8, random_value, guard_size);

                // 设置第一页为只读（警戒区）
                let mut old_protect: u32 = 0;
                if VirtualProtect(
                    guard_ptr,
                    4096,
                    PAGE_READONLY,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(guard_ptr, 0, MEM_RELEASE);
                    return Err(format!("Memory Error: {}", err));
                }

                // 设置第二页为不可访问
                if VirtualProtect(
                    (guard_ptr as usize + 4096) as *mut _,
                    4096,
                    PAGE_NOACCESS,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(guard_ptr, 0, MEM_RELEASE);
                    return Err(format!("Memory Error: {}", err));
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                // 使用mmap创建保护页
                let guard_size = 4096;
                let guard_ptr = libc::mmap(
                    std::ptr::null_mut(),
                    guard_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                if guard_ptr == libc::MAP_FAILED {
                    return Err("E009".to_string());
                }

                // 初始化内存
                let random_value = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u8;
                std::ptr::write_bytes(guard_ptr as *mut u8, random_value, guard_size);

                // 设置为不可访问
                if libc::mprotect(guard_ptr, guard_size, libc::PROT_NONE) == -1 {
                    libc::munmap(guard_ptr, guard_size);
                    return Err("E010".to_string());
                }
            }
        }

        // 设置堆保护
        #[cfg(target_os = "windows")]
        {
            unsafe {
                use winapi::um::winnt::PAGE_READONLY;

                // 分配堆保护页（分配三页：前后各一个保护页，中间一页作为警戒区）
                let guard_size = 4096 * 3;
                let guard_ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    guard_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                if guard_ptr.is_null() {
                    return Err(format!("堆保护内存分配失败: {}", io::Error::last_os_error()));
                }

                // 初始化内存为随机值
                let random_value = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u8;
                std::ptr::write_bytes(guard_ptr as *mut u8, random_value, guard_size);

                let mut old_protect: u32 = 0;

                // 设置第一页为不可访问（前保护页）
                if VirtualProtect(
                    guard_ptr,
                    4096,
                    PAGE_NOACCESS,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(guard_ptr, 0, MEM_RELEASE);
                    return Err(format!("堆前保护页设置失败: {}", err));
                }

                // 设置中间页为只读（警戒区）
                if VirtualProtect(
                    (guard_ptr as usize + 4096) as *mut _,
                    4096,
                    PAGE_READONLY,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(guard_ptr, 0, MEM_RELEASE);
                    return Err(format!("堆警戒区设置失败: {}", err));
                }

                // 设置最后一页为不可访问（后保护页）
                if VirtualProtect(
                    (guard_ptr as usize + 8192) as *mut _,
                    4096,
                    PAGE_NOACCESS,
                    &mut old_protect
                ) == 0 {
                    let err = io::Error::last_os_error();
                    VirtualFree(guard_ptr, 0, MEM_RELEASE);
                    return Err(format!("堆后保护页设置失败: {}", err));
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                // 使用mmap创建堆保护页
                let guard_size = 4096 * 2;
                let guard_ptr = libc::mmap(
                    std::ptr::null_mut(),
                    guard_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                if guard_ptr == libc::MAP_FAILED {
                    return Err("E011".to_string());
                }

                // 初始化内存
                let random_value = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u8;
                std::ptr::write_bytes(guard_ptr as *mut u8, random_value, guard_size);

                // 设置为不可访问
                if libc::mprotect(guard_ptr, guard_size, libc::PROT_NONE) == -1 {
                    libc::munmap(guard_ptr, guard_size);
                    return Err("E012".to_string());
                }
            }
        }

        //println!("[保护系统] 内存保护机制已设置");
        Ok(())
    }

    /// 启用完整性校验
    fn enable_integrity_checks(&self) -> Result<(), String> {
        self.setup_periodic_integrity_checks();
        Ok(())
    }

    fn setup_periodic_integrity_checks(&self) {
        static INTEGRITY_CHECK_ACTIVE: AtomicBool = AtomicBool::new(true);

        let _ = thread::spawn(move || {
            // Generate a runtime-random HMAC key (cannot be precomputed by attacker)
            static HMAC_KEY: OnceLock<[u8; 32]> = OnceLock::new();
            let hmac_key = HMAC_KEY.get_or_init(|| {
                let mut key = [0u8; 32];
                for i in 0..32 { key[i] = rand::random::<u8>(); }
                key
            });

            // Compute baseline hash on first run
            static INTEGRITY_BASELINE: OnceLock<[u8; 32]> = OnceLock::new();
            let baseline = INTEGRITY_BASELINE.get_or_init(|| {
                compute_integrity_hmac(hmac_key)
            });

            let check_interval = Duration::from_secs(30);
            let mut last_check = SystemTime::now();

            while INTEGRITY_CHECK_ACTIVE.load(Ordering::Relaxed) {
                if SystemTime::now().duration_since(last_check).unwrap_or(Duration::ZERO) >= check_interval {
                    let current_hash = compute_integrity_hmac(hmac_key);
                    if current_hash != *baseline {
                        // Code segment modified — delayed exit
                        crate::debug_log!("[SkyLicense] !!! Code integrity check FAILED — code segment modified, exiting !!!");
                        thread::sleep(Duration::from_secs(
                            rand::random::<u64>() % 10 + 2
                        ));
                        unsafe { libc::exit(1); }
                    }
                    last_check = SystemTime::now();
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
    }

    /// 启动保护监控线程
    fn start_protection_monitor(&mut self) {
        let heartbeat = self.last_heartbeat.clone();
        let debugger_detected = self.debugger_detected.clone();

        let monitor_handle = thread::spawn(move || {
            let mut consecutive_failures = 0;

            loop {
                // 更新心跳
                {
                    let mut last = heartbeat.lock().unwrap();
                    *last = SystemTime::now();
                }

                // 执行定期安全检查
                if Self::perform_periodic_security_checks() {
                    let mut detected = debugger_detected.lock().unwrap();
                    *detected = true;
                    crate::debug_log!("[SkyLicense] !!! Debugger/suspicious process detected — exiting !!!");
                    unsafe { crate::corrupt_state(); }
                    thread::sleep(Duration::from_millis(
                        (rand::random::<u64>() % 3000) + 500
                    ));
                    unsafe { libc::exit(1); }
                }

                // Anti-attach is now handled by the anti_attach module's own thread.
                // No thread-killing here.

                // 检查心跳间隔
                {
                    let last = heartbeat.lock().unwrap();
                    let elapsed = last.elapsed().unwrap_or(Duration::from_secs(0));
                    if elapsed > Duration::from_secs(60) {
                        consecutive_failures += 1;
                        if consecutive_failures >= 3 {
                            /*eprintln!("E019");
                            std::process::exit(1);*/
                        }
                    } else {
                        consecutive_failures = 0;
                    }
                }

                // 休眠短暂时间
                thread::sleep(Duration::from_millis(100));
            }
        });

        self.monitoring_thread = Some(monitor_handle);
        //println!("[保护系统] 保护监控线程已启动");
    }

    fn perform_periodic_security_checks() -> bool {
        use sysinfo::{ProcessRefreshKind, RefreshKind};
        let mut system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new())
        );
        system.refresh_processes();

        // 快速进程检查
        let quick_checks = if cfg!(target_os = "windows") {
            vec![
                "ollydbg", "x64dbg", "cheatengine", "frida",
                "dnspy", "binaryninja", "ghidra", "arthas",
                "pin.exe", "drrun", "dynamorio", "jvisualvm",
            ]
        } else {
            vec![
                "gdb", "lldb", "strace", "frida",
                "dnspy", "binaryninja", "ghidra", "arthas",
                "pin", "drrun", "dynamorio", "jvisualvm",
            ]
        };

        for process in system.processes().values() {
            let name = process.name().to_lowercase();
            for check in &quick_checks {
                if name.contains(check) {
                    //eprintln!("[保护系统] 定期检查发现可疑进程: {}", name);
                    return true;
                }
            }
        }

        // Linux特定检查
        #[cfg(target_os = "linux")]
        {
            // 检查TracerPid
            if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
                for line in content.lines() {
                    if line.starts_with("TracerPid:") {
                        let tracer_pid = line.split_whitespace().nth(1).unwrap_or("0");
                        if tracer_pid != "0" {
                            eprintln!("[保护系统] 定期检查发现跟踪进程: {}", tracer_pid);
                            return true;
                        }
                        break;
                    }
                }
            }
        }

        false
    }

    /// 获取保护状态
    #[allow(dead_code)]
    pub fn get_protection_status(&self) -> ProtectionStatus {
        ProtectionStatus {
            activated: self.is_activated,
            debugger_detected: *self.debugger_detected.lock().unwrap(),
            uptime_seconds: self.last_heartbeat.lock().unwrap()
                .duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }

    /// 停止保护系统
    pub fn shutdown(&mut self) {
        if self.is_activated {
            //println!("[保护系统] 正在关闭保护系统...");
            self.is_activated = false;

            // 在实际应用中，这里会清理资源
            // 由于监控线程是守护线程，它会自动退出

            //println!("[保护系统] 保护系统已关闭");
        }
    }
}

impl Drop for ProtectionManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 保护状态信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProtectionStatus {
    pub activated: bool,
    pub debugger_detected: bool,
    pub uptime_seconds: u64,
}

/// Compute HMAC-SHA256 over multiple critical code sections.
/// Uses function pointers as anchors to hash 4096 bytes from each.
#[inline(never)]
fn compute_integrity_hmac(key: &[u8; 32]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");

    unsafe {
        // Hash multiple function entry points for broader coverage
        let anchors: [*const u8; 3] = [
            enable_global_protection as *const () as *const u8,
            compute_integrity_hmac as *const () as *const u8,
            ProtectionManager::enable_protection as *const () as *const u8,
        ];

        for anchor in &anchors {
            let code_bytes = std::slice::from_raw_parts(*anchor, 4096);
            mac.update(code_bytes);
        }
    }

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// 全局保护系统实例
lazy_static::lazy_static! {
    static ref GLOBAL_PROTECTION: Mutex<ProtectionManager> =
        Mutex::new(ProtectionManager::new());
}

/// 全局函数：一键开启所有保护
#[allow(dead_code)]
pub fn enable_global_protection() -> Result<(), String> {
    GLOBAL_PROTECTION.lock().unwrap().enable_protection()
}

/// 全局函数：获取保护状态
#[allow(dead_code)]
pub fn get_global_protection_status() -> ProtectionStatus {
    GLOBAL_PROTECTION.lock().unwrap().get_protection_status()
}

// ============================================================
// 统一保护入口：一次调用启用所有防护
// ============================================================

/// 统一启用所有保护措施。
/// 在认证成功后调用一次，按顺序启用：
///   1. 反调试 + 反Hook + 内存保护 + 完整性校验 + 监控线程 + 反Attach
///   2. 禁止进程 dump (Linux PR_SET_DUMPABLE)
///   3. 内存蜜罐 + PAGE_GUARD 监控
///   4. JNI 层反 Attach（禁用 AttachListener）
///   5. 模块基线快照（检测注入）
///
/// 调用方只需：
/// ```ignore
/// protection::activate_all_protections(&env)?;
/// ```
pub fn activate_all_protections(env: &jni::JNIEnv) -> Result<(), String> {
    // 0. Agent 检测（最先执行，检测到立即拒绝）
    crate::debug_log!("[SkyLicense] [Protection] Step 0: Agent detection...");
    crate::agent_detect::initial_agent_check(env)?;
    crate::debug_log!("[SkyLicense] [Protection] Step 0: Agent detection OK");

    // 1. 核心保护系统（反调试、反Hook、内存保护页、完整性校验、监控线程、反Attach线程检测）
    crate::debug_log!("[SkyLicense] [Protection] Step 1: Core protection (anti-debug, anti-hook, memory guards)...");
    enable_global_protection()?;
    crate::debug_log!("[SkyLicense] [Protection] Step 1: Core protection OK");

    // 2. 禁止进程 dump（Linux: 阻止非 root 读取 /proc/pid/mem）
    crate::debug_log!("[SkyLicense] [Protection] Step 2: Disable process dump...");
    crate::mem_protect::disable_process_dump();
    crate::debug_log!("[SkyLicense] [Protection] Step 2: Disable process dump OK");

    // 3. 内存蜜罐 + PAGE_GUARD 异常监控（检测内存扫描工具）
    crate::debug_log!("[SkyLicense] [Protection] Step 3: Memory honeypot + PAGE_GUARD monitor...");
    crate::anti_dump::start_memory_monitor();
    crate::debug_log!("[SkyLicense] [Protection] Step 3: Memory monitor started OK");

    // 4. JNI 层反 Attach：通过 JNI 禁用 JVM 的 AttachListener
    crate::debug_log!("[SkyLicense] [Protection] Step 4: JNI anti-attach (disable AttachListener)...");
    crate::anti_attach::disable_attach_via_jni(env);
    crate::debug_log!("[SkyLicense] [Protection] Step 4: JNI anti-attach OK");

    // 5. 模块基线快照：记录当前已加载模块，后续检测新注入的 DLL
    crate::debug_log!("[SkyLicense] [Protection] Step 5: Module baseline snapshot...");
    crate::anti_attach::capture_module_baseline();
    crate::debug_log!("[SkyLicense] [Protection] Step 5: Module baseline OK");

    // 5.5. 线程基线快照（Windows: 记录当前所有线程，用于安全识别 Attach Listener）
    #[cfg(target_os = "windows")]
    {
        crate::debug_log!("[SkyLicense] [Protection] Step 5.5: Thread baseline snapshot...");
        crate::anti_attach::capture_thread_baseline();
        crate::debug_log!("[SkyLicense] [Protection] Step 5.5: Thread baseline OK");
    }

    // 6. 启动反 Attach 守护线程（持续监控 Attach 尝试）
    crate::debug_log!("[SkyLicense] [Protection] Step 6: Anti-attach guard thread...");
    let _guard = crate::anti_attach::AntiAttachGuard::start();
    std::mem::forget(_guard);
    crate::debug_log!("[SkyLicense] [Protection] Step 6: Anti-attach guard started OK");

    // 7. 启动 Agent 后台监控线程（定期重新检测运行时注入的 agent）
    crate::debug_log!("[SkyLicense] [Protection] Step 7: Agent monitor thread...");
    if let Ok(vm) = env.get_java_vm() {
        crate::agent_detect::start_agent_monitor(vm);
    }
    crate::debug_log!("[SkyLicense] [Protection] Step 7: Agent monitor started OK");
    crate::debug_log!("[SkyLicense] [Protection] All protections activated successfully");

    Ok(())
}