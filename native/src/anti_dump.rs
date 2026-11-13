/// Anti-dump and memory access monitoring
/// Detects attempts to read process memory from external tools

#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect, VirtualQuery};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE,
};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Counter for detected memory access violations
static VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Addresses of honeypot pages for re-arming PAGE_GUARD after trigger
#[cfg(target_os = "windows")]
static HONEYPOT_PAGES: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

/// Honeypot pages - allocated memory that looks like it contains the method map
/// but is actually a trap. Any access triggers detection.
pub struct MemoryHoneypot {
    #[cfg(target_os = "windows")]
    pub(crate) trap_pages: Vec<*mut std::ffi::c_void>,
    #[cfg(target_os = "linux")]
    pub(crate) trap_pages: Vec<(*mut std::ffi::c_void, usize)>,
}

impl MemoryHoneypot {
    /// Create honeypot pages that look like they contain valuable data
    pub fn new(count: usize) -> Self {
        let mut trap_pages = Vec::new();

        #[cfg(target_os = "windows")]
        unsafe {
            for _ in 0..count {
                // Allocate a page
                let page = VirtualAlloc(
                    std::ptr::null_mut(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );

                if !page.is_null() {
                    // Fill with fake data that looks like method info
                    let fake_data = generate_fake_method_data();
                    std::ptr::copy_nonoverlapping(
                        fake_data.as_ptr(),
                        page as *mut u8,
                        fake_data.len().min(4096),
                    );

                    // Set PAGE_GUARD - any access will trigger an exception
                    let mut old_protect = 0u32;
                    VirtualProtect(page, 4096, PAGE_GUARD | PAGE_READWRITE, &mut old_protect);

                    trap_pages.push(page);
                }
            }
        }

        #[cfg(target_os = "linux")]
        unsafe {
            for _ in 0..count {
                let page = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                if page != libc::MAP_FAILED {
                    let fake_data = generate_fake_method_data();
                    std::ptr::copy_nonoverlapping(
                        fake_data.as_ptr(),
                        page as *mut u8,
                        fake_data.len().min(4096),
                    );

                    // Make inaccessible - any read attempt from dumper will fail
                    libc::mprotect(page, 4096, libc::PROT_NONE);

                    trap_pages.push((page, 4096));
                }
            }
        }

        Self { trap_pages }
    }
}

/// Generate fake data that looks like a method map entry to confuse memory scanners
fn generate_fake_method_data() -> Vec<u8> {
    let fake_classes = [
        "java/lang/Object", "java/lang/String", "java/util/HashMap",
        "net/minecraft/server/MinecraftServer", "org/bukkit/plugin/Plugin",
        "cn/sky/license/AuthManager", "io/netty/channel/Channel",
    ];
    let fake_methods = [
        "getInstance", "toString", "hashCode", "equals", "notify",
        "getClass", "clone", "finalize", "wait", "run",
    ];
    let fake_descs = [
        "()V", "()Ljava/lang/String;", "(I)V", "(Ljava/lang/Object;)Z",
        "()I", "(II)I", "([B)V", "(Ljava/lang/String;)V",
    ];

    let mut data = Vec::with_capacity(4096);

    for _ in 0..20 {
        let class_idx = (rand::random::<usize>()) % fake_classes.len();
        let method_idx = (rand::random::<usize>()) % fake_methods.len();
        let desc_idx = (rand::random::<usize>()) % fake_descs.len();
        let class = fake_classes[class_idx];
        let method = fake_methods[method_idx];
        let desc = fake_descs[desc_idx];

        data.extend_from_slice(class.as_bytes());
        data.push(0);
        data.extend_from_slice(method.as_bytes());
        data.push(0);
        data.extend_from_slice(desc.as_bytes());
        data.push(0);
        // Add some random padding
        let pad_count = (rand::random::<usize>() % 24) + 8;
        for _ in 0..pad_count {
            data.push(rand::random::<u8>());
        }
    }

    data
}

/// Monitor for ReadProcessMemory calls targeting our process
/// Works by periodically checking if our guard pages have been accessed
#[cfg(target_os = "windows")]
pub fn start_memory_monitor() {
    std::thread::spawn(|| {
        // Create honeypot pages
        let honeypot = MemoryHoneypot::new(8);

        // Store page addresses for re-arming in VEH handler
        let page_addrs: Vec<usize> = honeypot.trap_pages.iter().map(|p| *p as usize).collect();
        let _ = HONEYPOT_PAGES.set(Mutex::new(page_addrs));

        // Install vectored exception handler for PAGE_GUARD violations
        unsafe {
            use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
            AddVectoredExceptionHandler(1, Some(guard_page_handler));
        }

        // Periodically check for memory scanning indicators
        loop {
            std::thread::sleep(Duration::from_millis(500));

            // Use decaying violation tracker
            if crate::mem_protect::add_violation(0) {
                // Threshold exceeded — exit
                crate::debug_log!("[SkyLicense] !!! Memory violation threshold exceeded — exiting !!!");
                unsafe { crate::corrupt_state(); }
                let delay = (rand::random::<u64>() % 3000) + 500;
                std::thread::sleep(Duration::from_millis(delay));
                std::process::exit(0);
            }

            // Check for common memory dumping tools
            //check_for_dump_tools();

            // Periodic hardware breakpoint check
            if crate::mem_protect::detect_hardware_breakpoints() {
                crate::debug_log!("[SkyLicense] !!! Hardware breakpoint detected — exiting !!!");
                unsafe { crate::corrupt_state(); }
                let delay = (rand::random::<u64>() % 2000) + 500;
                std::thread::sleep(Duration::from_millis(delay));
                std::process::exit(0);
            }

            // Periodic handle monitoring (every 5s = 10 ticks)
            static TICK: AtomicU64 = AtomicU64::new(0);
            let tick = TICK.fetch_add(1, Ordering::Relaxed);
            if tick % 10 == 0 {
                if crate::mem_protect::detect_external_memory_handles() {
                    let _ = crate::mem_protect::add_violation(2);
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn start_memory_monitor() {
    std::thread::spawn(|| {
        let _honeypot = MemoryHoneypot::new(8);

        loop {
            std::thread::sleep(Duration::from_secs(2));

            // Check /proc/self/status for memory access from other processes
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid = line.split_whitespace().nth(1).unwrap_or("0");
                        if pid != "0" {
                            crate::debug_log!("[SkyLicense] !!! TracerPid detected: {} — exiting !!!", pid);
                            unsafe { crate::corrupt_state(); }
                            std::thread::sleep(Duration::from_millis(
                                (rand::random::<u64>() % 2000) + 500
                            ));
                            std::process::exit(0);
                        }
                    }
                }
            }

            // Check /proc/self/mem access time (unreliable with noatime, but free)
            if let Ok(metadata) = std::fs::metadata("/proc/self/mem") {
                if let Ok(accessed) = metadata.accessed() {
                    let now = SystemTime::now();
                    if let Ok(diff) = now.duration_since(accessed) {
                        if diff < Duration::from_secs(5) {
                            if crate::mem_protect::add_violation(1) {
                                unsafe { crate::corrupt_state(); }
                                std::thread::sleep(Duration::from_millis(
                                    (rand::random::<u64>() % 2000) + 500
                                ));
                                std::process::exit(0);
                            }
                        }
                    }
                }
            }

            //check_for_dump_tools();
        }
    });
}

/// Vectored exception handler for Windows PAGE_GUARD violations
#[cfg(target_os = "windows")]
unsafe extern "system" fn guard_page_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    unsafe {
        let record = (*exception_info).ExceptionRecord;
        if record.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (*record).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION {
            // Someone accessed our guard page — likely a memory scanner
            // Use the decaying violation tracker
            if crate::mem_protect::add_violation(1) {
                // Threshold exceeded — take action
                crate::corrupt_state();
            }

            // Re-arm PAGE_GUARD on all honeypot pages (PAGE_GUARD is one-shot)
            if let Some(pages) = HONEYPOT_PAGES.get() {
                if let Ok(page_list) = pages.lock() {
                    for &page_addr in page_list.iter() {
                        let mut old_protect = 0u32;
                        VirtualProtect(
                            page_addr as *mut _,
                            4096,
                            PAGE_GUARD | PAGE_READWRITE,
                            &mut old_protect,
                        );
                    }
                }
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// Check for common memory dumping tools
fn check_for_dump_tools() {
    use sysinfo::{ProcessExt, System, SystemExt, ProcessRefreshKind, RefreshKind};

    // Lightweight refresh — only processes, not CPU/memory/disks
    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new())
    );
    system.refresh_processes();

    let dump_tools = [
        "processhacker", "procexp", "dumper", "memdump",
        "procdump", "minidump", "ce-", "cheatengine",
        "scanmem", "gameconqueror", "pmemdump",
        "dnspy", "binaryninja", "ghidra", "ghidrarun",
        "x64dbg", "jvisualvm", "visualvm", "jconsole",
        "pin", "drrun", "dynamorio",
    ];

    for process in system.processes().values() {
        let name = process.name().to_lowercase();
        for tool in &dump_tools {
            if name.contains(tool) {
                let _ = crate::mem_protect::add_violation(2);
                return;
            }
        }
    }
}
