//! Low-overhead anti-dump signals.
//!
//! Honeypot pages are intentionally treated as heuristic evidence. External
//! process-memory APIs do not guarantee delivery of an exception to the target,
//! so page guards must never be the sole authorization boundary.

#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::sync::OnceLock;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
#[cfg(target_os = "windows")]
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_GUARD, PAGE_READWRITE};

#[cfg(target_os = "windows")]
static VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "windows")]
static HONEYPOT_PAGES: OnceLock<Vec<usize>> = OnceLock::new();
#[cfg(target_os = "windows")]
static VEH_HANDLE: OnceLock<usize> = OnceLock::new();

pub struct MemoryHoneypot {
    #[cfg(target_os = "windows")]
    trap_pages: Vec<*mut std::ffi::c_void>,
    #[cfg(target_os = "linux")]
    trap_pages: Vec<(*mut std::ffi::c_void, usize)>,
}

impl MemoryHoneypot {
    pub fn new(count: usize) -> Self {
        let mut trap_pages = Vec::new();

        #[cfg(target_os = "windows")]
        unsafe {
            for _ in 0..count {
                let page = VirtualAlloc(
                    std::ptr::null_mut(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if page.is_null() {
                    continue;
                }

                let fake_data = generate_fake_method_data();
                std::ptr::copy_nonoverlapping(
                    fake_data.as_ptr(),
                    page.cast::<u8>(),
                    fake_data.len().min(4096),
                );
                let mut old_protect = 0;
                if VirtualProtect(page, 4096, PAGE_GUARD | PAGE_READWRITE, &mut old_protect) == 0 {
                    VirtualFree(page, 0, MEM_RELEASE);
                    continue;
                }
                trap_pages.push(page);
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
                if page == libc::MAP_FAILED {
                    continue;
                }

                let fake_data = generate_fake_method_data();
                std::ptr::copy_nonoverlapping(
                    fake_data.as_ptr(),
                    page.cast::<u8>(),
                    fake_data.len().min(4096),
                );
                if libc::mprotect(page, 4096, libc::PROT_NONE) != 0 {
                    libc::munmap(page, 4096);
                    continue;
                }
                trap_pages.push((page, 4096));
            }
        }

        Self { trap_pages }
    }
}

impl Drop for MemoryHoneypot {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            for page in self.trap_pages.drain(..) {
                VirtualFree(page, 0, MEM_RELEASE);
            }
        }

        #[cfg(target_os = "linux")]
        unsafe {
            for (page, size) in self.trap_pages.drain(..) {
                libc::munmap(page, size);
            }
        }
    }
}

fn generate_fake_method_data() -> Vec<u8> {
    const CLASSES: &[&str] = &[
        "java/lang/Object",
        "java/lang/String",
        "java/util/HashMap",
        "net/minecraft/server/MinecraftServer",
        "org/bukkit/plugin/Plugin",
        "cn/sky/license/AuthManager",
        "io/netty/channel/Channel",
    ];
    const METHODS: &[&str] = &[
        "getInstance",
        "toString",
        "hashCode",
        "equals",
        "notify",
        "getClass",
        "clone",
        "finalize",
        "wait",
        "run",
    ];
    const DESCRIPTORS: &[&str] = &[
        "()V",
        "()Ljava/lang/String;",
        "(I)V",
        "(Ljava/lang/Object;)Z",
        "()I",
        "(II)I",
        "([B)V",
        "(Ljava/lang/String;)V",
    ];

    let mut data = Vec::with_capacity(4096);
    for _ in 0..20 {
        let class = CLASSES[rand::random::<usize>() % CLASSES.len()];
        let method = METHODS[rand::random::<usize>() % METHODS.len()];
        let descriptor = DESCRIPTORS[rand::random::<usize>() % DESCRIPTORS.len()];
        data.extend_from_slice(class.as_bytes());
        data.push(0);
        data.extend_from_slice(method.as_bytes());
        data.push(0);
        data.extend_from_slice(descriptor.as_bytes());
        data.push(0);
        for _ in 0..((rand::random::<usize>() % 24) + 8) {
            data.push(rand::random());
        }
    }
    data
}

#[cfg(target_os = "windows")]
pub fn start_memory_monitor() -> Result<(), String> {
    crate::security::spawn_ready_monitor(
        "sky-memory-monitor",
        Duration::from_secs(5),
        |stop, ready| {
            let honeypot = MemoryHoneypot::new(8);
            if honeypot.trap_pages.is_empty() {
                let _ = ready.send(Err(
                    "no Windows guard-page honeypots were allocated".to_string()
                ));
                return;
            }
            let pages = honeypot
                .trap_pages
                .iter()
                .map(|page| *page as usize)
                .collect();
            if HONEYPOT_PAGES.set(pages).is_err() {
                let _ = ready.send(Err("honeypot pages were already initialized".to_string()));
                return;
            }

            let handler = unsafe {
                winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(guard_page_handler))
            };
            if handler.is_null() {
                let _ = ready.send(Err("AddVectoredExceptionHandler failed".to_string()));
                return;
            }
            if VEH_HANDLE.set(handler as usize).is_err() {
                unsafe {
                    winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(handler);
                }
                let _ = ready.send(Err(
                    "vectored exception handler was already initialized".to_string()
                ));
                return;
            }
            if ready.send(Ok(())).is_err() {
                unsafe {
                    winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(handler);
                }
                return;
            }

            while !stop.load(Ordering::Acquire) {
                if crate::security::wait_for_stop(&stop, Duration::from_millis(500)) {
                    break;
                }
                rearm_honeypots();

                let violations = VIOLATION_COUNT.swap(0, Ordering::AcqRel);
                if violations >= 3 {
                    crate::security::submit(crate::security::SecurityEvidence::new(
                        crate::security::EvidenceKind::MemoryAccess,
                        crate::security::EvidenceConfidence::High,
                        "memory.guard",
                        format!("{violations} guarded honeypot accesses"),
                    ));
                    break;
                }

                // This detector currently checks only the monitor thread. Treat it
                // as a risk signal until all relevant JVM threads are inspected.
                if crate::mem_protect::detect_hardware_breakpoints() {
                    crate::security::submit(crate::security::SecurityEvidence::new(
                        crate::security::EvidenceKind::Debugger,
                        crate::security::EvidenceConfidence::Medium,
                        "memory.debug_registers",
                        "hardware debug register detected on monitor thread",
                    ));
                }
            }

            if let Some(handle) = VEH_HANDLE.get() {
                unsafe {
                    winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(*handle as *mut _);
                }
            }
            drop(honeypot);
        },
    )
}

#[cfg(target_os = "linux")]
pub fn start_memory_monitor() -> Result<(), String> {
    crate::security::spawn_ready_monitor(
        "sky-memory-monitor",
        Duration::from_secs(5),
        |stop, ready| {
            let honeypot = MemoryHoneypot::new(8);
            if honeypot.trap_pages.is_empty() {
                let _ = ready.send(Err(
                    "no Linux PROT_NONE honeypot mappings were allocated".to_string()
                ));
                return;
            }
            let Some(initial_tracer_pid) = linux_tracer_pid() else {
                let _ = ready.send(Err("unable to read /proc/self/status".to_string()));
                return;
            };
            if initial_tracer_pid != 0 {
                crate::security::submit(crate::security::SecurityEvidence::new(
                    crate::security::EvidenceKind::Debugger,
                    crate::security::EvidenceConfidence::High,
                    "linux.tracer_pid",
                    format!("TracerPid is {initial_tracer_pid}"),
                ));
                if crate::security::state().is_terminal() {
                    let _ = ready.send(Err("a Linux tracer is already attached".to_string()));
                    return;
                }
            }
            if ready.send(Ok(())).is_err() {
                return;
            }

            while !stop.load(Ordering::Acquire) {
                if crate::security::wait_for_stop(&stop, Duration::from_secs(2)) {
                    break;
                }
                match linux_tracer_pid() {
                    Some(tracer_pid) if tracer_pid != 0 => {
                        crate::security::submit(crate::security::SecurityEvidence::new(
                            crate::security::EvidenceKind::Debugger,
                            crate::security::EvidenceConfidence::High,
                            "linux.tracer_pid",
                            format!("TracerPid is {tracer_pid}"),
                        ));
                        break;
                    }
                    Some(_) => {}
                    None => {
                        let evidence = crate::security::SecurityEvidence::new(
                            crate::security::EvidenceKind::RuntimeFailure,
                            crate::security::EvidenceConfidence::High,
                            "linux.tracer_monitor",
                            "lost access to /proc/self/status while the session was active",
                        );
                        if crate::security::policy().profile
                            == crate::security::SecurityProfile::Compatible
                        {
                            crate::security::report(evidence);
                        } else {
                            crate::security::fail_closed(evidence);
                        }
                        break;
                    }
                }
            }
        },
    )
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn start_memory_monitor() -> Result<(), String> {
    Err("memory monitoring is unsupported on this operating system".to_string())
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
fn rearm_honeypots() {
    if let Some(pages) = HONEYPOT_PAGES.get() {
        for &page in pages {
            let mut old_protect = 0;
            unsafe {
                VirtualProtect(
                    page as *mut _,
                    4096,
                    PAGE_GUARD | PAGE_READWRITE,
                    &mut old_protect,
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn guard_page_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = unsafe { (*exception_info).ExceptionRecord };
    if record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let is_guard = unsafe { (*record).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION };
    let has_address = unsafe { (*record).NumberParameters >= 2 };
    if !is_guard || !has_address {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let accessed = unsafe { (*record).ExceptionInformation[1] };
    let belongs_to_honeypot = HONEYPOT_PAGES
        .get()
        .map(|pages| {
            pages
                .iter()
                .any(|page| accessed >= *page && accessed < page.saturating_add(4096))
        })
        .unwrap_or(false);
    if !belongs_to_honeypot {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
    // Guard is re-armed by the monitor after this instruction completes.
    EXCEPTION_CONTINUE_EXECUTION
}
