//! Runtime code anchors used by the in-memory key hierarchy.
//!
//! Each public anchor is the trusted value captured during initialization.
//! `runtime_anchors_match` recomputes the live values for explicit tamper
//! detection; hot-path key derivation uses the trusted value and therefore does
//! not turn a detected patch into an uncontrolled pointer or decryption crash.

use hmac::{Hmac, Mac};
use obfuse::obfuse;
use sha2::Sha256;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

type HmacSha256 = Hmac<Sha256>;
const ANCHOR_REGION_SIZE: usize = 512;
static ANCHOR_READ_FAILURE: AtomicBool = AtomicBool::new(false);

fn hash_code_region(function: *const u8, hmac_key: &[u8]) -> [u8; 32] {
    let Some(code) = bounded_executable_code_region(function, ANCHOR_REGION_SIZE) else {
        ANCHOR_READ_FAILURE.store(true, Ordering::Release);
        return [0u8; 32];
    };
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(hmac_key) else {
        return [0u8; 32];
    };
    mac.update(&(code.len() as u64).to_be_bytes());
    mac.update(code);
    mac.finalize().into_bytes().into()
}

/// Return only the portion of an executable mapping that is safe to inspect.
/// All callers that read native code must use this helper instead of assuming
/// a fixed number of bytes remains before the next unmapped page.
pub(crate) fn bounded_executable_code_region(
    function: *const u8,
    requested: usize,
) -> Option<&'static [u8]> {
    let length = executable_region_length(function, requested)?;
    // The loaded library remains mapped for the lifetime of this process. The
    // OS query above proves the range is committed and readable/executable.
    Some(unsafe { std::slice::from_raw_parts(function, length) })
}

#[cfg(target_os = "windows")]
fn executable_region_length(function: *const u8, requested: usize) -> Option<usize> {
    use std::mem::{size_of, zeroed};
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    };

    if function.is_null() || requested == 0 {
        return None;
    }
    let mut information: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
    let queried = unsafe {
        VirtualQuery(
            function as *const _,
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried != size_of::<MEMORY_BASIC_INFORMATION>()
        || information.State != MEM_COMMIT
        || information.Protect & PAGE_GUARD != 0
        || information.Protect & PAGE_NOACCESS != 0
    {
        return None;
    }

    let protection = information.Protect & 0xff;
    if !matches!(
        protection,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    ) {
        return None;
    }

    let address = function as usize;
    let base = information.BaseAddress as usize;
    let end = base.checked_add(information.RegionSize)?;
    if address < base || address >= end {
        return None;
    }
    Some((end - address).min(requested))
}

#[cfg(target_os = "linux")]
fn executable_region_length(function: *const u8, requested: usize) -> Option<usize> {
    if function.is_null() || requested == 0 {
        return None;
    }
    let address = function as usize;
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
        let permission_bytes = permissions.as_bytes();
        if permission_bytes.len() < 3 || permission_bytes[0] != b'r' || permission_bytes[2] != b'x'
        {
            continue;
        }
        let Some((start_text, end_text)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start_text, 16),
            usize::from_str_radix(end_text, 16),
        ) else {
            continue;
        };
        if address >= start && address < end {
            return Some((end - address).min(requested));
        }
    }
    None
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn executable_region_length(_function: *const u8, _requested: usize) -> Option<usize> {
    None
}

fn compute_anchor_1() -> [u8; 32] {
    let key = obfuse!("A1k9Xm2pQ7wR4vLn");
    hash_code_region(
        crate::dispatch_cached as *const () as *const u8,
        key.as_bytes(),
    )
}

fn compute_anchor_2() -> [u8; 32] {
    let key = obfuse!("B3jF8sNcY6tH1wZq");
    hash_code_region(
        crate::secure_map::encrypted_map_get_ptr() as *const u8,
        key.as_bytes(),
    )
}

fn compute_anchor_3() -> [u8; 32] {
    let key = obfuse!("C5gD0rKe8mP2xUaW");
    hash_code_region(
        crate::mem_protect::xor_encrypt_string as *const () as *const u8,
        key.as_bytes(),
    )
}

fn compute_anchor_4() -> [u8; 32] {
    let key = obfuse!("D7iL4oSb1nV9yJcF");
    hash_code_region(
        crate::heartbeat::heartbeat_send_ptr() as *const u8,
        key.as_bytes(),
    )
}

fn compute_anchor_5() -> [u8; 32] {
    let key = obfuse!("E2fA6uMh3qT8wXpG");
    hash_code_region(
        crate::secure_map::hash_lookup_key_ptr() as *const u8,
        key.as_bytes(),
    )
}

fn compute_anchor_6() -> [u8; 32] {
    let key = obfuse!("F9cR1vOj5kB7zNdI");
    hash_code_region(
        crate::encrypt::decrypt_resource_ptr() as *const u8,
        key.as_bytes(),
    )
}

macro_rules! trusted_anchor {
    ($name:ident, $compute:ident, $slot:ident) => {
        #[inline(never)]
        pub fn $name() -> [u8; 32] {
            static $slot: OnceLock<[u8; 32]> = OnceLock::new();
            *$slot.get_or_init($compute)
        }
    };
}

trusted_anchor!(anchor_1, compute_anchor_1, ANCHOR_1);
trusted_anchor!(anchor_2, compute_anchor_2, ANCHOR_2);
trusted_anchor!(anchor_3, compute_anchor_3, ANCHOR_3);
trusted_anchor!(anchor_4, compute_anchor_4, ANCHOR_4);
trusted_anchor!(anchor_5, compute_anchor_5, ANCHOR_5);
trusted_anchor!(anchor_6, compute_anchor_6, ANCHOR_6);

pub fn runtime_anchors_match() -> bool {
    if ANCHOR_READ_FAILURE.load(Ordering::Acquire) {
        return false;
    }
    let matches = constant_time_equal(&anchor_1(), &compute_anchor_1())
        && constant_time_equal(&anchor_2(), &compute_anchor_2())
        && constant_time_equal(&anchor_3(), &compute_anchor_3())
        && constant_time_equal(&anchor_4(), &compute_anchor_4())
        && constant_time_equal(&anchor_5(), &compute_anchor_5())
        && constant_time_equal(&anchor_6(), &compute_anchor_6());
    matches && !ANCHOR_READ_FAILURE.load(Ordering::Acquire)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[inline(never)]
pub fn derive_effective_key(base_key: &[u8; 32], anchor: &[u8; 32]) -> [u8; 32] {
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(base_key) else {
        return [0u8; 32];
    };
    mac.update(anchor);
    mac.finalize().into_bytes().into()
}

#[inline(never)]
pub fn get_pointer_anchor_adjustment() -> usize {
    static ADJUSTMENT: OnceLock<usize> = OnceLock::new();
    *ADJUSTMENT.get_or_init(|| {
        let anchor = anchor_1();
        let raw = u32::from_ne_bytes([anchor[0], anchor[1], anchor[2], anchor[3]]) as usize;
        raw & 0x0000_0000_FFFF_FFFF
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_distinguishes_values() {
        assert!(constant_time_equal(&[7; 32], &[7; 32]));
        assert!(!constant_time_equal(&[7; 32], &[8; 32]));
    }

    #[test]
    fn runtime_anchors_are_stable_without_code_changes() {
        let _ = anchor_1();
        let _ = anchor_2();
        let _ = anchor_3();
        let _ = anchor_4();
        let _ = anchor_5();
        let _ = anchor_6();
        assert!(runtime_anchors_match());
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    #[test]
    fn anchor_region_is_bounded_to_an_executable_mapping() {
        let length = executable_region_length(
            compute_anchor_1 as *const () as *const u8,
            ANCHOR_REGION_SIZE,
        );
        assert!(length.is_some_and(|value| (1..=ANCHOR_REGION_SIZE).contains(&value)));
    }
}
