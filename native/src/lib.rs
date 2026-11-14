#![allow(non_snake_case)] // The cdylib/JNI ABI name is intentionally stable.

#[cfg(any(
    all(feature = "security-compatible", feature = "security-balanced"),
    all(feature = "security-compatible", feature = "security-strict"),
    all(feature = "security-balanced", feature = "security-strict")
))]
compile_error!("exactly one security profile feature must be enabled");

#[cfg(not(any(
    feature = "security-compatible",
    feature = "security-balanced",
    feature = "security-strict"
)))]
compile_error!("one security profile feature must be enabled");

#[cfg(all(feature = "insecure-plaintext", not(feature = "security-compatible")))]
compile_error!("insecure-plaintext is permitted only with security-compatible");

extern crate core;

#[cfg(test)]
mod test_mem_protect;

pub mod agent_detect;
pub mod anti_attach;
pub mod anti_dump;
pub mod artifact_integrity;
pub mod bytebuf;
pub mod challenge;
pub mod encrypt;
pub mod heartbeat;
pub mod hwid;
pub mod integrity;
pub mod mem_protect;
mod model;
pub mod obfuscate;
mod protection;
pub mod secure_map;
pub mod security;
pub mod tls;
mod utils;

use crate::challenge::{ChallengeResponse, KeyExchange};
use crate::encrypt::EncryptUtil;
use crate::model::Resource;
use crate::obfuscate::*;
use crate::secure_map::EncryptedMethodMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytebuf::ByteBuf;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue, JValueOwned};
use jni::signature::ReturnType;
use jni::sys::{_jobject, JNI_ERR, JNI_VERSION_1_8, jint, jmethodID, jobject};
use obfuse::obfuse;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Runtime;
use zeroize::{Zeroize, Zeroizing};

/// 全局调试开关。设为 true 时输出所有调试信息。
pub static DEBUG: AtomicBool = AtomicBool::new(false);

/// 调试输出宏：仅在 DEBUG=true 时打印
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}

/// The method map is stored ENCRYPTED in memory at all times.
/// Individual entries are decrypted only during the JNI call and zeroized immediately after.
static ENCRYPTED_MAP: OnceLock<Mutex<EncryptedMethodMap>> = OnceLock::new();
static SESSION_LEASE: OnceLock<std::sync::Arc<heartbeat::SessionLease>> = OnceLock::new();

/// Cached decoded lookup keys: encrypted_base64 → XOR-encrypted decoded string.
/// Each unique encrypted key is authenticated and decrypted exactly once, then
/// the result is XOR-encrypted and cached. Plaintext never persists.
type EncryptedCacheEntry = (Vec<u8>, u64);
type DecodedKeyCache = RwLock<FxHashMap<String, EncryptedCacheEntry>>;
static DECODED_KEY_CACHE: OnceLock<DecodedKeyCache> = OnceLock::new();

/// Pre-resolved jmethodID + jclass cache with RwLock.
/// Multiple readers (hot path) never block each other.
/// Only the first call per method takes a write lock.
static METHOD_CACHE: OnceLock<RwLock<FxHashMap<String, CachedMethod>>> = OnceLock::new();
const MAX_RESOURCE_BYTES: usize = 256 * 1024 * 1024;
const AUTH_PROTOCOL_VERSION: i32 = 4;
const CHALLENGE_RESPONSE_MAGIC: i32 = 0x534B_4352;
const DELIVERY_ACK_MAGIC: i32 = 0x534B_4441;
const DELIVERY_ACK_SUCCESS: u8 = 0x01;
const DELIVERY_ACK_CONFIRMED: u8 = 0x01;
const DELIVERY_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const AUTHENTICATION_IDLE: u8 = 0;
const AUTHENTICATION_IN_PROGRESS: u8 = 1;
const AUTHENTICATION_RESOURCE_RELEASED: u8 = 2;
const AUTHENTICATION_INITIALIZED: u8 = 3;

/// The native bridge owns one protected resource session per JVM process.
/// Serializing the transition before any network I/O prevents two concurrent
/// Java callers from both consuming a server authorization and then racing on
/// the process-global encrypted method map.
static AUTHENTICATION_STATE: AtomicU8 = AtomicU8::new(AUTHENTICATION_IDLE);

struct AuthenticationAttempt {
    state: &'static AtomicU8,
}

impl AuthenticationAttempt {
    fn begin() -> Result<Self, &'static str> {
        match AUTHENTICATION_STATE.compare_exchange(
            AUTHENTICATION_IDLE,
            AUTHENTICATION_IN_PROGRESS,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(Self {
                state: &AUTHENTICATION_STATE,
            }),
            Err(AUTHENTICATION_IN_PROGRESS) => Err("AUTHENTICATION_IN_PROGRESS"),
            Err(AUTHENTICATION_RESOURCE_RELEASED | AUTHENTICATION_INITIALIZED) => {
                Err("SESSION_ALREADY_INITIALIZED")
            }
            Err(_) => Err("SESSION_REVOKED"),
        }
    }

    fn mark_resource_released(&self) -> bool {
        self.state
            .compare_exchange(
                AUTHENTICATION_IN_PROGRESS,
                AUTHENTICATION_RESOURCE_RELEASED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn commit(self) {
        self.state
            .store(AUTHENTICATION_INITIALIZED, Ordering::Release);
    }
}

impl Drop for AuthenticationAttempt {
    fn drop(&mut self) {
        match self.state.load(Ordering::Acquire) {
            AUTHENTICATION_IN_PROGRESS => {
                let _ = self.state.compare_exchange(
                    AUTHENTICATION_IN_PROGRESS,
                    AUTHENTICATION_IDLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            AUTHENTICATION_RESOURCE_RELEASED => {
                // The server commits binding/quota immediately before writing
                // the resource. Any later local failure is non-retryable in
                // this process and must destroy the local session keys.
                security::fail_closed(security::SecurityEvidence::new(
                    security::EvidenceKind::RuntimeFailure,
                    security::EvidenceConfidence::Certain,
                    "authentication.resource_release_failure",
                    "protected resource was released but initialization did not complete",
                ));
            }
            _ => {}
        }
    }
}

/// Establish immutable code anchors and reject a debugger/known inline hook
/// before any authentication request or server-delivered secret is processed.
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jint {
    if let Err(detail) =
        artifact_integrity::verify_current_library(security::policy().require_signed_manifest)
    {
        security::tamper(security::SecurityEvidence::new(
            security::EvidenceKind::CodeIntegrity,
            security::EvidenceConfidence::Certain,
            "jni.onload.artifact_manifest",
            detail,
        ));
        return JNI_ERR;
    }
    if let Err(detail) = protection::prepare_early_environment() {
        security::fail_closed(security::SecurityEvidence::new(
            security::EvidenceKind::RuntimeFailure,
            security::EvidenceConfidence::High,
            "jni.onload.early_environment",
            detail,
        ));
        return JNI_ERR;
    }
    match protection::run_early_load_checks() {
        Ok(()) => JNI_VERSION_1_8,
        Err(evidence) => {
            security::submit(evidence);
            if security::state().is_terminal() {
                JNI_ERR
            } else {
                JNI_VERSION_1_8
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnUnload(_vm: *mut jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) {
    security::shutdown();
    security::join_monitors();
    destroy_sensitive_state();
}

struct CachedMethod {
    /// jmethodID XOR current pointer mask — never stored as raw pointer
    method_id_masked: usize,
    /// GlobalRef to the owner class — prevents GC from invalidating the class pointer.
    owner_class_ref: Option<GlobalRef>,
    func_type: char,
    /// Whether the method returns an Object (vs void/primitive)
    returns_object: bool,
    /// Pointer mask generation when this entry was created (for staleness check)
    mask_generation: u64,
    /// For string type ('l'): XOR-encrypted cached value (never plaintext)
    cached_string_encrypted: Option<(Vec<u8>, u64)>,
}

impl CachedMethod {
    fn new(
        method_id: jmethodID,
        owner_class_ref: GlobalRef,
        func_type: char,
        returns_object: bool,
    ) -> Self {
        let mask = mem_protect::get_current_pointer_mask();
        let adj = integrity::get_pointer_anchor_adjustment();
        let mask_gen = mem_protect::get_pointer_mask_state()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation;
        //debug_log!("[SkyLicense] CachedMethod::new: mid={:?}, cls={:?}, mask={:#x}, adj={:#x}", method_id, owner_class_ref.as_raw(), mask, adj);
        Self {
            method_id_masked: encode_masked_pointer(method_id as usize, mask, adj),
            owner_class_ref: Some(owner_class_ref),
            func_type,
            returns_object,
            mask_generation: mask_gen,
            cached_string_encrypted: None,
        }
    }

    fn new_string(value: &str) -> Self {
        let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(value);
        Self {
            method_id_masked: 0,
            owner_class_ref: None,
            func_type: 'l',
            returns_object: true,
            mask_generation: 0,
            cached_string_encrypted: Some((encrypted, xor_gen)),
        }
    }

    fn method_id(&self) -> jmethodID {
        let mask = mem_protect::get_current_pointer_mask();
        let adj = integrity::get_pointer_anchor_adjustment();
        decode_masked_pointer(self.method_id_masked, mask, adj) as jmethodID
    }

    fn owner_class(&self) -> *mut _jobject {
        self.owner_class_ref
            .as_ref()
            .map(|r| r.as_raw())
            .unwrap_or(std::ptr::null_mut())
    }

    /// Decrypt the cached string value. Returns None if XOR key was rotated (stale entry).
    fn get_cached_string(&self) -> Option<String> {
        if let Some((ref encrypted, xor_gen)) = self.cached_string_encrypted {
            mem_protect::xor_decrypt_string(encrypted, xor_gen)
        } else {
            None
        }
    }
}

fn encode_masked_pointer(pointer: usize, mask: usize, adjustment: usize) -> usize {
    pointer ^ adjustment ^ mask
}

fn decode_masked_pointer(encoded: usize, mask: usize, adjustment: usize) -> usize {
    encoded ^ mask ^ adjustment
}

fn reencode_masked_pointer(encoded: usize, old_mask: usize, new_mask: usize) -> usize {
    encoded ^ old_mask ^ new_mask
}

fn inactive_dispatch_result(env: &mut JNIEnv<'_>, authentication: bool) -> jobject {
    if authentication {
        new_java_string_or_null(env, "SESSION_REVOKED")
    } else {
        let _ = env.throw_new(
            "java/lang/SecurityException",
            "SkyLicense session is inactive",
        );
        JObject::null().as_raw()
    }
}

fn new_java_string_or_null(env: &mut JNIEnv<'_>, value: impl AsRef<str>) -> jobject {
    env.new_string(value.as_ref())
        .map(|string| string.as_raw())
        .unwrap_or_else(|_| {
            let _ = env.exception_clear();
            JObject::null().as_raw()
        })
}

fn decrypt_lookup_key(raw_key: &str, method_key: &[u8]) -> Option<String> {
    let encoded = BASE64_STANDARD.decode(raw_key).ok()?;
    let plaintext = Zeroizing::new(EncryptUtil::decrypt_method_lookup(&encoded, method_key).ok()?);
    String::from_utf8(plaintext.to_vec()).ok()
}

fn decrypt_method_string(encoded: &str, method_key: &[u8]) -> Option<String> {
    let envelope = BASE64_STANDARD.decode(encoded).ok()?;
    let plaintext = Zeroizing::new(EncryptUtil::decrypt_method_string(&envelope, method_key).ok()?);
    String::from_utf8(plaintext.to_vec()).ok()
}

unsafe impl Send for CachedMethod {}
unsafe impl Sync for CachedMethod {}

/// Destroy all client-side material required to dispatch protected methods.
///
/// Terminal transitions call this function at most once, while every cleanup
/// operation remains idempotent for safe shutdown and initialization rollback.
pub(crate) fn destroy_sensitive_state() {
    debug_log!("[SkyLicense] destroying sensitive client state");
    if let Some(lease) = SESSION_LEASE.get() {
        lease.revoke();
    }
    secure_map::destroy_all_keys();
    if let Some(map_mutex) = ENCRYPTED_MAP.get()
        && let Ok(mut map) = map_mutex.lock()
    {
        map.destroy();
    }
    if let Some(dk_cache) = DECODED_KEY_CACHE.get()
        && let Ok(mut cache) = dk_cache.write()
    {
        for (mut key, (mut value, _)) in cache.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
    if let Some(mc) = METHOD_CACHE.get()
        && let Ok(mut cache) = mc.write()
    {
        cache.clear();
    }
    mem_protect::destroy_runtime_secrets();
}

/// Compatibility wrapper for older integrations. New code should submit typed
/// evidence through `security::tamper` or `security::revoke`.
#[inline(never)]
pub fn corrupt_state() {
    security::tamper(security::SecurityEvidence::new(
        security::EvidenceKind::RuntimeFailure,
        security::EvidenceConfidence::Certain,
        "legacy.corrupt_state",
        "legacy terminal-state request",
    ));
}

fn start_key_rotation_monitor() -> Result<(), String> {
    security::spawn_monitor("sky-key-rotation", |stop| {
        while !stop.load(Ordering::Acquire) {
            let policy = security::policy();
            let minimum = policy.key_rotation_min.as_secs();
            let maximum = policy.key_rotation_max.as_secs().max(minimum);
            let interval_seconds =
                minimum + (rand::random::<u64>() % (maximum.saturating_sub(minimum) + 1));
            if security::wait_for_stop(&stop, std::time::Duration::from_secs(interval_seconds)) {
                return;
            }

            let rotation_result = ENCRYPTED_MAP
                .get()
                .ok_or_else(|| "encrypted method map is unavailable".to_string())
                .and_then(|map| {
                    map.lock()
                        .map_err(|_| "encrypted method-map lock is poisoned".to_string())?
                        .rotate_key()
                });

            if let Err(error) = rotation_result {
                security::mark_suspected(security::SecurityEvidence::new(
                    security::EvidenceKind::RuntimeFailure,
                    security::EvidenceConfidence::High,
                    "key_rotation.method_map",
                    error,
                ));
                return;
            }

            if let Some(cache) = METHOD_CACHE.get() {
                let Ok(mut cache) = cache.write() else {
                    security::mark_suspected(security::SecurityEvidence::new(
                        security::EvidenceKind::RuntimeFailure,
                        security::EvidenceConfidence::High,
                        "key_rotation.method_cache",
                        "method-cache lock is poisoned",
                    ));
                    return;
                };

                // Hold the method-cache write lock while changing the pointer
                // mask. Dispatch readers cannot observe a new mask paired with
                // an old encoded jmethodID.
                mem_protect::rotate_cache_xor_key();
                let (old_mask, new_mask) = mem_protect::rotate_pointer_mask();
                let generation = mem_protect::get_pointer_mask_state()
                    .read()
                    .map(|state| state.generation)
                    .unwrap_or_default();

                for entry in cache.values_mut() {
                    if entry.func_type != 'l' {
                        entry.method_id_masked =
                            reencode_masked_pointer(entry.method_id_masked, old_mask, new_mask);
                        entry.mask_generation = generation;
                    }
                    if let Some((mut encrypted, _)) = entry.cached_string_encrypted.take() {
                        encrypted.zeroize();
                    }
                }
            } else {
                mem_protect::rotate_cache_xor_key();
                let _ = mem_protect::rotate_pointer_mask();
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_cn_sky_license_authlib_AuthLib_authenticate<'a>(
    env: JNIEnv<'a>,
    class: JClass<'a>,
    obj: JObject<'a>,
    input: JString<'a>,
) -> jobject {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authenticate_jni_impl(env, class, obj, input)
    })) {
        Ok(result) => result,
        Err(_) => JObject::null().as_raw(),
    }
}

fn authenticate_jni_impl<'a>(
    mut env: JNIEnv<'a>,
    _: JClass<'a>,
    obj: JObject<'a>,
    str: JString<'a>,
) -> jobject {
    let input: String = match env.get_string(&str) {
        Ok(value) => value.into(),
        Err(_) => {
            let _ = env.exception_clear();
            return JObject::null().as_raw();
        }
    };
    if input == "!skylicense:v4:status" {
        let lease = SESSION_LEASE.get();
        let active = AUTHENTICATION_STATE.load(Ordering::Acquire) == AUTHENTICATION_INITIALIZED
            && !security::state().is_terminal()
            && lease.is_some_and(|lease| lease.is_valid());
        let count = lease.map_or(0, |lease| lease.verified_heartbeat_count());
        return new_java_string_or_null(
            &mut env,
            format!("{}:{count}", if active { "ACTIVE" } else { "INACTIVE" }),
        );
    }
    if input == "!skylicense:v4:close" {
        security::shutdown();
        return JObject::null().as_raw();
    }
    if input == "!skylicense:v4:rotations" {
        return new_java_string_or_null(
            &mut env,
            mem_protect::current_xor_generation().to_string(),
        );
    }
    let authentication =
        input.split('@').count() == 5 && input.contains("$$") && input.contains('/');
    if security::state().is_terminal() {
        return inactive_dispatch_result(&mut env, authentication);
    }

    // Every protected dispatch is gated by the process-local monotonic lease.
    if let Some(lease) = SESSION_LEASE.get()
        && !lease.is_valid()
    {
        security::submit(security::SecurityEvidence::new(
            security::EvidenceKind::HeartbeatFailure,
            security::EvidenceConfidence::Certain,
            "dispatch.lease_expired",
            "protected dispatch was attempted after the server lease expired",
        ));
        return inactive_dispatch_result(&mut env, authentication);
    }

    let obj_clone = *obj;
    let str = input;

    if authentication {
        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(_) => {
                return env
                    .new_string(obfuse!("RUNTIME_ERROR"))
                    .map(|value| value.as_raw())
                    .unwrap_or_else(|_| JObject::null().as_raw());
            }
        };
        let result = rt.block_on(async {
            match tokio::time::timeout(
                std::time::Duration::from_secs(60),
                authenticate(&env, obj_clone, &str),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => String::from("SOCKET_ERROR_TIMEOUT"),
            }
        });
        new_java_string_or_null(&mut env, &result)
    } else {
        // Master password — TTL cached, auto-zeroized after 30s
        let method_key = secure_map::method_token_key();
        let Some(method_key) = method_key else {
            return inactive_dispatch_result(&mut env, false);
        };

        let Some(key) = str.split('@').nth(2) else {
            return JObject::null().as_raw();
        };
        let Some(raw_key) = key.get(1..) else {
            return JObject::null().as_raw();
        };
        if raw_key.is_empty() || raw_key.len() > 16 * 1024 {
            return JObject::null().as_raw();
        }

        // === Decoded key cache with XOR encryption ===
        // Authenticated tokens are XOR-encrypted before caching as plaintext never persists.
        let dk_cache = DECODED_KEY_CACHE.get_or_init(|| RwLock::new(FxHashMap::default()));

        let decoded_key = {
            let read_cache = dk_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((encrypted_val, xor_gen)) = read_cache.get(raw_key) {
                // Try to decrypt with current XOR key
                match mem_protect::xor_decrypt_string(encrypted_val, *xor_gen) {
                    Some(val) => val,
                    None => {
                        // XOR key rotated — re-decrypt from source
                        drop(read_cache);
                        // Double-check: another thread may have already refreshed this entry
                        let mut write_cache = dk_cache
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        // Re-check under write lock (another thread may have updated)
                        if let Some((enc, g)) = write_cache.get(raw_key) {
                            if let Some(val) = mem_protect::xor_decrypt_string(enc, *g) {
                                val
                            } else {
                                let Some(result) = decrypt_lookup_key(raw_key, &*method_key) else {
                                    return JObject::null().as_raw();
                                };
                                let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                                write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                                result
                            }
                        } else {
                            let Some(result) = decrypt_lookup_key(raw_key, &*method_key) else {
                                return JObject::null().as_raw();
                            };
                            let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                            write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                            result
                        }
                    }
                }
            } else {
                drop(read_cache);
                // Slow path: authenticate and decrypt this token for the first time.
                let Some(result) = decrypt_lookup_key(raw_key, &*method_key) else {
                    return JObject::null().as_raw();
                };
                let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                let mut write_cache = dk_cache
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                result
            }
        };

        // === HOT PATH with RwLock ===
        let cache_rw = METHOD_CACHE.get_or_init(|| RwLock::new(FxHashMap::default()));

        // Fast path: read lock — multiple threads can read simultaneously
        {
            let cache = cache_rw
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cache.get(decoded_key.as_str()) {
                let func_type = cached.func_type;

                if func_type == 'l' {
                    // String type — decrypt from XOR cache
                    if let Some(result) = cached.get_cached_string() {
                        drop(cache);
                        return new_java_string_or_null(&mut env, &result);
                    }
                    // XOR key rotated, entry stale — fall through to slow path
                    drop(cache);
                } else {
                    let method_id = cached.method_id();
                    let owner_class = cached.owner_class();
                    let ret_obj = cached.returns_object;
                    drop(cache);
                    return dispatch_cached(
                        &mut env,
                        func_type,
                        method_id,
                        owner_class,
                        obj_clone,
                        ret_obj,
                    );
                }
            }
        }

        // Slow path: write lock — only on first call per method or stale entry
        {
            let mut cache = cache_rw
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            // Double-check after acquiring write lock
            if let Some(cached) = cache.get(decoded_key.as_str()) {
                let func_type = cached.func_type;
                if func_type == 'l' {
                    if let Some(result) = cached.get_cached_string() {
                        debug_log!("str: {}", result);
                        drop(cache);
                        return new_java_string_or_null(&mut env, &result);
                    }
                    // Stale — remove and re-resolve below
                    cache.remove(decoded_key.as_str());
                } else {
                    let method_id = cached.method_id();
                    let owner_class = cached.owner_class();
                    let ret_obj = cached.returns_object;
                    drop(cache);
                    return dispatch_cached(
                        &mut env,
                        func_type,
                        method_id,
                        owner_class,
                        obj_clone,
                        ret_obj,
                    );
                }
            }

            // Resolve from encrypted map
            let Some(map_mutex) = ENCRYPTED_MAP.get() else {
                return JObject::null().as_raw();
            };
            let map = match map_mutex.lock() {
                Ok(map) => map,
                Err(_) => {
                    security::tamper_deferred(security::SecurityEvidence::new(
                        security::EvidenceKind::RuntimeFailure,
                        security::EvidenceConfidence::Certain,
                        "dispatch.method_map_lock",
                        "encrypted method-map lock is poisoned",
                    ));
                    return JObject::null().as_raw();
                }
            };
            let method_info = match map.get(decoded_key.as_str()) {
                Some(info) => info,
                None => return JObject::null().as_raw(),
            };
            drop(map);

            let func_type = method_info.func_type;

            if func_type == 'l' {
                // Decrypt string value, XOR-encrypt for cache, return plaintext
                let Some(mut decrypted_str) =
                    decrypt_method_string(&method_info.method_name, &*method_key)
                else {
                    return JObject::null().as_raw();
                };
                let result = decrypted_str.clone();
                cache.insert(
                    decoded_key.clone(),
                    CachedMethod::new_string(&decrypted_str),
                );
                // Zeroize the temporary plaintext
                decrypted_str.zeroize();
                drop(cache);
                return new_java_string_or_null(&mut env, &result);
            }

            // Resolve jclass + jmethodID (one-time)
            let jclass = match env.find_class(&method_info.class_name) {
                Ok(class) => class,
                Err(_) => {
                    let _ = env.exception_clear();
                    return JObject::null().as_raw();
                }
            };
            let global_class = match env.new_global_ref(jclass) {
                Ok(class) => class,
                Err(_) => {
                    let _ = env.exception_clear();
                    return JObject::null().as_raw();
                }
            };
            let raw_class = global_class.as_raw();

            let method_id_result = if matches!(func_type, 'I' | '0' | 'i' | 'O') {
                env.get_static_method_id(
                    unsafe { JClass::from_raw(raw_class) },
                    &method_info.method_name,
                    &method_info.method_desc,
                )
                .map(|method_id| method_id.into_raw())
            } else {
                env.get_method_id(
                    unsafe { JClass::from_raw(raw_class) },
                    &method_info.method_name,
                    &method_info.method_desc,
                )
                .map(|method_id| method_id.into_raw())
            };
            let method_id = match method_id_result {
                Ok(method_id) => method_id,
                Err(_) => {
                    let _ = env.exception_clear();
                    return JObject::null().as_raw();
                }
            };

            // Determine if method returns an Object (L... or [...) vs void/primitive
            let returns_object = method_info
                .method_desc
                .rsplit(')')
                .next()
                .map(|ret| ret.starts_with('L') || ret.starts_with('['))
                .unwrap_or(false);

            debug_log!(
                "call: {}_{} {} ret_obj={}",
                &method_info.method_name,
                &method_info.method_desc,
                func_type,
                returns_object
            );
            cache.insert(
                decoded_key.clone(),
                CachedMethod::new(method_id, global_class, func_type, returns_object),
            );
            drop(cache);

            dispatch_cached(
                &mut env,
                func_type,
                method_id,
                raw_class,
                obj_clone,
                returns_object,
            )
        }
    }
}

/// Dispatch a method call using pre-resolved jmethodID (zero resolution overhead)
#[inline(never)]
pub(crate) fn dispatch_cached(
    env: &mut JNIEnv,
    func_type: char,
    method_id: jmethodID,
    owner_class: *mut _jobject,
    obj_clone: *mut _jobject,
    returns_object: bool,
) -> jobject {
    let ret_type = if returns_object {
        ReturnType::Object
    } else {
        ReturnType::Primitive(jni::signature::Primitive::Void)
    };

    let v;
    unsafe {
        let mid = jni::objects::JMethodID::from_raw(method_id);
        let smid = jni::objects::JStaticMethodID::from_raw(method_id);
        match func_type {
            'I' | '0' => {
                v = env.call_static_method_unchecked(
                    JClass::from_raw(owner_class),
                    smid,
                    ret_type,
                    &[],
                );
            }
            'i' | 'O' => {
                v = env.call_static_method_unchecked(
                    JClass::from_raw(owner_class),
                    smid,
                    ret_type,
                    &[JValue::from(&JObject::from_raw(obj_clone)).as_jni()],
                );
            }
            '1' | '|' => {
                v = env.call_method_unchecked(JObject::from_raw(obj_clone), mid, ret_type, &[]);
            }
            _ => {
                v = Ok(JValueOwned::from(JObject::null()));
            }
        }
    };

    if !returns_object {
        // Method returns void or primitive — return null to JVM
        // (the actual return value is meaningless for non-object types)
        return JObject::null().as_raw();
    }

    match v {
        Ok(val) => match val.l() {
            Ok(obj) => obj.as_raw(),
            Err(_) => JObject::null().as_raw(),
        },
        Err(_) => {
            // A Java business exception must propagate through the native
            // bridge, not be printed/cleared and silently replaced by null.
            if !env.exception_check().unwrap_or(true) {
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    "Protected JNI dispatch failed",
                );
            }
            JObject::null().as_raw()
        }
    }
}

async fn authenticate(java_env: &JNIEnv<'_>, obj_clone: *mut _jobject, str: &str) -> String {
    let mut env = unsafe { java_env.unsafe_clone() };
    let arr = str.split("@").collect::<Vec<&str>>();
    if arr.len() != 5
        || arr.iter().any(|part| part.is_empty() || part.len() > 4096)
        || arr[1].parse::<u16>().is_err()
        || !valid_resource_identity(arr[2])
        || !valid_resource_identity(arr[3])
    {
        return String::from("INVALID_REQUEST");
    }
    let attempt = match AuthenticationAttempt::begin() {
        Ok(attempt) => attempt,
        Err(response) => return response.to_string(),
    };
    let host = arr[0];
    let port = arr[1];
    let url = format!("{}:{}", host, port);

    debug_log!("[SkyLicense] Connecting to {}...", url);

    // Generate ECDH key pair for this session
    let key_exchange = KeyExchange::new();
    let client_public_key = key_exchange.public_key;
    let client_security_epoch =
        match artifact_integrity::compiled_security_epoch().and_then(|epoch| {
            i32::try_from(epoch)
                .map_err(|_| "SKYLICENSE_SECURITY_EPOCH exceeds protocol range".to_string())
        }) {
            Ok(epoch) => epoch,
            Err(error) => return format!("CLIENT_BUILD_ERROR: {error}"),
        };
    let client_build_id = match artifact_integrity::compiled_build_id() {
        Ok(build_id) => build_id,
        Err(error) => return format!("CLIENT_BUILD_ERROR: {error}"),
    };

    // Generate client nonce
    let client_nonce: [u8; 32] = {
        let mut nonce = [0u8; 32];
        for byte in &mut nonce {
            *byte = rand::random::<u8>();
        }
        nonce
    };

    let mut stream = match tls::connect(host, port).await {
        Ok(stream) => {
            debug_log!("[SkyLicense] Connected to server");
            stream
        }
        Err(e) => {
            debug_log!("[SkyLicense] Connection failed: {}", e);
            return String::from("SOCKET_ERROR_CONNECT");
        }
    };

    // Phase 1: Send ClientHello with ECDH public key + nonce + HWID
    let hwid_hash = match hwid::get_hwid() {
        Ok(value) => value,
        Err(error) => return format!("HWID_ERROR: {error}"),
    };
    let plugin_data = arr.iter().skip(2).cloned().collect::<Vec<&str>>().join("@");
    debug_log!(
        "[SkyLicense] HWID length: {} chars",
        hwid_hash.chars().count()
    );
    debug_log!(
        "[SkyLicense] Plugin data length: {} chars",
        plugin_data.chars().count()
    );
    {
        let mut buf = ByteBuf::new();
        // Protocol version
        buf.write_int(AUTH_PROTOCOL_VERSION);
        // Client ECDH public key
        buf.write_bytes(&client_public_key);
        // Client nonce
        buf.write_bytes(&client_nonce);
        // Signed artifact identity bound into the v4 challenge transcript.
        buf.write_int(client_security_epoch);
        buf.write_bytes(&client_build_id);
        // HWID
        buf.write_string(&hwid_hash);
        // Original verify data
        buf.write_string(&plugin_data);
        // Reserved v4 fields must remain all zero.
        buf.write_int(0);
        buf.write_bytes(&[0u8; 16]);

        debug_log!("[SkyLicense] Sending {} bytes total", buf.get_bytes().len());
        if let Err(error) = stream.write_all(buf.get_bytes()).await {
            return format!("SOCKET_ERROR_WRITE: {error}");
        }
        debug_log!("[SkyLicense] ClientHello sent");
    }

    // Phase 2: Read server response
    let response = match utils::read_message(&mut stream).await {
        Ok(msg) => {
            debug_log!("[SkyLicense] Server response: {}", msg);
            msg
        }
        Err(e) => {
            debug_log!("[SkyLicense] Failed to read server response: {}", e);
            return format!("SOCKET_ERROR_READ: {}", e);
        }
    };

    let accept_str = get_accept_string();
    if response == accept_str {
        debug_log!("[SkyLicense] Server accepted, receiving protected resources...");

        // 一键启用所有保护（反调试、反Hook、内存保护、反Attach、蜜罐监控等）

        // Read server's ECDH public key (32 bytes)
        let mut server_pub_key = [0u8; 32];
        if let Err(e) = stream.read_exact(&mut server_pub_key).await {
            debug_log!("[SkyLicense] Failed to read server public key: {}", e);
            return format!("SOCKET_ERROR_ECDH: {}", e);
        }

        // Read server nonce (32 bytes)
        let mut server_nonce = [0u8; 32];
        if let Err(e) = stream.read_exact(&mut server_nonce).await {
            debug_log!("[SkyLicense] Failed to read server nonce: {}", e);
            return format!("SOCKET_ERROR_NONCE: {}", e);
        }

        // Read server challenge (32 bytes)
        let mut server_challenge = [0u8; 32];
        if let Err(e) = stream.read_exact(&mut server_challenge).await {
            debug_log!("[SkyLicense] Failed to read server challenge: {}", e);
            return format!("SOCKET_ERROR_CHALLENGE: {}", e);
        }
        let mut session_id = [0u8; 32];
        if let Err(e) = stream.read_exact(&mut session_id).await {
            debug_log!("[SkyLicense] Failed to read session id: {}", e);
            return format!("SOCKET_ERROR_SESSION: {e}");
        }
        debug_log!("[SkyLicense] ECDH exchange complete, computing shared secret...");

        // Derive shared secret via ECDH
        let shared_secret = match key_exchange.derive_shared_secret(&server_pub_key) {
            Ok(secret) => secret,
            Err(error) => return format!("KEY_EXCHANGE_ERROR: {error}"),
        };
        let session_key = match shared_secret.derive_session_key(&client_nonce, &server_nonce) {
            Ok(key) => Zeroizing::new(key),
            Err(error) => return format!("KEY_EXCHANGE_ERROR: {error}"),
        };

        // Compute challenge response
        let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(error) => return format!("CLOCK_ERROR: {error}"),
        };
        let challenge_response = match ChallengeResponse::compute_response(
            &session_key,
            &server_challenge,
            &client_nonce,
            &session_id,
            client_security_epoch as u32,
            &client_build_id,
            timestamp,
        ) {
            Ok(response) => Zeroizing::new(response),
            Err(error) => return format!("CHALLENGE_ERROR: {error}"),
        };

        {
            let mut response = ByteBuf::new();
            response.write_int(CHALLENGE_RESPONSE_MAGIC);
            response.write_long(timestamp);
            response.write_bytes(&challenge_response);
            if let Err(error) = stream.write_all(response.get_bytes()).await {
                return format!("SOCKET_ERROR_CHALLENGE_WRITE: {error}");
            }
        }

        debug_log!("[SkyLicense] Challenge response sent for server verification");

        // Read resource data
        let mut length_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut length_bytes).await {
            debug_log!("[SkyLicense] Failed to read resource length: {}", e);
            return format!("SOCKET_ERROR_RESOURCE_LEN: {}", e);
        }
        let resource_length = i32::from_be_bytes(length_bytes);
        if resource_length <= 0 || resource_length as usize > MAX_RESOURCE_BYTES {
            return String::from("RESOURCE_ERROR_SIZE");
        }
        if !attempt.mark_resource_released() {
            return String::from("SESSION_REVOKED");
        }
        debug_log!("[SkyLicense] Resource size: {} bytes", resource_length);

        let mut resource_data = vec![0u8; resource_length as usize];
        if let Err(e) = stream.read_exact(&mut resource_data).await {
            debug_log!("[SkyLicense] Failed to read resource data: {}", e);
            return format!("SOCKET_ERROR_RESOURCE_DATA: {}", e);
        }
        debug_log!("[SkyLicense] Resource data received, decrypting...");

        let plugin_name = arr[2];
        let transport_key = match ChallengeResponse::derive_resource_transport_key(
            &session_key,
            &session_id,
            client_security_epoch as u32,
            &client_build_id,
            plugin_name,
            arr[3],
        ) {
            Ok(key) => Zeroizing::new(key),
            Err(_) => return String::from("RESOURCE_ERROR_KEY_DERIVATION"),
        };
        let method_key = match ChallengeResponse::derive_method_key(
            &session_key,
            &session_id,
            client_security_epoch as u32,
            &client_build_id,
            plugin_name,
            arr[3],
        ) {
            Ok(key) => Zeroizing::new(key),
            Err(_) => return String::from("RESOURCE_ERROR_KEY_DERIVATION"),
        };
        let associated_data = match ChallengeResponse::build_resource_associated_data(
            &session_id,
            client_security_epoch as u32,
            &client_build_id,
            plugin_name,
            arr[3],
        ) {
            Ok(value) => value,
            Err(_) => return String::from("RESOURCE_ERROR_KEY_DERIVATION"),
        };
        let decoded_resource =
            EncryptUtil::decrypt_resource(&resource_data, &*transport_key, &associated_data);
        resource_data.zeroize();
        match decoded_resource {
            Ok(decrypted_data) => {
                let decrypted_data = Zeroizing::new(decrypted_data);
                debug_log!(
                    "[SkyLicense] Resource decrypted ({} bytes), parsing...",
                    decrypted_data.len()
                );
                match Resource::from_bytes(&decrypted_data) {
                    Ok(resource) => {
                        debug_log!(
                            "[SkyLicense] Resource parsed: {} classes, {} methods",
                            resource.byte_codes.len(),
                            resource.method_map.len()
                        );

                        // The server's resource serializer already emits a
                        // dependency-aware topological order. Preserve it:
                        // sorting by nested-class depth can move a top-level
                        // class ahead of a nested superclass and make
                        // ClassLoader#defineClass fail during linking.

                        let entry_class = resource.entry_class.clone();
                        let entry_point = resource.entry_point.clone();

                        // Store method map in ENCRYPTED memory
                        // The plaintext FxHashMap is consumed and all entries
                        // are individually encrypted with AES-256-GCM
                        let encrypted_map = match EncryptedMethodMap::from_plaintext(
                            resource.method_map,
                            &method_key,
                        ) {
                            Ok(map) => map,
                            Err(error) => {
                                debug_log!("[SkyLicense] Method-map encryption failed: {}", error);
                                return String::from("RESOURCE_ERROR_SAVING");
                            }
                        };

                        // Load classes via JNI
                        let classloader_path = get_classloader_path();
                        let define_class_name = get_define_class_string();
                        let define_class_sig = get_define_class_sig();

                        let class = match env.find_class(&classloader_path) {
                            Ok(class) => class,
                            Err(_) => {
                                let _ = env.exception_clear();
                                return String::from("RESOURCE_ERROR_CLASSLOADER");
                            }
                        };
                        let define_class_id =
                            match env.get_method_id(class, &define_class_name, &define_class_sig) {
                                Ok(id) => id,
                                Err(_) => return String::from("RESOURCE_ERROR_UNCOMPRESS"),
                            };

                        debug_log!(
                            "[SkyLicense] Loading {} classes...",
                            resource.byte_codes.len()
                        );
                        for (idx, bytecode) in resource.byte_codes.iter().enumerate() {
                            debug_log!(
                                "[SkyLicense] Loading class #{}: {}",
                                idx,
                                &bytecode.class_name
                            );
                            // Convert class name from internal format (/) to binary name (.)
                            let binary_name = bytecode.class_name.replace('/', ".");
                            let class_name_jstr = match env.new_string(&binary_name) {
                                Ok(name) => name,
                                Err(_) => {
                                    let _ = env.exception_clear();
                                    return String::from("RESOURCE_ERROR_UNCOMPRESS");
                                }
                            };
                            let byte_array = match env.byte_array_from_slice(&bytecode.code) {
                                Ok(array) => array,
                                Err(_) => {
                                    let _ = env.exception_clear();
                                    return String::from("RESOURCE_ERROR_UNCOMPRESS");
                                }
                            };
                            let args = [
                                JValue::from(&class_name_jstr).as_jni(),
                                JValue::from(&byte_array).as_jni(),
                                JValue::from(jint::from(0i32)).as_jni(),
                                JValue::from(bytecode.code.len() as i32).as_jni(),
                            ];

                            unsafe {
                                match env.call_method_unchecked(
                                    JObject::from_raw(obj_clone),
                                    define_class_id,
                                    ReturnType::Object,
                                    &args,
                                ) {
                                    Ok(obj) => {
                                        if obj.l().is_err() {
                                            return String::from("RESOURCE_ERROR_UNCOMPRESS");
                                        }
                                    }
                                    Err(_) => {
                                        env.exception_describe().ok();
                                        env.exception_clear().ok();
                                        debug_log!("[SkyLicense] Failed to load class #{}", idx);
                                        return String::from("RESOURCE_ERROR_UNCOMPRESS");
                                    }
                                }
                            };
                        }
                        debug_log!("[SkyLicense] All classes loaded successfully");

                        let entry_class_ref = match env.find_class(&entry_class) {
                            Ok(class) => class,
                            Err(_) => {
                                env.exception_clear().ok();
                                debug_log!(
                                    "[SkyLicense] Entry class was not found: {}",
                                    entry_class
                                );
                                return String::from("ENTRY_CLASS_NOT_FOUND");
                            }
                        };
                        if env
                            .get_static_method_id(&entry_class_ref, &entry_point, "()V")
                            .is_err()
                        {
                            env.exception_clear().ok();
                            debug_log!(
                                "[SkyLicense] Entry point was not found: {}.{}()",
                                entry_class,
                                entry_point
                            );
                            return String::from("ENTRY_POINT_NOT_FOUND");
                        }

                        if ENCRYPTED_MAP.set(Mutex::new(encrypted_map)).is_err() {
                            security::tamper(security::SecurityEvidence::new(
                                security::EvidenceKind::RuntimeFailure,
                                security::EvidenceConfidence::Certain,
                                "session.state_install",
                                "sensitive session state could not be installed atomically",
                            ));
                            return String::from("RESOURCE_ERROR_SAVING");
                        }
                        debug_log!("[SkyLicense] Method map encrypted and stored in memory");

                        if let Err(error) = protection::activate_all_protections(&env) {
                            security::tamper(security::SecurityEvidence::new(
                                security::EvidenceKind::RuntimeFailure,
                                security::EvidenceConfidence::Certain,
                                "protection.activation",
                                error.clone(),
                            ));
                            return format!("PROTECTION_ERROR: {error}");
                        }
                        if let Err(error) = start_key_rotation_monitor() {
                            security::tamper(security::SecurityEvidence::new(
                                security::EvidenceKind::RuntimeFailure,
                                security::EvidenceConfidence::Certain,
                                "key_rotation.spawn",
                                error,
                            ));
                            return String::from("RESOURCE_ERROR_SAVING");
                        }
                        debug_log!("[SkyLicense] All protections enabled");

                        // Install the renewable lease before invoking plugin
                        // code. A long-running entry point can no longer prevent
                        // the heartbeat monitor from enforcing revocation.
                        let heartbeat = heartbeat::HeartbeatClient::new(*session_key, session_id);
                        let lease = match heartbeat.start(host.to_string(), port.to_string()) {
                            Ok(handle) => handle,
                            Err(error) => {
                                security::tamper(security::SecurityEvidence::new(
                                    security::EvidenceKind::RuntimeFailure,
                                    security::EvidenceConfidence::Certain,
                                    "heartbeat.spawn",
                                    error,
                                ));
                                return String::from("HEARTBEAT_ERROR");
                            }
                        };
                        if SESSION_LEASE.set(std::sync::Arc::clone(&lease)).is_err() {
                            lease.revoke();
                            security::tamper(security::SecurityEvidence::new(
                                security::EvidenceKind::RuntimeFailure,
                                security::EvidenceConfidence::Certain,
                                "heartbeat.state_install",
                                "heartbeat session lease was already initialized",
                            ));
                            return String::from("HEARTBEAT_ERROR");
                        }
                        if !lease.is_valid() || security::state().is_terminal() {
                            return String::from("HEARTBEAT_ERROR");
                        }
                        debug_log!("[SkyLicense] Heartbeat started before plugin entry point");

                        // Call entry point
                        debug_log!(
                            "[SkyLicense] Calling entry point: {}.{}()",
                            entry_class,
                            entry_point
                        );
                        match env.call_static_method(&entry_class_ref, &entry_point, "()V", &[]) {
                            Ok(_) => {
                                debug_log!("[SkyLicense] Entry point executed successfully");
                            }
                            Err(_) => {
                                env.exception_describe().ok();
                                env.exception_clear().ok();
                                security::fail_closed(security::SecurityEvidence::new(
                                    security::EvidenceKind::RuntimeFailure,
                                    security::EvidenceConfidence::Certain,
                                    "resource.entry_point",
                                    format!(
                                        "entry point execution failed: {}.{}()",
                                        entry_class, entry_point
                                    ),
                                ));
                                debug_log!("[SkyLicense] Entry point execution failed");
                                return String::from("ENTRY_POINT_EXCEPTION");
                            }
                        };

                        if let Err(error) =
                            acknowledge_delivery(&mut stream, &session_key, &session_id).await
                        {
                            debug_log!("[SkyLicense] Delivery acknowledgement failed: {}", error);
                            security::fail_closed(security::SecurityEvidence::new(
                                security::EvidenceKind::RuntimeFailure,
                                security::EvidenceConfidence::Certain,
                                "resource.delivery_ack",
                                error,
                            ));
                            return String::from("DELIVERY_ACK_ERROR");
                        }

                        attempt.commit();

                        debug_log!(
                            "[SkyLicense] Resource initialization acknowledged, authentication complete"
                        );
                    }
                    Err(e) => {
                        debug_log!("[SkyLicense] Failed to parse resource: {:?}", e);
                        return String::from("RESOURCE_ERROR_UNCOMPRESS");
                    }
                }
            }
            Err(e) => {
                debug_log!("[SkyLicense] Failed to decrypt resource data: {}", e);
                return String::from("RESOURCE_ERROR_UNCOMPRESS");
            }
        }
    }
    response
}

fn valid_resource_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'-'))
}

async fn acknowledge_delivery<S>(
    stream: &mut S,
    session_key: &[u8; 32],
    session_id: &[u8; 32],
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("delivery acknowledgement clock error: {error}"))?
        .as_secs();
    let signature = Zeroizing::new(ChallengeResponse::compute_delivery_acknowledgement(
        session_key,
        session_id,
        timestamp,
        DELIVERY_ACK_SUCCESS,
    )?);
    let mut acknowledgement = ByteBuf::new();
    acknowledgement.write_int(DELIVERY_ACK_MAGIC);
    acknowledgement.write_long(timestamp);
    acknowledgement.write_bytes(session_id);
    acknowledgement.write_bytes(&[DELIVERY_ACK_SUCCESS]);
    acknowledgement.write_bytes(signature.as_ref());

    tokio::time::timeout(DELIVERY_ACK_TIMEOUT, async {
        stream
            .write_all(acknowledgement.get_bytes())
            .await
            .map_err(|error| format!("delivery acknowledgement write failed: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("delivery acknowledgement flush failed: {error}"))?;

        let mut confirmation = [0u8; 1];
        stream
            .read_exact(&mut confirmation)
            .await
            .map_err(|error| format!("delivery acknowledgement confirmation failed: {error}"))?;
        if confirmation[0] != DELIVERY_ACK_CONFIRMED {
            return Err("delivery acknowledgement was not confirmed".to_string());
        }
        Ok(())
    })
    .await
    .map_err(|_| "delivery acknowledgement timed out".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_identity_matches_server_protocol_rules() {
        assert!(valid_resource_identity("Core-1.0_Release+1"));
        assert!(!valid_resource_identity(""));
        assert!(!valid_resource_identity("Unsafe@Resource"));
        assert!(!valid_resource_identity("."));
        assert!(!valid_resource_identity(&"A".repeat(65)));
    }

    #[test]
    fn authentication_attempts_are_serialized_and_success_is_final() {
        AUTHENTICATION_STATE.store(AUTHENTICATION_IDLE, Ordering::Release);
        {
            let first = AuthenticationAttempt::begin().expect("first attempt must start");
            assert!(matches!(
                AuthenticationAttempt::begin(),
                Err("AUTHENTICATION_IN_PROGRESS")
            ));
            drop(first);
        }

        let retry = AuthenticationAttempt::begin().expect("pre-release failure may retry");
        retry.commit();
        assert!(matches!(
            AuthenticationAttempt::begin(),
            Err("SESSION_ALREADY_INITIALIZED")
        ));
        AUTHENTICATION_STATE.store(AUTHENTICATION_IDLE, Ordering::Release);
    }

    #[test]
    fn pointer_reencoding_preserves_the_raw_method_id() {
        for pointer in [1usize, 0x1234_5678, usize::MAX - 17] {
            let adjustment = 0x55AA_33CCusize;
            let old_mask = 0xA5A5_5A5Ausize;
            let new_mask = 0xDEAD_BEEFusize;
            let encoded = encode_masked_pointer(pointer, old_mask, adjustment);
            let rotated = reencode_masked_pointer(encoded, old_mask, new_mask);
            assert_eq!(
                decode_masked_pointer(rotated, new_mask, adjustment),
                pointer
            );
        }
    }

    #[tokio::test]
    async fn delivery_acknowledgement_uses_the_fixed_authenticated_frame() {
        let session_key = [3u8; 32];
        let session_id = [4u8; 32];
        let (mut client, mut server) = tokio::io::duplex(128);

        let server_task = tokio::spawn(async move {
            let mut frame = [0u8; 77];
            server.read_exact(&mut frame).await.unwrap();
            assert_eq!(
                i32::from_be_bytes(frame[..4].try_into().unwrap()),
                DELIVERY_ACK_MAGIC
            );
            assert_eq!(&frame[12..44], &session_id);
            assert_eq!(frame[44], DELIVERY_ACK_SUCCESS);
            let timestamp = u64::from_be_bytes(frame[4..12].try_into().unwrap());
            let expected = ChallengeResponse::compute_delivery_acknowledgement(
                &session_key,
                &session_id,
                timestamp,
                DELIVERY_ACK_SUCCESS,
            )
            .unwrap();
            assert_eq!(&frame[45..], &expected);
            server.write_all(&[DELIVERY_ACK_CONFIRMED]).await.unwrap();
        });

        acknowledge_delivery(&mut client, &session_key, &session_id)
            .await
            .unwrap();
        server_task.await.unwrap();
    }
}
