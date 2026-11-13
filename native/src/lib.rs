extern crate core;

#[cfg(test)]
mod test_mem_protect;

pub mod bytebuf;
pub mod encrypt;
pub mod challenge;
pub mod heartbeat;
pub mod hwid;
mod model;
pub mod obfuscate;
mod protection;
pub mod secure_map;
pub mod anti_dump;
pub mod anti_attach;
pub mod mem_protect;
pub mod agent_detect;
pub mod integrity;
pub mod tls;
mod utils;

use crate::encrypt::EncryptUtil;
use crate::model::{MethodInfo, Resource};
use crate::obfuscate::*;
use crate::challenge::{ChallengeResponse, KeyExchange};
use crate::secure_map::EncryptedMethodMap;
use bytebuf::ByteBuf;
use fxhash::FxHashMap;
use jni::objects::{JClass, JObject, JString, JValue, JValueOwned, GlobalRef};
use jni::signature::ReturnType;
use jni::sys::{_jobject, jint, jmethodID, jobject};
use jni::JNIEnv;
use obfuse::obfuse;
use rust_native_obf::*;
use std::error::Error;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use zeroize::Zeroize;

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

static P: OnceLock<Vec<u8>> = OnceLock::new();
/// The method map is stored ENCRYPTED in memory at all times.
/// Individual entries are decrypted only during the JNI call and zeroized immediately after.
static ENCRYPTED_MAP: OnceLock<Mutex<EncryptedMethodMap>> = OnceLock::new();
static SESSION_ACTIVE: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();

/// Cached decoded lookup keys: encrypted_base64 → XOR-encrypted decoded string.
/// Each unique encrypted key is decrypted (with PBKDF2) exactly ONCE,
/// then the result is XOR-encrypted and cached. Plaintext never persists.
static DECODED_KEY_CACHE: OnceLock<RwLock<FxHashMap<String, (Vec<u8>, u64)>>> = OnceLock::new();

/// Pre-resolved jmethodID + jclass cache with RwLock.
/// Multiple readers (hot path) never block each other.
/// Only the first call per method takes a write lock.
static METHOD_CACHE: OnceLock<RwLock<FxHashMap<String, CachedMethod>>> = OnceLock::new();

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
    fn new(method_id: jmethodID, owner_class_ref: GlobalRef, func_type: char, returns_object: bool) -> Self {
        let mask = mem_protect::get_current_pointer_mask();
        let adj = integrity::get_pointer_anchor_adjustment();
        let mask_gen = mem_protect::get_pointer_mask_state().read().unwrap().generation;
        //debug_log!("[SkyLicense] CachedMethod::new: mid={:?}, cls={:?}, mask={:#x}, adj={:#x}", method_id, owner_class_ref.as_raw(), mask, adj);
        Self {
            method_id_masked: ((method_id as usize) ^ adj) ^ mask,
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
        ((self.method_id_masked ^ mask) ^ adj) as jmethodID
    }

    fn owner_class(&self) -> *mut _jobject {
        self.owner_class_ref.as_ref()
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

/// Wrapper to send a raw pointer across threads safely.
/// Safety: the pointed-to data must outlive the thread (static lifetime).
struct SendPtr<T>(*const T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

unsafe impl Send for CachedMethod {}
unsafe impl Sync for CachedMethod {}

/// Called by heartbeat when license is revoked - corrupts internal state
/// so the program cannot continue functioning even if the check is bypassed
#[inline(never)]

pub unsafe fn corrupt_state() {
    debug_log!("[SkyLicense] !!! CORRUPT_STATE triggered — internal state being destroyed !!!");
    if let Some(active) = SESSION_ACTIVE.get() {
        active.store(false, Ordering::Relaxed);
    }
    // Corrupt the encrypted map so all future lookups fail
    if let Some(map_mutex) = ENCRYPTED_MAP.get() {
        if let Ok(mut map) = map_mutex.lock() {
            let _ = map.rotate_key();
        }
    }
    // Clear decoded key cache — forces re-decryption which will fail
    if let Some(dk_cache) = DECODED_KEY_CACHE.get() {
        if let Ok(mut cache) = dk_cache.write() {
            cache.clear();
        }
    }
    // Clear method cache
    if let Some(mc) = METHOD_CACHE.get() {
        if let Ok(mut cache) = mc.write() {
            cache.clear();
        }
    }
}

/// Assemble the master password at runtime from multiple fragments
/// Binary patching invalidates fragment C (code hash), causing silent failure
#[inline(never)]

fn assemble_master_key() -> String {
    hidden_call!({ derive_master_key() })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_cn_sky_license_authlib_AuthLib_authenticate<'a>(
    mut env: JNIEnv<'a>,
    _: JClass<'a>,
    obj: JObject<'a>,
    str: JString<'a>,
) -> jobject {
    // Check if session was revoked by heartbeat
    if let Some(active) = SESSION_ACTIVE.get() {
        if !active.load(Ordering::Relaxed) {
            return env.new_string(obfuse!("SESSION_REVOKED"))
                .expect("string error")
                .as_raw();
        }
    }

    let obj_clone = obj.clone();
    let str: String = env.get_string(&str).unwrap().into();

    if str.contains("@") && str.contains("$$") && str.contains("/") {
        let rt = Runtime::new().expect("runtime error");
        let result = rt.block_on(async {
            authenticate(&env, obj_clone, &str).await
        });
        env.new_string(result).expect("string error").as_raw()
    } else {
        // Master password — TTL cached, auto-zeroized after 30s
        let password = mem_protect::get_master_password(|| {
            let padding_password = assemble_master_key();
            base64::encode(
                EncryptUtil::decode(P.get().unwrap(), &padding_password).unwrap()
            )
        });
        let password = password.as_str();

        let key = str.split("@").collect::<Vec<&str>>()[2];
        let raw_key = &key[1..key.len()];

        // === Decoded key cache with XOR encryption ===
        // PBKDF2 result is XOR-encrypted before caching. Never stored as plaintext.
        let dk_cache = DECODED_KEY_CACHE.get_or_init(|| RwLock::new(FxHashMap::default()));

        let decoded_key = {
            let read_cache = dk_cache.read().expect("read lock");
            if let Some((encrypted_val, xor_gen)) = read_cache.get(raw_key) {
                // Try to decrypt with current XOR key
                match mem_protect::xor_decrypt_string(encrypted_val, *xor_gen) {
                    Some(val) => val,
                    None => {
                        // XOR key rotated — re-decrypt from source
                        drop(read_cache);
                        // Double-check: another thread may have already refreshed this entry
                        let mut write_cache = dk_cache.write().expect("write lock");
                        // Re-check under write lock (another thread may have updated)
                        if let Some((enc, g)) = write_cache.get(raw_key) {
                            if let Some(val) = mem_protect::xor_decrypt_string(enc, *g) {
                                val
                            } else {
                                let result = String::from_utf8(
                                    EncryptUtil::decode(
                                        base64::decode(raw_key).expect("base64 error").as_slice(),
                                        password,
                                    ).expect("decrypt error")
                                ).expect("utf8 error");
                                let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                                write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                                result
                            }
                        } else {
                            let result = String::from_utf8(
                                EncryptUtil::decode(
                                    base64::decode(raw_key).expect("base64 error").as_slice(),
                                    password,
                                ).expect("decrypt error")
                            ).expect("utf8 error");
                            let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                            write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                            result
                        }
                    }
                }
            } else {
                drop(read_cache);
                // Slow path: first time — run PBKDF2 once
                let result = String::from_utf8(
                    EncryptUtil::decode(
                        base64::decode(raw_key).expect("base64 error").as_slice(),
                        password,
                    ).expect("decrypt error")
                ).expect("utf8 error");
                let (encrypted, xor_gen) = mem_protect::xor_encrypt_string(&result);
                let mut write_cache = dk_cache.write().expect("write lock");
                write_cache.insert(raw_key.to_string(), (encrypted, xor_gen));
                result
            }
        };

        // === HOT PATH with RwLock ===
        let cache_rw = METHOD_CACHE.get_or_init(|| RwLock::new(FxHashMap::default()));

        // Fast path: read lock — multiple threads can read simultaneously
        {
            let cache = cache_rw.read().expect("read lock error");
            if let Some(cached) = cache.get(decoded_key.as_str()) {
                let func_type = cached.func_type;

                if func_type == 'l' {
                    // String type — decrypt from XOR cache
                    if let Some(result) = cached.get_cached_string() {
                        drop(cache);
                        return env.new_string(result).expect("str err").as_raw();
                    }
                    // XOR key rotated, entry stale — fall through to slow path
                    drop(cache);
                } else {
                    let method_id = cached.method_id();
                    let owner_class = cached.owner_class();
                    let ret_obj = cached.returns_object;
                    drop(cache);
                    return dispatch_cached(&mut env, func_type, method_id, owner_class, obj_clone, ret_obj);
                }
            }
        }

        // Slow path: write lock — only on first call per method or stale entry
        {
            let mut cache = cache_rw.write().expect("write lock error");

            // Double-check after acquiring write lock
            if let Some(cached) = cache.get(decoded_key.as_str()) {
                let func_type = cached.func_type;
                if func_type == 'l' {
                    if let Some(result) = cached.get_cached_string() {
                        debug_log!("str: {}", result);
                        drop(cache);
                        return env.new_string(result).expect("str err").as_raw();
                    }
                    // Stale — remove and re-resolve below
                    cache.remove(decoded_key.as_str());
                } else {
                    let method_id = cached.method_id();
                    let owner_class = cached.owner_class();
                    let ret_obj = cached.returns_object;
                    drop(cache);
                    return dispatch_cached(&mut env, func_type, method_id, owner_class, obj_clone, ret_obj);
                }
            }

            // Resolve from encrypted map
            let map_mutex = ENCRYPTED_MAP.get().expect("state error");
            let map = map_mutex.lock().expect("lock error");
            let method_info = match map.get(decoded_key.as_str()) {
                Some(info) => info,
                None => return JObject::null().as_raw(),
            };
            drop(map);

            let func_type = method_info.func_type;

            if func_type == 'l' {
                // Decrypt string value, XOR-encrypt for cache, return plaintext
                let mut decrypted_str = String::from_utf8(
                    EncryptUtil::decode(
                        base64::decode(method_info.method_name.clone())
                            .expect("b64 err").as_slice(),
                        password,
                    ).expect("dec err")
                ).expect("utf8 err");
                let result = decrypted_str.clone();
                cache.insert(decoded_key.clone(), CachedMethod::new_string(&decrypted_str));
                // Zeroize the temporary plaintext
                unsafe { decrypted_str.as_mut_vec().iter_mut().for_each(|b| *b = 0); }
                drop(cache);
                return env.new_string(result).expect("str err").as_raw();
            }

            // Resolve jclass + jmethodID (one-time)
            let jclass = env.find_class(&method_info.class_name).expect("class error");
            let global_class = env.new_global_ref(jclass).expect("ref error");
            let raw_class = global_class.as_raw();

            let method_id = if matches!(func_type, 'I' | '0' | 'i' | 'O') {
                env.get_static_method_id(
                    unsafe { JClass::from_raw(raw_class) },
                    &method_info.method_name,
                    &method_info.method_desc,
                ).expect("mid error").into_raw()
            } else {
                env.get_method_id(
                    unsafe { JClass::from_raw(raw_class) },
                    &method_info.method_name,
                    &method_info.method_desc,
                ).expect("mid error").into_raw()
            };

            // Determine if method returns an Object (L... or [...) vs void/primitive
            let returns_object = method_info.method_desc
                .rsplit(')')
                .next()
                .map(|ret| ret.starts_with('L') || ret.starts_with('['))
                .unwrap_or(false);

            debug_log!("call: {}_{} {} ret_obj={}", &method_info.method_name, &method_info.method_desc, func_type, returns_object);
            cache.insert(decoded_key.clone(), CachedMethod::new(method_id, global_class, func_type, returns_object));
            drop(cache);

            dispatch_cached(&mut env, func_type, method_id, raw_class, obj_clone, returns_object)
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
                    &JClass::from_raw(owner_class),
                    smid,
                    ret_type,
                    &[],
                );
            }
            'i' | 'O' => {
                v = env.call_static_method_unchecked(
                    &JClass::from_raw(owner_class),
                    smid,
                    ret_type,
                    &[JValue::from(&JObject::from_raw(obj_clone)).as_jni()],
                );
            }
            '1' | '|' => {
                v = env.call_method_unchecked(
                    &JObject::from_raw(obj_clone),
                    mid,
                    ret_type,
                    &[],
                );
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
            env.exception_describe().ok();
            env.exception_clear().ok();
            JObject::null().as_raw()
        }
    }
}

async fn authenticate(java_env: &JNIEnv<'_>, obj_clone: *mut _jobject, str: &str) -> String {
    let mut env = unsafe { java_env.unsafe_clone() };
    let arr = str.split("@").collect::<Vec<&str>>();
    let host = arr[0];
    let port = arr[1];
    let url = format!("{}:{}", host, port);

    debug_log!("[SkyLicense] Connecting to {}...", url);

    // Generate ECDH key pair for this session
    let key_exchange = KeyExchange::new();
    let client_public_key = key_exchange.public_key;

    // Generate client nonce
    let client_nonce: [u8; 32] = {
        let mut nonce = [0u8; 32];
        for i in 0..32 { nonce[i] = rand::random::<u8>(); }
        nonce
    };

    let random_key: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

    // Connect to server (TCP for now, TLS when server supports it)
    let mut stream = match TcpStream::connect(&url).await {
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
    let hwid_hash = hwid::get_hwid();
    let plugin_data = arr.iter().skip(2).cloned().collect::<Vec<&str>>().join("@");
    debug_log!("[SkyLicense] HWID: {} ({} chars)", &hwid_hash[..16.min(hwid_hash.len())], hwid_hash.chars().count());
    debug_log!("[SkyLicense] Plugin data: {} ({} chars)", &plugin_data, plugin_data.chars().count());
    {
        let mut buf = ByteBuf::new();
        // Protocol version
        buf.write_int(2);
        // Client ECDH public key
        buf.write_bytes(&client_public_key);
        // Client nonce
        buf.write_bytes(&client_nonce);
        // HWID
        buf.write_string(&hwid_hash);
        // Original verify data
        buf.write_string(&plugin_data);
        // Local port
        let local_port = stream.local_addr().unwrap().port() as i32;
        buf.write_int(local_port);
        // Random key for legacy compatibility
        buf.write_bytes(&random_key);

        debug_log!("[SkyLicense] Sending {} bytes total", buf.get_bytes().len());
        stream.write_all(buf.get_bytes()).await.expect("write error");
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
        debug_log!("[SkyLicense] Server accepted, enabling protections...");

        // 一键启用所有保护（反调试、反Hook、内存保护、反Attach、蜜罐监控等）
        if let Err(e) = protection::activate_all_protections(&env) {
            debug_log!("[SkyLicense] Protection activation failed: {}", e);
            return format!("PROTECTION_ERROR: {}", e);
        }
        debug_log!("[SkyLicense] All protections enabled");

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
        debug_log!("[SkyLicense] ECDH exchange complete, computing shared secret...");

        // Derive shared secret via ECDH
        let shared_secret = key_exchange.derive_shared_secret(&server_pub_key);
        let session_key = shared_secret.derive_session_key(&client_nonce, &server_nonce);

        // Compute challenge response
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let challenge_response = ChallengeResponse::compute_response(
            &session_key,
            &server_challenge,
            &client_nonce,
            timestamp,
        );

        // NOTE: Server does not currently read challenge response (TODO on server side).
        // Do NOT send it — sending causes the server to interpret it as a new connection
        // after it has already closed the channel, resulting in "early eof" on resource read.
        // When server implements challenge verification, uncomment the block below.
        /*
        {
            let mut buf = ByteBuf::new();
            buf.write_int(challenge_response.len() as i32);
            buf.write_bytes(&challenge_response);
            buf.write_int(timestamp as i32);
            if let Err(e) = stream.write_all(buf.get_bytes()).await {
                debug_log!("[SkyLicense] Failed to send challenge response: {}", e);
                return format!("SOCKET_ERROR_WRITE: {}", e);
            }
            debug_log!("[SkyLicense] Challenge response sent");
        }
        */
        debug_log!("[SkyLicense] Challenge computed (not sent, server does not verify yet)");

        // Read resource data
        let mut length_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut length_bytes).await {
            debug_log!("[SkyLicense] Failed to read resource length: {}", e);
            return format!("SOCKET_ERROR_RESOURCE_LEN: {}", e);
        }
        let resource_length = i32::from_be_bytes(length_bytes);
        debug_log!("[SkyLicense] Resource size: {} bytes", resource_length);

        let mut resource_data = vec![0u8; resource_length as usize];
        if let Err(e) = stream.read_exact(&mut resource_data).await {
            debug_log!("[SkyLicense] Failed to read resource data: {}", e);
            return format!("SOCKET_ERROR_RESOURCE_DATA: {}", e);
        }
        debug_log!("[SkyLicense] Resource data received, decrypting...");

        // Derive decryption key
        let plugin_name = arr[2];
        let padding_password = assemble_master_key();

        let pad_name = format!("{}{}", plugin_name, &padding_password);
        let base_key = EncryptUtil::aes_encrypt(
            pad_name.as_bytes(),
            padding_password.as_bytes(),
        ).expect("encrypt error");

        let real_key = EncryptUtil::aes_encrypt(&base_key, &random_key).expect("encrypt error");
        let truncate_key = &real_key[0..16];

        // Store encrypted key for later use
        if let Err(_) = P.set(
            EncryptUtil::encode(truncate_key, &padding_password).expect("encode error")
        ) {
            return String::from("RESOURCE_ERROR_SAVING");
        }

        // Decrypt and load resources
        let decrypt_password = base64::encode(truncate_key);
        match EncryptUtil::decode(&resource_data, &decrypt_password) {
            Ok(mut decrypted_data) => {
                debug_log!("[SkyLicense] Resource decrypted ({} bytes), parsing...", decrypted_data.len());
                match Resource::from_bytes(&decrypted_data) {
                    Ok(mut resource) => {
                        // Zeroize decrypted data immediately
                        decrypted_data.zeroize();

                        debug_log!("[SkyLicense] Resource parsed: {} classes, {} methods",
                            resource.byte_codes.len(), resource.method_map.len());

                        resource.byte_codes.sort_by(|a, b| {
                            a.class_name.matches('$').count()
                                .cmp(&b.class_name.matches('$').count())
                        });

                        let entry_class = resource.entry_class.clone();
                        let entry_point = resource.entry_point.clone();

                        // Store method map in ENCRYPTED memory
                        // The plaintext FxHashMap is consumed and all entries
                        // are individually encrypted with AES-256-GCM
                        let encrypted_map = EncryptedMethodMap::from_plaintext(resource.method_map)
                            .expect("map encryption error");
                        if let Err(_) = ENCRYPTED_MAP.set(Mutex::new(encrypted_map)) {
                            return String::from("RESOURCE_ERROR_SAVING");
                        }
                        debug_log!("[SkyLicense] Method map encrypted and stored in memory");

                        // Start background key rotation thread
                        // TEMPORARILY DISABLED for debugging — re-enable after fixing crash
                        /*
                        if let Some(map_ref) = ENCRYPTED_MAP.get() {
                            // Safety: ENCRYPTED_MAP is a static OnceLock, lives for 'static.
                            let map_addr = map_ref as *const Mutex<EncryptedMethodMap> as usize;

                            std::thread::spawn(move || {
                                let map_ref = unsafe { &*(map_addr as *const Mutex<EncryptedMethodMap>) };
                                loop {
                                    let interval = (rand::random::<u64>() % 60) + 30;
                                    std::thread::sleep(std::time::Duration::from_secs(interval));

                                    // 1. Rotate AES-256-GCM encryption key
                                    if let Ok(mut locked_map) = map_ref.lock() {
                                        let _ = locked_map.rotate_key();
                                    }

                                    // 2. Rotate XOR cache key (invalidates cached strings)
                                    mem_protect::rotate_cache_xor_key();

                                    // 3. Rotate pointer mask and re-encode all cached pointers
                                    let (old_mask, new_mask) = mem_protect::rotate_pointer_mask();
                                    let new_mask_gen = mem_protect::get_pointer_mask_state()
                                        .read().unwrap().generation;
                                    if let Some(mc) = METHOD_CACHE.get() {
                                        if let Ok(mut cache) = mc.write() {
                                            for entry in cache.values_mut() {
                                                if entry.func_type != 'l' {
                                                    // Re-encode method_id: unmask with old, remask with new
                                                    let raw_mid = entry.method_id_masked ^ old_mask;
                                                    entry.method_id_masked = raw_mid ^ new_mask;
                                                    // owner_class is stored as GlobalRef, no re-encoding needed
                                                    entry.mask_generation = new_mask_gen;
                                                }
                                                // Invalidate stale XOR-encrypted strings
                                                entry.cached_string_encrypted = None;
                                            }
                                        }
                                    }

                                    // 4. Check hardware breakpoints (opportunistic)
                                    if mem_protect::detect_hardware_breakpoints() {
                                        unsafe { crate::corrupt_state(); }
                                    }
                                }
                            });
                        }
                        */

                        // Load classes via JNI
                        let classloader_path = get_classloader_path();
                        let define_class_name = get_define_class_string();
                        let define_class_sig = get_define_class_sig();

                        let class = env.find_class(&classloader_path).expect("class error");
                        let define_class_id = match env.get_method_id(
                            class,
                            &define_class_name,
                            &define_class_sig,
                        ) {
                            Ok(id) => id,
                            Err(_) => return String::from("RESOURCE_ERROR_UNCOMPRESS"),
                        };

                        debug_log!("[SkyLicense] Loading {} classes...", resource.byte_codes.len());
                        for (idx, bytecode) in resource.byte_codes.iter().enumerate() {
                            debug_log!("[SkyLicense] Loading class #{}: {}", idx, &bytecode.class_name);
                            // Convert class name from internal format (/) to binary name (.)
                            let binary_name = bytecode.class_name.replace('/', ".");
                            let class_name_jstr = env.new_string(&binary_name).expect("string error");
                            let args = [
                                JValue::from(&class_name_jstr).as_jni(),
                                JValue::from(
                                    &env.byte_array_from_slice(&bytecode.code)
                                        .expect("array error")
                                ).as_jni(),
                                JValue::from(jint::from(0i32)).as_jni(),
                                JValue::from(bytecode.code.len() as i32).as_jni(),
                            ];

                            unsafe {
                                match env.call_method_unchecked(
                                    JObject::from_raw(obj_clone),
                                    define_class_id,
                                    ReturnType::from_str("Ljava/lang/Class;")
                                        .expect("type error"),
                                    &args,
                                ) {
                                    Ok(obj) => { obj.l().expect("class error"); }
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

                        // Call entry point
                        debug_log!("[SkyLicense] Calling entry point: {}.{}()", entry_class, entry_point);
                        match env.call_static_method(
                            entry_class, entry_point, "()V", &[]
                        ) {
                            Ok(_) => {
                                debug_log!("[SkyLicense] Entry point executed successfully");
                            }
                            Err(_) => {
                                env.exception_describe().ok();
                                env.exception_clear().ok();
                                debug_log!("[SkyLicense] Entry point execution failed (non-fatal)");
                            }
                        };

                        // Start heartbeat in background
                        let heartbeat = heartbeat::HeartbeatClient::new(session_key);
                        let active_handle = heartbeat.start(
                            host.to_string(),
                            port.to_string(),
                        );
                        let _ = SESSION_ACTIVE.set(active_handle);
                        debug_log!("[SkyLicense] Heartbeat started, authentication complete");
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
