use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::bytebuf::ByteBuf;
use crate::hwid;

type HmacSha256 = Hmac<Sha256>;

/// Heartbeat message types
const HEARTBEAT_PING: u8 = 0x01;
const HEARTBEAT_PONG: u8 = 0x02;
const HEARTBEAT_REVOKE: u8 = 0xFF;

/// Heartbeat client that maintains connection with server
pub struct HeartbeatClient {
    session_key: [u8; 32],
    is_active: Arc<AtomicBool>,
}

impl HeartbeatClient {
    pub fn new(session_key: [u8; 32]) -> Self {
        Self {
            session_key,
            is_active: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Start heartbeat loop in background
    /// Returns a handle to stop the heartbeat
    pub fn start(self, host: String, port: String) -> Arc<AtomicBool> {
        let active = self.is_active.clone();
        let active_ret = self.is_active.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("heartbeat runtime");
            rt.block_on(async move {
                self.heartbeat_loop(&host, &port).await;
            });
        });

        active_ret
    }

    async fn heartbeat_loop(&self, host: &str, port: &str) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut consecutive_failures = 0u32;

        while self.is_active.load(Ordering::Relaxed) {
            interval.tick().await;

            match self.send_heartbeat(host, port).await {
                Ok(response) => {
                    consecutive_failures = 0;
                    if response == HEARTBEAT_REVOKE {
                        // Server revoked our license
                        self.is_active.store(false, Ordering::Relaxed);
                        // Corrupt internal state
                        unsafe {
                            crate::corrupt_state();
                        }
                        break;
                    }
                }
                Err(_) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= 5 {
                        // Too many failures, assume revoked
                        self.is_active.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
    }

    async fn send_heartbeat(&self, host: &str, port: &str) -> Result<u8, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|_| "ERROR".to_string())?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build heartbeat payload
        let mut buf = ByteBuf::new();
        buf.write_bytes(&[HEARTBEAT_PING]);
        buf.write_int(timestamp as i32);

        // Include environment hash (detects debugging)
        let env_hash = self.compute_environment_hash();
        buf.write_bytes(&env_hash);

        // Include HWID for binding verification
        let hwid = hwid::get_hwid();
        buf.write_string(&hwid);

        // HMAC the entire payload
        let payload = buf.get_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&self.session_key)
            .map_err(|_| "ERROR".to_string())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();

        // Send: [payload_len][payload][signature]
        let mut out = ByteBuf::new();
        out.write_int(payload.len() as i32);
        out.write_bytes(&payload);
        out.write_bytes(&signature);

        stream.write_all(out.get_bytes()).await
            .map_err(|_| "ERROR".to_string())?;

        // Read response
        let mut response = [0u8; 1];
        stream.read_exact(&mut response).await
            .map_err(|_| "ERROR".to_string())?;

        Ok(response[0])
    }

    /// Compute a hash of the current runtime environment
    /// Changes if debugger is attached or hooks are installed
    fn compute_environment_hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();

        // Check for debugger indicators
        #[cfg(target_os = "windows")]
        unsafe {
            use winapi::um::debugapi::IsDebuggerPresent;
            let debugger = IsDebuggerPresent();
            hasher.update(&[debugger as u8]);
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        hasher.update(line.as_bytes());
                        break;
                    }
                }
            }
        }

        // Include timestamp to prevent replay
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        hasher.update(&ts.to_be_bytes());

        hasher.finalize().into()
    }
}

// Integrity anchor pointer
#[inline(never)]
pub fn heartbeat_send_ptr() -> *const () {
    HeartbeatClient::compute_environment_hash as *const ()
}
