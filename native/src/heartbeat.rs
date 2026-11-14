use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::bytebuf::ByteBuf;
use crate::hwid;

type HmacSha256 = Hmac<Sha256>;

/// Heartbeat message types
const HEARTBEAT_PING: u8 = 0x01;
const HEARTBEAT_PONG: u8 = 0x02;
const HEARTBEAT_REVOKE: u8 = 0xFF;
const HEARTBEAT_MAGIC: i32 = 0x534B_4842;
const SESSION_LEASE_DURATION: Duration = Duration::from_secs(90);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(8);
const FAILURE_EVIDENCE_THRESHOLD: u32 = 3;

/// A process-local lease renewed only by an authenticated server PONG.
///
/// `Instant` cannot be stored atomically, so deadlines are represented as
/// milliseconds from a process-local monotonic epoch. Wall-clock changes can
/// therefore neither extend nor shorten an established license lease.
pub struct SessionLease {
    active: AtomicBool,
    expires_at_millis: AtomicU64,
    verified_pongs: AtomicU64,
}

impl SessionLease {
    fn new() -> Self {
        Self::new_with_duration(SESSION_LEASE_DURATION)
    }

    fn new_with_duration(duration: Duration) -> Self {
        Self {
            active: AtomicBool::new(true),
            expires_at_millis: AtomicU64::new(deadline_after(duration)),
            verified_pongs: AtomicU64::new(0),
        }
    }

    /// Returns true only while the lease is active and its monotonic deadline
    /// has not elapsed. A revoked lease can never be renewed.
    pub fn is_valid(&self) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        let valid = monotonic_millis() < self.expires_at_millis.load(Ordering::Acquire);
        valid && self.active.load(Ordering::Acquire)
    }

    pub fn revoke(&self) {
        self.active.store(false, Ordering::Release);
        self.expires_at_millis.store(0, Ordering::Release);
    }

    fn renew_authenticated(&self) -> bool {
        if self.renew_for(SESSION_LEASE_DURATION) {
            self.verified_pongs.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn verified_heartbeat_count(&self) -> u64 {
        self.verified_pongs.load(Ordering::Relaxed)
    }

    fn renew_for(&self, duration: Duration) -> bool {
        if !self.is_valid() {
            return false;
        }
        self.expires_at_millis
            .store(deadline_after(duration), Ordering::Release);
        self.active.load(Ordering::Acquire)
    }

    fn remaining(&self) -> Option<Duration> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let now = monotonic_millis();
        let deadline = self.expires_at_millis.load(Ordering::Acquire);
        deadline
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .map(Duration::from_millis)
    }
}

fn monotonic_millis() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

fn deadline_after(duration: Duration) -> u64 {
    let duration_millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    monotonic_millis().saturating_add(duration_millis)
}

/// Heartbeat client that maintains connection with server
pub struct HeartbeatClient {
    session_key: [u8; 32],
    session_id: [u8; 32],
    lease: Arc<SessionLease>,
}

impl HeartbeatClient {
    pub fn new(session_key: [u8; 32], session_id: [u8; 32]) -> Self {
        Self {
            session_key,
            session_id,
            lease: Arc::new(SessionLease::new()),
        }
    }

    /// Start heartbeat loop in background
    /// Returns a handle to stop the heartbeat
    pub fn start(self, host: String, port: String) -> Result<Arc<SessionLease>, String> {
        let lease = Arc::clone(&self.lease);
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|error| format!("failed to create heartbeat runtime: {error}"))?;

        crate::security::spawn_monitor("sky-heartbeat", move |stop| {
            runtime.block_on(async move {
                self.heartbeat_loop(&host, &port, &stop).await;
            });
        })?;

        Ok(lease)
    }

    async fn heartbeat_loop(&self, host: &str, port: &str, stop: &AtomicBool) {
        let mut consecutive_failures = 0u32;

        while !stop.load(Ordering::Acquire) {
            if !self.lease.is_valid() {
                if !stop.load(Ordering::Acquire) {
                    self.expire_lease();
                }
                break;
            }

            match tokio::time::timeout(HEARTBEAT_TIMEOUT, self.send_heartbeat(host, port)).await {
                Ok(Ok(HEARTBEAT_PONG)) => {
                    consecutive_failures = 0;
                    if !self.lease.renew_authenticated() {
                        if !stop.load(Ordering::Acquire) {
                            self.expire_lease();
                        }
                        break;
                    }
                }
                Ok(Ok(HEARTBEAT_REVOKE)) => {
                    self.lease.revoke();
                    crate::security::revoke(crate::security::SecurityEvidence::new(
                        crate::security::EvidenceKind::ServerRevocation,
                        crate::security::EvidenceConfidence::Certain,
                        "heartbeat.server",
                        "server revoked the active license session",
                    ));
                    break;
                }
                Ok(Ok(response)) => {
                    crate::security::submit(crate::security::SecurityEvidence::new(
                        crate::security::EvidenceKind::RuntimeFailure,
                        crate::security::EvidenceConfidence::Low,
                        "heartbeat.protocol",
                        format!("unexpected heartbeat response type {response:#04x}"),
                    ));
                    consecutive_failures = consecutive_failures.saturating_add(1);
                }
                Ok(Err(_)) | Err(_) => {
                    consecutive_failures += 1;
                }
            }

            if consecutive_failures >= FAILURE_EVIDENCE_THRESHOLD {
                crate::security::submit(crate::security::SecurityEvidence::new(
                    crate::security::EvidenceKind::HeartbeatFailure,
                    crate::security::EvidenceConfidence::Medium,
                    "heartbeat.transport",
                    format!("{consecutive_failures} consecutive heartbeat failures"),
                ));
                consecutive_failures = FAILURE_EVIDENCE_THRESHOLD;
            }

            let Some(remaining) = self.lease.remaining() else {
                if !stop.load(Ordering::Acquire) {
                    self.expire_lease();
                }
                break;
            };
            if wait_for_stop_async(stop, remaining.min(HEARTBEAT_INTERVAL)).await {
                break;
            }
        }
    }

    fn expire_lease(&self) {
        self.lease.revoke();
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::HeartbeatFailure,
            crate::security::EvidenceConfidence::Certain,
            "heartbeat.lease_expired",
            "the authenticated server lease expired without a valid PONG",
        ));
    }

    async fn send_heartbeat(&self, host: &str, port: &str) -> Result<u8, String> {
        let mut stream = crate::tls::connect(host, port).await?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("CLOCK_ERROR: {error}"))?
            .as_secs();

        // Build heartbeat payload
        let mut buf = ByteBuf::new();
        buf.write_bytes(&[HEARTBEAT_PING]);
        buf.write_bytes(&self.session_id);
        buf.write_long(timestamp);

        // Include stable authenticated environment telemetry. The server can
        // detect a transition, but this is not hardware-backed attestation.
        let env_hash = self.compute_environment_hash();
        buf.write_bytes(&env_hash);

        // Include HWID for binding verification
        let hwid = hwid::get_hwid().map_err(|error| format!("HWID_ERROR: {error}"))?;
        buf.write_string(&hwid);

        // HMAC the entire payload
        let payload = buf.get_bytes().to_vec();
        let mut mac =
            HmacSha256::new_from_slice(&self.session_key).map_err(|_| "ERROR".to_string())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();

        // Send: [payload_len][payload][signature]
        let mut out = ByteBuf::new();
        out.write_int(HEARTBEAT_MAGIC);
        out.write_int(payload.len() as i32);
        out.write_bytes(&payload);
        out.write_bytes(&signature);

        stream
            .write_all(out.get_bytes())
            .await
            .map_err(|_| "ERROR".to_string())?;

        // Read response
        let mut response = [0u8; 33];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|_| "ERROR".to_string())?;

        let mut response_mac =
            HmacSha256::new_from_slice(&self.session_key).map_err(|_| "ERROR".to_string())?;
        response_mac.update(b"SkyLicense heartbeat response");
        response_mac.update(&self.session_id);
        response_mac.update(&timestamp.to_be_bytes());
        response_mac.update(&response[..1]);
        response_mac
            .verify_slice(&response[1..])
            .map_err(|_| "ERROR".to_string())?;

        Ok(response[0])
    }

    /// Compute a hash of the current runtime environment
    /// Changes if debugger is attached or hooks are installed
    fn compute_environment_hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"SkyLicense environment evidence v1\0");

        // Check for debugger indicators
        #[cfg(target_os = "windows")]
        unsafe {
            use winapi::um::debugapi::IsDebuggerPresent;
            let debugger = IsDebuggerPresent();
            hasher.update([u8::from(debugger != 0)]);
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                let mut found = false;
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        hasher.update(line.as_bytes());
                        found = true;
                        break;
                    }
                }
                if !found {
                    hasher.update(b"TracerPid:unavailable");
                }
            } else {
                hasher.update(b"TracerPid:unavailable");
            }
        }

        hasher.update([u8::from(crate::agent_detect::is_agent_detected())]);
        hasher.update([u8::from(crate::integrity::runtime_anchors_match())]);

        hasher.finalize().into()
    }
}

impl Drop for HeartbeatClient {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.session_id.zeroize();
        self.lease.revoke();
    }
}

#[cfg(test)]
mod verified_counter_tests {
    use super::*;

    #[test]
    fn only_successful_renewals_increment_verified_count() {
        let lease = SessionLease::new();
        assert_eq!(lease.verified_heartbeat_count(), 0);
        assert!(lease.renew_authenticated());
        assert_eq!(lease.verified_heartbeat_count(), 1);
        lease.revoke();
        assert!(!lease.renew_authenticated());
        assert_eq!(lease.verified_heartbeat_count(), 1);
    }
}

async fn wait_for_stop_async(stop: &AtomicBool, duration: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + duration;
    while !stop.load(Ordering::Acquire) {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(100))).await;
    }
    true
}

// Integrity anchor pointer
#[inline(never)]
pub fn heartbeat_send_ptr() -> *const () {
    HeartbeatClient::compute_environment_hash as *const ()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_duration_lease_is_immediately_invalid() {
        let lease = SessionLease::new_with_duration(Duration::ZERO);
        assert!(!lease.is_valid());
        assert!(lease.remaining().is_none());
    }

    #[test]
    fn authenticated_renewal_extends_only_an_active_lease() {
        let expired = SessionLease::new_with_duration(Duration::ZERO);
        assert!(!expired.renew_for(Duration::from_secs(1)));

        let lease = SessionLease::new_with_duration(Duration::from_secs(1));
        assert!(lease.renew_for(Duration::from_secs(1)));
        assert!(lease.is_valid());

        lease.revoke();
        assert!(!lease.renew_for(Duration::from_secs(1)));
        assert!(!lease.is_valid());
    }
}
