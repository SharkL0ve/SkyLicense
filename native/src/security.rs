//! Central security state, evidence collection, and monitor lifecycle management.
//!
//! Platform detectors must not terminate the host JVM directly. They report
//! evidence here; only cryptographically strong or otherwise definitive events
//! transition the runtime to a terminal state. Terminal transitions destroy the
//! client-side key material before subsequent JNI calls can continue.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

const MAX_EVIDENCE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    Compatible,
    Balanced,
    Strict,
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityPolicy {
    pub profile: SecurityProfile,
    pub environment_scan_interval: std::time::Duration,
    pub attach_scan_interval: std::time::Duration,
    pub key_rotation_min: std::time::Duration,
    pub key_rotation_max: std::time::Duration,
    pub hard_fail_on_runtime_agent: bool,
    pub require_jvm_attach_hardening: bool,
    pub require_certificate_pin: bool,
    pub require_signed_manifest: bool,
}

impl SecurityPolicy {
    pub fn for_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::Compatible => Self {
                profile,
                environment_scan_interval: std::time::Duration::from_secs(30),
                attach_scan_interval: std::time::Duration::from_secs(5),
                key_rotation_min: std::time::Duration::from_secs(90),
                key_rotation_max: std::time::Duration::from_secs(180),
                hard_fail_on_runtime_agent: false,
                require_jvm_attach_hardening: false,
                require_certificate_pin: false,
                require_signed_manifest: false,
            },
            SecurityProfile::Balanced => Self {
                profile,
                environment_scan_interval: std::time::Duration::from_secs(10),
                attach_scan_interval: std::time::Duration::from_secs(2),
                key_rotation_min: std::time::Duration::from_secs(30),
                key_rotation_max: std::time::Duration::from_secs(90),
                hard_fail_on_runtime_agent: true,
                require_jvm_attach_hardening: false,
                require_certificate_pin: false,
                require_signed_manifest: true,
            },
            SecurityProfile::Strict => Self {
                profile,
                environment_scan_interval: std::time::Duration::from_secs(5),
                attach_scan_interval: std::time::Duration::from_secs(1),
                key_rotation_min: std::time::Duration::from_secs(15),
                key_rotation_max: std::time::Duration::from_secs(45),
                hard_fail_on_runtime_agent: true,
                require_jvm_attach_hardening: true,
                require_certificate_pin: true,
                require_signed_manifest: true,
            },
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        #[cfg(feature = "security-compatible")]
        let profile = SecurityProfile::Compatible;
        #[cfg(feature = "security-balanced")]
        let profile = SecurityProfile::Balanced;
        #[cfg(feature = "security-strict")]
        let profile = SecurityProfile::Strict;

        Self::for_profile(profile)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityState {
    Uninitialized = 0,
    Initializing = 1,
    Active = 2,
    Suspected = 3,
    Revoked = 4,
    Tampered = 5,
    ShuttingDown = 6,
}

impl SecurityState {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Initializing,
            2 => Self::Active,
            3 => Self::Suspected,
            4 => Self::Revoked,
            5 => Self::Tampered,
            6 => Self::ShuttingDown,
            _ => Self::Uninitialized,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Tampered | Self::ShuttingDown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceConfidence {
    Low,
    Medium,
    High,
    Certain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    Debugger,
    JavaAgent,
    AttachAttempt,
    MemoryAccess,
    CodeIntegrity,
    ServerRevocation,
    HeartbeatFailure,
    RuntimeFailure,
}

#[derive(Debug, Clone)]
pub struct SecurityEvidence {
    pub kind: EvidenceKind,
    pub confidence: EvidenceConfidence,
    pub source: &'static str,
    pub detail: String,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceDisposition {
    Record,
    Suspect,
    Revoke,
    Tamper,
}

impl SecurityEvidence {
    pub fn new(
        kind: EvidenceKind,
        confidence: EvidenceConfidence,
        source: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            confidence,
            source,
            detail: detail.into(),
            observed_at: SystemTime::now(),
        }
    }
}

struct SecurityRuntime {
    state: AtomicU8,
    secrets_destroyed: AtomicBool,
    stop: Arc<AtomicBool>,
    evidence: Mutex<VecDeque<SecurityEvidence>>,
    monitors: Mutex<Vec<JoinHandle<()>>>,
}

impl SecurityRuntime {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(SecurityState::Uninitialized as u8),
            secrets_destroyed: AtomicBool::new(false),
            stop: Arc::new(AtomicBool::new(false)),
            evidence: Mutex::new(VecDeque::with_capacity(MAX_EVIDENCE)),
            monitors: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, evidence: SecurityEvidence) {
        if let Ok(mut entries) = self.evidence.lock() {
            if entries.len() == MAX_EVIDENCE {
                entries.pop_front();
            }
            entries.push_back(evidence);
        }
    }
}

static SECURITY_RUNTIME: OnceLock<SecurityRuntime> = OnceLock::new();
static SECURITY_POLICY: OnceLock<SecurityPolicy> = OnceLock::new();

fn runtime() -> &'static SecurityRuntime {
    SECURITY_RUNTIME.get_or_init(SecurityRuntime::new)
}

pub fn policy() -> SecurityPolicy {
    *SECURITY_POLICY.get_or_init(SecurityPolicy::default)
}

pub fn state() -> SecurityState {
    SecurityState::from_raw(runtime().state.load(Ordering::Acquire))
}

pub fn begin_initialization() -> Result<(), String> {
    let runtime = runtime();
    runtime.stop.store(false, Ordering::Release);
    runtime
        .state
        .compare_exchange(
            SecurityState::Uninitialized as u8,
            SecurityState::Initializing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|current| {
            format!(
                "security runtime cannot initialize from {:?}",
                SecurityState::from_raw(current)
            )
        })
}

pub struct InitializationGuard {
    committed: bool,
}

impl InitializationGuard {
    pub fn begin() -> Result<Self, String> {
        begin_initialization()?;
        Ok(Self { committed: false })
    }

    pub fn commit(mut self) -> Result<(), String> {
        activate()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for InitializationGuard {
    fn drop(&mut self) {
        if !self.committed {
            abort_initialization("security initialization did not complete");
        }
    }
}

pub fn activate() -> Result<(), String> {
    runtime()
        .state
        .compare_exchange(
            SecurityState::Initializing as u8,
            SecurityState::Active as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|current| {
            format!(
                "security runtime cannot activate from {:?}",
                SecurityState::from_raw(current)
            )
        })
}

pub fn abort_initialization(detail: impl Into<String>) {
    report(SecurityEvidence::new(
        EvidenceKind::RuntimeFailure,
        EvidenceConfidence::High,
        "security.initialize",
        detail,
    ));
    runtime().stop.store(true, Ordering::Release);
    let _ = runtime().state.compare_exchange(
        SecurityState::Initializing as u8,
        SecurityState::Uninitialized as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    join_monitors();
}

pub fn report(evidence: SecurityEvidence) {
    runtime().record(evidence);
}

/// Apply the compiled security policy to detector evidence.
///
/// Detectors should report what they observed and must not independently
/// choose whether the shared JVM is terminated. Cryptographically definitive
/// protocol events may still call `revoke` directly at their verification
/// boundary.
pub fn submit(evidence: SecurityEvidence) {
    match disposition_for(policy(), evidence.kind, evidence.confidence) {
        EvidenceDisposition::Record => report(evidence),
        EvidenceDisposition::Suspect => mark_suspected(evidence),
        EvidenceDisposition::Revoke => revoke(evidence),
        EvidenceDisposition::Tamper => tamper(evidence),
    }
}

fn disposition_for(
    policy: SecurityPolicy,
    kind: EvidenceKind,
    confidence: EvidenceConfidence,
) -> EvidenceDisposition {
    use EvidenceConfidence::{Certain, High, Low, Medium};
    use EvidenceDisposition::{Record, Revoke, Suspect, Tamper};
    use EvidenceKind::{
        AttachAttempt, CodeIntegrity, Debugger, HeartbeatFailure, JavaAgent, MemoryAccess,
        RuntimeFailure, ServerRevocation,
    };

    match (kind, confidence) {
        (ServerRevocation, Certain) | (HeartbeatFailure, Certain) => Revoke,
        (CodeIntegrity | Debugger | MemoryAccess, Certain) => Tamper,
        (JavaAgent, High | Certain) | (AttachAttempt, High | Certain) => {
            if policy.hard_fail_on_runtime_agent {
                Tamper
            } else {
                Suspect
            }
        }
        (Debugger | MemoryAccess, High) => {
            if policy.profile == SecurityProfile::Compatible {
                Suspect
            } else {
                Tamper
            }
        }
        (CodeIntegrity, High)
        | (Debugger | JavaAgent | AttachAttempt | MemoryAccess, Medium)
        | (HeartbeatFailure | ServerRevocation, High | Medium)
        | (RuntimeFailure, High | Certain) => Suspect,
        (CodeIntegrity, Low | Medium)
        | (JavaAgent | AttachAttempt | MemoryAccess, Low)
        | (Debugger | HeartbeatFailure | RuntimeFailure | ServerRevocation, Low)
        | (RuntimeFailure, Medium) => Record,
    }
}

pub fn mark_suspected(evidence: SecurityEvidence) {
    runtime().record(evidence);
    let _ = runtime().state.compare_exchange(
        SecurityState::Active as u8,
        SecurityState::Suspected as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

pub fn clear_suspicion() -> bool {
    runtime()
        .state
        .compare_exchange(
            SecurityState::Suspected as u8,
            SecurityState::Active as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

pub fn revoke(evidence: SecurityEvidence) {
    transition_terminal(SecurityState::Revoked, evidence);
}

/// Fail closed because a required security control could not be established.
/// This is a local capability revocation, not a claim that an attacker was
/// definitively observed.
pub fn fail_closed(evidence: SecurityEvidence) {
    transition_terminal(SecurityState::Revoked, evidence);
}

pub fn tamper(evidence: SecurityEvidence) {
    transition_terminal(SecurityState::Tampered, evidence);
}

/// Enter the tampered state while destruction is completed on a separate
/// thread. Use this only when the caller may already hold a sensitive-state
/// lock; synchronous destruction would otherwise deadlock on that same lock.
pub fn tamper_deferred(evidence: SecurityEvidence) {
    set_terminal_state(SecurityState::Tampered, evidence);
    let _ = thread::Builder::new()
        .name("sky-security-destroy".to_string())
        .spawn(destroy_secrets_once);
}

fn transition_terminal(target: SecurityState, evidence: SecurityEvidence) {
    set_terminal_state(target, evidence);
    destroy_secrets_once();
}

fn set_terminal_state(target: SecurityState, evidence: SecurityEvidence) {
    debug_assert!(target.is_terminal());
    let runtime = runtime();
    runtime.record(evidence);

    transition_atomic_to_terminal(&runtime.state, target);

    runtime.stop.store(true, Ordering::Release);
}

fn transition_atomic_to_terminal(state: &AtomicU8, target: SecurityState) -> SecurityState {
    debug_assert!(target.is_terminal());
    loop {
        let current = SecurityState::from_raw(state.load(Ordering::Acquire));
        if current.is_terminal() {
            return current;
        }
        if state
            .compare_exchange(
                current as u8,
                target as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return target;
        }
    }
}

fn destroy_secrets_once() {
    let runtime = runtime();
    if runtime
        .secrets_destroyed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::destroy_sensitive_state();
    }
}

pub fn ensure_operational() -> Result<(), SecurityState> {
    match state() {
        SecurityState::Active | SecurityState::Suspected => Ok(()),
        other => Err(other),
    }
}

pub fn evidence_snapshot() -> Vec<SecurityEvidence> {
    runtime()
        .evidence
        .lock()
        .map(|entries| entries.iter().cloned().collect())
        .unwrap_or_default()
}

pub fn stop_requested() -> bool {
    runtime().stop.load(Ordering::Acquire)
}

/// Wait for a monitor interval while polling the shared stop token. Returning
/// `true` means shutdown was requested. The short polling quantum keeps JNI
/// unload and initialization rollback from waiting on long scan intervals.
pub fn wait_for_stop(stop: &AtomicBool, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
    true
}

pub fn spawn_monitor<F>(name: &'static str, monitor: F) -> Result<(), String>
where
    F: FnOnce(Arc<AtomicBool>) + Send + 'static,
{
    if state().is_terminal() {
        return Err("security runtime is terminal".to_string());
    }

    spawn_monitor_for(runtime(), name, monitor)
}

/// Spawn a monitor and wait until its platform-specific control is installed.
/// Initialization succeeds only after the worker sends `Ok(())` through the
/// readiness channel.
pub fn spawn_ready_monitor<F>(
    name: &'static str,
    timeout: Duration,
    monitor: F,
) -> Result<(), String>
where
    F: FnOnce(Arc<AtomicBool>, SyncSender<Result<(), String>>) + Send + 'static,
{
    if state().is_terminal() {
        return Err("security runtime is terminal".to_string());
    }
    spawn_ready_monitor_for(runtime(), name, timeout, monitor)
}

fn spawn_ready_monitor_for<F>(
    runtime: &SecurityRuntime,
    name: &'static str,
    timeout: Duration,
    monitor: F,
) -> Result<(), String>
where
    F: FnOnce(Arc<AtomicBool>, SyncSender<Result<(), String>>) + Send + 'static,
{
    let (ready_tx, ready_rx) = sync_channel(1);
    spawn_monitor_for(runtime, name, move |stop| monitor(stop, ready_tx))?;
    ready_rx
        .recv_timeout(timeout)
        .map_err(|error| format!("{name} readiness failed: {error}"))?
}

fn spawn_monitor_for<F>(
    runtime: &SecurityRuntime,
    name: &'static str,
    monitor: F,
) -> Result<(), String>
where
    F: FnOnce(Arc<AtomicBool>) + Send + 'static,
{
    let stop = runtime.stop.clone();
    let handle = thread::Builder::new()
        .name(name.to_string())
        .spawn(move || monitor(stop))
        .map_err(|error| format!("failed to spawn {name}: {error}"))?;

    runtime
        .monitors
        .lock()
        .map_err(|_| "security monitor registry is poisoned".to_string())?
        .push(handle);
    Ok(())
}

pub fn shutdown() {
    let runtime = runtime();
    runtime
        .state
        .store(SecurityState::ShuttingDown as u8, Ordering::Release);
    runtime.stop.store(true, Ordering::Release);
}

/// Join stopped monitors. This must be called from a non-monitor host thread.
pub fn join_monitors() {
    join_runtime_monitors(runtime());
}

fn join_runtime_monitors(runtime: &SecurityRuntime) {
    let current = thread::current().id();
    let handles = runtime
        .monitors
        .lock()
        .map(|mut handles| std::mem::take(&mut *handles))
        .unwrap_or_default();

    for handle in handles {
        if handle.thread().id() != current {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_values_round_trip() {
        for state in [
            SecurityState::Uninitialized,
            SecurityState::Initializing,
            SecurityState::Active,
            SecurityState::Suspected,
            SecurityState::Revoked,
            SecurityState::Tampered,
            SecurityState::ShuttingDown,
        ] {
            assert_eq!(SecurityState::from_raw(state as u8), state);
        }
    }

    #[test]
    fn terminal_states_are_explicit() {
        assert!(SecurityState::Revoked.is_terminal());
        assert!(SecurityState::Tampered.is_terminal());
        assert!(SecurityState::ShuttingDown.is_terminal());
        assert!(!SecurityState::Active.is_terminal());
        assert!(!SecurityState::Suspected.is_terminal());
    }

    #[test]
    fn policy_ranges_are_ordered() {
        for profile in [
            SecurityProfile::Compatible,
            SecurityProfile::Balanced,
            SecurityProfile::Strict,
        ] {
            let policy = SecurityPolicy::for_profile(profile);
            assert!(policy.key_rotation_min <= policy.key_rotation_max);
            assert!(!policy.environment_scan_interval.is_zero());
            assert!(!policy.attach_scan_interval.is_zero());
        }
    }

    #[test]
    fn default_policy_matches_the_compiled_profile() {
        #[cfg(feature = "security-compatible")]
        assert_eq!(
            SecurityPolicy::default().profile,
            SecurityProfile::Compatible
        );
        #[cfg(feature = "security-balanced")]
        assert_eq!(SecurityPolicy::default().profile, SecurityProfile::Balanced);
        #[cfg(feature = "security-strict")]
        assert_eq!(SecurityPolicy::default().profile, SecurityProfile::Strict);
    }

    #[test]
    fn evidence_policy_separates_faults_from_attacks() {
        let strict = SecurityPolicy::for_profile(SecurityProfile::Strict);
        assert_eq!(
            disposition_for(
                strict,
                EvidenceKind::RuntimeFailure,
                EvidenceConfidence::Certain
            ),
            EvidenceDisposition::Suspect
        );
        assert_eq!(
            disposition_for(
                strict,
                EvidenceKind::CodeIntegrity,
                EvidenceConfidence::Certain
            ),
            EvidenceDisposition::Tamper
        );
        assert_eq!(
            disposition_for(
                strict,
                EvidenceKind::HeartbeatFailure,
                EvidenceConfidence::Certain
            ),
            EvidenceDisposition::Revoke
        );
    }

    #[test]
    fn compatible_profile_does_not_hard_fail_on_agent_evidence() {
        let compatible = SecurityPolicy::for_profile(SecurityProfile::Compatible);
        let strict = SecurityPolicy::for_profile(SecurityProfile::Strict);
        assert_eq!(
            disposition_for(
                compatible,
                EvidenceKind::JavaAgent,
                EvidenceConfidence::High
            ),
            EvidenceDisposition::Suspect
        );
        assert_eq!(
            disposition_for(strict, EvidenceKind::JavaAgent, EvidenceConfidence::High),
            EvidenceDisposition::Tamper
        );
    }

    #[test]
    fn terminal_transition_is_one_way() {
        let state = AtomicU8::new(SecurityState::Active as u8);
        assert_eq!(
            transition_atomic_to_terminal(&state, SecurityState::Revoked),
            SecurityState::Revoked
        );
        assert_eq!(
            transition_atomic_to_terminal(&state, SecurityState::Tampered),
            SecurityState::Revoked
        );
        assert_eq!(
            SecurityState::from_raw(state.load(Ordering::Acquire)),
            SecurityState::Revoked
        );
    }

    #[test]
    fn local_monitor_registry_stops_and_joins_workers() {
        let runtime = SecurityRuntime::new();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_by_worker = Arc::clone(&finished);
        spawn_monitor_for(&runtime, "sky-test-monitor", move |stop| {
            let _ = wait_for_stop(&stop, Duration::from_secs(5));
            finished_by_worker.store(true, Ordering::Release);
        })
        .unwrap();

        runtime.stop.store(true, Ordering::Release);
        join_runtime_monitors(&runtime);
        assert!(finished.load(Ordering::Acquire));
        assert!(runtime.monitors.lock().unwrap().is_empty());
    }

    #[test]
    fn ready_monitor_reports_initialization_before_returning() {
        let runtime = SecurityRuntime::new();
        spawn_ready_monitor_for(
            &runtime,
            "sky-test-ready",
            Duration::from_secs(1),
            |stop, ready| {
                let _ = ready.send(Ok(()));
                let _ = wait_for_stop(&stop, Duration::from_secs(5));
            },
        )
        .unwrap();

        runtime.stop.store(true, Ordering::Release);
        join_runtime_monitors(&runtime);
    }
}
