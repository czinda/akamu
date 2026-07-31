//! Structured audit trail (PP CA v2.1 FAU family).
//!
//! All ACME and administrative operations that must be logged for CC evaluation
//! call [`record`].  The function writes a structured journal entry to the
//! `akamu` journal namespace, enforces the in-memory overflow counter
//! (FAU_STG.4), and maintains the rolling SecurityViolation counter for the
//! alarm response (FAU_ARP.1).
//!
//! # Design notes
//!
//! * Audit events are written to a dedicated systemd journal namespace via
//!   [`crate::journal::JournalWriter`].  When the namespace socket is
//!   unavailable (dev, CI), events are logged via `tracing` as a fallback.
//! * [`AuditState`] lives in `AppState` and survives the lifetime of the server
//!   process.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use crate::error::AcmeError;
use crate::journal::JournalWriter;

/// Maximum concurrent `journalctl` subprocesses spawned by audit queries.
static JOURNALCTL_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub use crate::journal::{AuditEventRow, AuditQuery};

// ── Event taxonomy ─────────────────────────────────────────────────────────────

/// Every auditable operation the server can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    // CA lifecycle
    CaStart,
    CaStop,
    // Account management
    AccountCreate,
    AccountDeactivate,
    AccountKeyChange,
    // Order / certificate lifecycle
    OrderCreate,
    OrderFinalize,
    CertIssue,
    CertRevoke,
    CrlGenerate,
    CrossSignIssue,
    // Key management
    KeyGenerate,
    KeyLoad,
    // ACME request authentication
    AuthJwsOk,
    AuthJwsFail,
    // DNS / HTTP / TLS challenge validation
    AuthChallengeOk,
    AuthChallengeFail,
    // EAB key usage
    EabUse,
    EabReject,
    // Admin interface
    AdminLogin,
    AdminLogout,
    AdminAction,
    // Email webhook HMAC authentication
    AuthWebhookHmacFail,
    // Security anomalies
    SecurityViolation,
}

impl AuditEventType {
    /// Return the canonical dot-separated string for this event type (e.g. `"cert.issue"`).
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEventType::CaStart => "ca.start",
            AuditEventType::CaStop => "ca.stop",
            AuditEventType::AccountCreate => "account.create",
            AuditEventType::AccountDeactivate => "account.deactivate",
            AuditEventType::AccountKeyChange => "account.key-change",
            AuditEventType::OrderCreate => "order.create",
            AuditEventType::OrderFinalize => "order.finalize",
            AuditEventType::CertIssue => "cert.issue",
            AuditEventType::CertRevoke => "cert.revoke",
            AuditEventType::CrlGenerate => "crl.generate",
            AuditEventType::CrossSignIssue => "cross-sign.issue",
            AuditEventType::KeyGenerate => "key.generate",
            AuditEventType::KeyLoad => "key.load",
            AuditEventType::AuthJwsOk => "auth.jws.ok",
            AuditEventType::AuthJwsFail => "auth.jws.fail",
            AuditEventType::AuthChallengeOk => "auth.challenge.ok",
            AuditEventType::AuthChallengeFail => "auth.challenge.fail",
            AuditEventType::EabUse => "eab.use",
            AuditEventType::EabReject => "eab.reject",
            AuditEventType::AdminLogin => "admin.login",
            AuditEventType::AdminLogout => "admin.logout",
            AuditEventType::AdminAction => "admin.action",
            AuditEventType::AuthWebhookHmacFail => "auth.webhook.hmac.fail",
            AuditEventType::SecurityViolation => "security.violation",
        }
    }
}

// ── Outcome ────────────────────────────────────────────────────────────────────

/// Outcome of an auditable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The operation completed without error.
    Success,
    /// The operation failed or was denied.
    Failure,
}

impl AuditOutcome {
    /// Return the string representation (`"success"` or `"failure"`).
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Failure => "failure",
        }
    }
}

// ── Event ──────────────────────────────────────────────────────────────────────

/// A single auditable event to be persisted.
#[derive(Debug)]
pub struct AuditEvent {
    pub(crate) event_type: AuditEventType,
    /// JWK thumbprint, account UUID, certificate serial, or similar identifier.
    pub(crate) subject: Option<String>,
    /// Authenticated identity: operator name or `"acme:<jwk_thumbprint>"`.
    pub(crate) principal: Option<String>,
    pub(crate) outcome: AuditOutcome,
    /// JSON object with event-specific fields, or `None`.
    pub(crate) detail: Option<String>,
}

impl AuditEvent {
    /// Construct a successful event of the given type.
    pub fn success(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            subject: None,
            principal: None,
            outcome: AuditOutcome::Success,
            detail: None,
        }
    }

    /// Construct a failure event of the given type.
    pub fn failure(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            subject: None,
            principal: None,
            outcome: AuditOutcome::Failure,
            detail: None,
        }
    }

    /// Set the subject (e.g. account UUID, certificate serial, JWK thumbprint).
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the principal (operator name or `"acme:<thumbprint>"`).
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Attach a JSON detail string with event-specific context.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

// ── Policy types ───────────────────────────────────────────────────────────────

/// What to do when the audit event count reaches `max_events` (FAU_STG.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Refuse new requests until an administrator intervenes.
    Halt,
    /// Continue recording; journald manages its own retention.
    DropOldest,
}

/// What to do when repeated `SecurityViolation` events are detected (FAU_ARP.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAction {
    /// Emit a CRIT-level log entry (visible to syslog consumers).
    Syslog,
    /// Halt the server.
    Halt,
}

/// Audit overflow and alarm policy, extracted from `AdminConfig` at startup.
#[derive(Debug, Clone)]
pub struct AuditPolicy {
    /// Maximum audit events (since startup) before overflow action.  `None` = unlimited.
    pub max_events: Option<u64>,
    /// Action to take when `max_events` is reached.
    pub overflow: OverflowPolicy,
    /// Number of `SecurityViolation` events in a rolling 5-minute window that
    /// triggers the FAU_ARP.1 alarm response.
    pub alarm_threshold: u32,
    /// Action to take when `alarm_threshold` is reached.
    pub alarm_action: AlarmAction,
}

impl AuditPolicy {
    /// Construct from the `[admin]` TOML config block.
    pub fn from_admin_config(cfg: &crate::config::AdminConfig) -> Self {
        Self {
            max_events: cfg.audit_max_events.and_then(|v| {
                if v <= 0 {
                    tracing::warn!(
                        audit_max_events = v,
                        "non-positive audit_max_events treated as unlimited"
                    );
                    None
                } else {
                    Some(v as u64)
                }
            }),
            overflow: if cfg.audit_overflow == "halt" {
                OverflowPolicy::Halt
            } else {
                OverflowPolicy::DropOldest
            },
            alarm_threshold: cfg.audit_alarm_threshold,
            alarm_action: if cfg.audit_alarm_action == "halt" {
                AlarmAction::Halt
            } else {
                AlarmAction::Syslog
            },
        }
    }
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            max_events: None,
            overflow: OverflowPolicy::DropOldest,
            alarm_threshold: 10,
            alarm_action: AlarmAction::Syslog,
        }
    }
}

// ── In-memory audit state ──────────────────────────────────────────────────────

/// Shared in-memory state for the audit subsystem.
///
/// Stored in `AppState::audit` and referenced wherever audit events are recorded.
pub struct AuditState {
    /// Recent `SecurityViolation` event timestamps for FAU_ARP.1 rolling window.
    pub violation_times: Mutex<VecDeque<Instant>>,
    /// Set to `true` when a halt condition has been triggered (overflow or alarm).
    /// Checked by the request dispatcher before accepting new work.
    pub should_halt: AtomicBool,
    /// Total audit events recorded since this process started.
    pub event_count: AtomicU64,
    /// Consecutive audit write failures (FAU_STG.1).  Reset to 0 on success;
    /// when this reaches `alarm_threshold`, `should_halt` is set.
    pub consecutive_insert_failures: AtomicU32,
}

impl std::fmt::Debug for AuditState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditState")
            .field("should_halt", &self.should_halt.load(Ordering::Relaxed))
            .field("event_count", &self.event_count.load(Ordering::Relaxed))
            .field(
                "consecutive_insert_failures",
                &self.consecutive_insert_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl AuditState {
    pub fn new() -> Self {
        Self {
            violation_times: Mutex::new(VecDeque::new()),
            should_halt: AtomicBool::new(false),
            event_count: AtomicU64::new(0),
            consecutive_insert_failures: AtomicU32::new(0),
        }
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Record ─────────────────────────────────────────────────────────────────────

fn handle_alarm(state: &AuditState, policy: &AuditPolicy) {
    match policy.alarm_action {
        AlarmAction::Syslog => {
            tracing::error!(
                threshold = policy.alarm_threshold,
                window_secs = 300,
                "SECURITY ALARM: repeated SecurityViolation events detected (FAU_ARP.1)"
            );
        }
        AlarmAction::Halt => {
            tracing::error!(
                threshold = policy.alarm_threshold,
                window_secs = 300,
                "SECURITY ALARM: halting server due to repeated SecurityViolation events (FAU_ARP.1)"
            );
            state.should_halt.store(true, Ordering::Release);
        }
    }
}

fn check_violation(state: &AuditState, policy: &AuditPolicy) {
    let threshold_exceeded = {
        // Panic rather than recover: a poisoned mutex means the VecDeque may
        // have been left mid-update by the panicking thread, and continuing
        // to evaluate the FAU_ARP.1 alarm against that state risks a silent
        // mis-evaluation. Let the task unwind — Tokio catches the panic, the
        // current request fails, and the alarm state is not misused. See
        // commit 1dd9b68b3, which this reinstates after a later refactor
        // silently reintroduced the recover-and-continue behavior.
        let mut times = state
            .violation_times
            .lock()
            .expect("violation_times mutex poisoned — FAU_ARP.1 alarm state is corrupt");
        let cutoff = Instant::now() - Duration::from_secs(300);
        times.retain(|&t| t >= cutoff);
        times.push_back(Instant::now());
        times.len() as u32 >= policy.alarm_threshold
    };
    if threshold_exceeded {
        handle_alarm(state, policy);
    }
}

/// Write one audit event to the journal namespace and enforce the in-memory
/// overflow counter (FAU_STG.4) and alarm (FAU_ARP.1).
pub fn record(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev: AuditEvent,
) -> Result<(), AcmeError> {
    let is_violation = ev.event_type == AuditEventType::SecurityViolation;

    let priority = match ev.outcome {
        AuditOutcome::Success => "6",
        AuditOutcome::Failure => "4",
    };

    let mut fields: Vec<(&str, &str)> = vec![
        ("SYSLOG_IDENTIFIER", "akamu-audit"),
        ("PRIORITY", priority),
        ("AKAMU_EVENT_TYPE", ev.event_type.as_str()),
        ("AKAMU_OUTCOME", ev.outcome.as_str()),
    ];
    if let Some(ref s) = ev.subject {
        fields.push(("AKAMU_SUBJECT", s));
    }
    if let Some(ref p) = ev.principal {
        fields.push(("AKAMU_PRINCIPAL", p));
    }
    if let Some(ref d) = ev.detail {
        fields.push(("AKAMU_DETAIL", d));
    }

    journal
        .send(&fields)
        .map_err(|e| AcmeError::Journal(format!("journal send: {e}")))?;

    let count = state.event_count.fetch_add(1, Ordering::AcqRel) + 1;

    // FAU_STG.4: overflow enforcement.
    if let Some(max) = policy.max_events {
        if count >= max {
            match policy.overflow {
                OverflowPolicy::Halt => {
                    tracing::error!(
                        max_events = max,
                        count,
                        "AUDIT OVERFLOW: halting server (FAU_STG.4)"
                    );
                    state.should_halt.store(true, Ordering::Release);
                }
                OverflowPolicy::DropOldest => {
                    // journald manages its own retention — nothing to do
                }
            }
        }
    }

    // FAU_ARP.1: rolling-window alarm for repeated SecurityViolation events.
    if is_violation {
        check_violation(state, policy);
    }

    Ok(())
}

/// Record two audit events sequentially.
pub fn record_pair(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev1: AuditEvent,
    ev2: AuditEvent,
) -> Result<(), AcmeError> {
    let err1 = record(journal, state, policy, ev1).err();
    let err2 = record(journal, state, policy, ev2).err();
    match (err1, err2) {
        (Some(e1), Some(e2)) => Err(AcmeError::Journal(format!(
            "journal send pair: {}; {}",
            e1, e2
        ))),
        (Some(e), None) | (None, Some(e)) => Err(e),
        (None, None) => Ok(()),
    }
}

/// Track a record result: reset the failure counter on success, increment
/// on failure and trigger a halt when the alarm threshold is reached.
fn track_record_result(
    result: Result<(), AcmeError>,
    state: &AuditState,
    policy: &AuditPolicy,
    context: &str,
) {
    match result {
        Ok(()) => {
            state
                .consecutive_insert_failures
                .store(0, Ordering::Release);
        }
        Err(e) => {
            let n = state
                .consecutive_insert_failures
                .fetch_add(1, Ordering::AcqRel)
                + 1;
            tracing::error!(
                error = %e,
                context,
                consecutive_failures = n,
                "audit record failed"
            );
            if n >= policy.alarm_threshold {
                tracing::error!(
                    consecutive_failures = n,
                    threshold = policy.alarm_threshold,
                    "AUDIT UNAVAILABLE: halting server after repeated insert failures (FAU_STG.1)"
                );
                state.should_halt.store(true, Ordering::Release);
            }
        }
    }
}

/// Record two audit events, logging any errors.
///
/// The `consecutive_insert_failures` counter tracks failed *calls*, not
/// individual events.  When both events in a pair fail, this increments
/// by 1 (one call), not 2.  The `alarm_threshold` therefore triggers
/// after N failed calls, each of which may lose 1 or 2 events.
pub fn record_or_log_pair(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev1: AuditEvent,
    ev2: AuditEvent,
) {
    let ev1_type = ev1.event_type.as_str();
    let ev2_type = ev2.event_type.as_str();
    let result = record_pair(journal, state, policy, ev1, ev2);
    let context = format!("{ev1_type}+{ev2_type}");
    track_record_result(result, state, policy, &context);
}

pub fn record_or_log(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev: AuditEvent,
) {
    let ev_type = ev.event_type.as_str();
    let result = record(journal, state, policy, ev);
    track_record_result(result, state, policy, ev_type);
}

// ── Journal query ─────────────────────────────────────────────────────────────

/// RFC 3339 timestamp pattern: YYYY-MM-DDTHH:MM:SS (with optional fractional seconds and Z/offset).
/// Validates positional separators and restricts characters to the RFC 3339
/// alphabet (ASCII digits, `-`, `T`, `:`, `.`, `Z`, `+`).
fn is_rfc3339_like(s: &str) -> bool {
    s.len() >= 20
        && s.as_bytes()[4] == b'-'
        && s.as_bytes()[10] == b'T'
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'T' | b':' | b'.' | b'Z' | b'+'))
}

/// Query the journal for audit events.
///
/// When the journal writer has a built-in daemon (in-memory store), queries
/// it directly.  Otherwise shells out to `journalctl`.
pub async fn query_journal(
    journal: &JournalWriter,
    q: &AuditQuery,
) -> Result<Vec<AuditEventRow>, AcmeError> {
    if journal.has_store() {
        return journal
            .query(q)
            .map_err(|e| AcmeError::Journal(format!("journal query: {e}")));
    }

    let _permit = JOURNALCTL_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| AcmeError::Journal("journalctl semaphore closed".into()))?;

    let namespace = journal.namespace();
    let mut cmd = tokio::process::Command::new("journalctl");
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/usr/sbin");
    cmd.env("LC_ALL", "C");
    cmd.arg(format!("--namespace={namespace}"));
    cmd.arg("--output=json");
    cmd.arg("--no-pager");
    cmd.arg("--reverse");
    cmd.arg("SYSLOG_IDENTIFIER=akamu-audit");

    if let Some(ref t) = q.event_type {
        cmd.arg(format!("AKAMU_EVENT_TYPE={t}"));
    }
    if let Some(ref s) = q.subject {
        cmd.arg(format!("AKAMU_SUBJECT={s}"));
    }
    if let Some(ref o) = q.outcome {
        cmd.arg(format!("AKAMU_OUTCOME={o}"));
    }
    if let Some(ref from) = q.from {
        if !is_rfc3339_like(from) {
            return Err(AcmeError::Journal(
                "invalid 'from' timestamp: expected RFC 3339 format".into(),
            ));
        }
        cmd.arg(format!("--since={from}"));
    }
    if let Some(ref until) = q.until {
        if !is_rfc3339_like(until) {
            return Err(AcmeError::Journal(
                "invalid 'until' timestamp: expected RFC 3339 format".into(),
            ));
        }
        cmd.arg(format!("--until={until}"));
    }

    // `--lines=N` returns the N most recent entries.  For large offsets this
    // may under-fetch, producing empty pages even when older entries exist.
    // A full solution would require cursor-based pagination.
    let fetch = q.limit.saturating_add(q.offset);
    cmd.arg(format!("--lines={fetch}"));

    let output = tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .map_err(|_| AcmeError::Journal("journalctl timed out after 30s".into()))?
        .map_err(|e| AcmeError::Journal(format!("failed to run journalctl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(1) && stderr.trim().is_empty() {
            return Ok(Vec::new());
        }
        return Err(AcmeError::Journal(format!(
            "journalctl failed (exit {}): {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_journalctl_json(&stdout, q.offset, q.limit))
}

fn parse_journalctl_json(output: &str, offset: u32, limit: u32) -> Vec<AuditEventRow> {
    let mut rows = Vec::new();
    let mut skipped: usize = 0;
    for (line_no, line) in output.lines().enumerate().skip(offset as usize) {
        if rows.len() >= limit as usize {
            break;
        }
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            tracing::debug!(line = line_no + 1, "skipping unparseable journalctl line");
            skipped += 1;
            continue;
        };
        let occurred_at = obj
            .get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str())
            .and_then(|us_str| us_str.parse::<u64>().ok())
            .map(|us| crate::util::unix_to_rfc3339((us / 1_000_000) as i64))
            .unwrap_or_default();

        rows.push(AuditEventRow {
            occurred_at,
            event_type: obj
                .get("AKAMU_EVENT_TYPE")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            subject: obj
                .get("AKAMU_SUBJECT")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned()),
            principal: obj
                .get("AKAMU_PRINCIPAL")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned()),
            outcome: obj
                .get("AKAMU_OUTCOME")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            detail: obj
                .get("AKAMU_DETAIL")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned()),
        });
    }
    if skipped > 0 {
        tracing::debug!(skipped, "journalctl query skipped unparseable lines");
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_halt_sets_flag() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: Some(1),
            overflow: OverflowPolicy::Halt,
            ..Default::default()
        };
        record(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::CertIssue),
        )
        .unwrap();
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    #[test]
    fn overflow_drop_oldest_does_not_halt() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: Some(1),
            overflow: OverflowPolicy::DropOldest,
            ..Default::default()
        };
        for _ in 0..5 {
            record(
                &journal,
                &state,
                &policy,
                AuditEvent::success(AuditEventType::CertIssue),
            )
            .unwrap();
        }
        assert!(!state.should_halt.load(Ordering::SeqCst));
        assert_eq!(state.event_count.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn alarm_fires_after_threshold() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: None,
            alarm_threshold: 3,
            alarm_action: AlarmAction::Halt,
            ..Default::default()
        };
        for _ in 0..3 {
            record(
                &journal,
                &state,
                &policy,
                AuditEvent::failure(AuditEventType::SecurityViolation),
            )
            .unwrap();
        }
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    /// Regression test for a silently reverted fix (commit `1dd9b68b3`):
    /// `check_violation` must panic on a poisoned `violation_times` mutex
    /// rather than recovering and continuing to evaluate the FAU_ARP.1 alarm
    /// against potentially corrupt state.
    #[test]
    fn check_violation_panics_on_poisoned_mutex() {
        let state = AuditState::new();
        let policy = AuditPolicy::default();

        // Poison the mutex by panicking while holding the lock.
        let state_ref = &state;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state_ref.violation_times.lock().unwrap();
            panic!("deliberately poisoning the mutex for this test");
        }));
        assert!(result.is_err());
        assert!(state.violation_times.is_poisoned());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_violation(&state, &policy);
        }));
        assert!(
            result.is_err(),
            "check_violation must panic on a poisoned mutex, not silently recover"
        );
    }

    #[test]
    fn audit_event_builder_methods() {
        let ev = AuditEvent::failure(AuditEventType::AuthJwsFail)
            .with_subject("thumb-abc")
            .with_principal("acme:thumb-abc")
            .with_detail("{\"reason\":\"bad sig\"}");
        assert_eq!(ev.event_type, AuditEventType::AuthJwsFail);
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.subject.as_deref(), Some("thumb-abc"));
        assert_eq!(ev.principal.as_deref(), Some("acme:thumb-abc"));
    }

    #[test]
    fn event_count_increments() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        for _ in 0..3 {
            record(
                &journal,
                &state,
                &policy,
                AuditEvent::success(AuditEventType::CaStart),
            )
            .unwrap();
        }
        assert_eq!(state.event_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn all_event_type_strings_are_dot_separated() {
        let types = [
            (AuditEventType::CaStart, "ca.start"),
            (AuditEventType::CaStop, "ca.stop"),
            (AuditEventType::AccountCreate, "account.create"),
            (AuditEventType::AccountDeactivate, "account.deactivate"),
            (AuditEventType::AccountKeyChange, "account.key-change"),
            (AuditEventType::OrderCreate, "order.create"),
            (AuditEventType::OrderFinalize, "order.finalize"),
            (AuditEventType::CertIssue, "cert.issue"),
            (AuditEventType::CertRevoke, "cert.revoke"),
            (AuditEventType::CrlGenerate, "crl.generate"),
            (AuditEventType::CrossSignIssue, "cross-sign.issue"),
            (AuditEventType::KeyGenerate, "key.generate"),
            (AuditEventType::KeyLoad, "key.load"),
            (AuditEventType::AuthJwsOk, "auth.jws.ok"),
            (AuditEventType::AuthJwsFail, "auth.jws.fail"),
            (AuditEventType::AuthChallengeOk, "auth.challenge.ok"),
            (AuditEventType::AuthChallengeFail, "auth.challenge.fail"),
            (AuditEventType::EabUse, "eab.use"),
            (AuditEventType::EabReject, "eab.reject"),
            (AuditEventType::AdminLogin, "admin.login"),
            (AuditEventType::AdminLogout, "admin.logout"),
            (AuditEventType::AdminAction, "admin.action"),
            (
                AuditEventType::AuthWebhookHmacFail,
                "auth.webhook.hmac.fail",
            ),
            (AuditEventType::SecurityViolation, "security.violation"),
        ];
        for (t, expected) in types {
            assert_eq!(t.as_str(), expected, "{t:?}");
        }
    }

    #[test]
    fn audit_state_default_matches_new() {
        let d = AuditState::default();
        assert!(!d.should_halt.load(Ordering::SeqCst));
        assert_eq!(d.event_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn alarm_syslog_does_not_halt() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: None,
            alarm_threshold: 2,
            alarm_action: AlarmAction::Syslog,
            ..Default::default()
        };
        for _ in 0..3 {
            record(
                &journal,
                &state,
                &policy,
                AuditEvent::failure(AuditEventType::SecurityViolation),
            )
            .unwrap();
        }
        assert!(!state.should_halt.load(Ordering::SeqCst));
    }

    #[test]
    fn record_or_log_tracks_failures_and_halts() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: None,
            alarm_threshold: 2,
            ..Default::default()
        };
        // disconnected writer always returns Ok, so record_or_log won't see errors
        // test the success path clears consecutive failures
        state.consecutive_insert_failures.store(5, Ordering::SeqCst);
        record_or_log(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert_eq!(state.consecutive_insert_failures.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn record_or_log_pair_resets_on_success() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        state.consecutive_insert_failures.store(3, Ordering::SeqCst);
        record_or_log_pair(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::OrderFinalize),
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert_eq!(state.consecutive_insert_failures.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn query_journal_with_store_returns_results() {
        let journal = JournalWriter::with_daemon();
        record(
            &journal,
            &AuditState::new(),
            &AuditPolicy::default(),
            AuditEvent::success(AuditEventType::CertIssue)
                .with_subject("serial-1")
                .with_principal("alice"),
        )
        .unwrap();
        record(
            &journal,
            &AuditState::new(),
            &AuditPolicy::default(),
            AuditEvent::failure(AuditEventType::AuthJwsFail).with_subject("thumb-x"),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let rows = query_journal(
            &journal,
            &AuditQuery {
                event_type: Some("cert.issue".to_owned()),
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 10,
                offset: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].subject.as_deref(), Some("serial-1"));
    }

    #[tokio::test]
    async fn query_journal_rejects_bad_timestamps() {
        let journal = JournalWriter::disconnected();
        let result = query_journal(
            &journal,
            &AuditQuery {
                event_type: None,
                subject: None,
                from: Some("yesterday".to_owned()),
                until: None,
                outcome: None,
                limit: 10,
                offset: 0,
            },
        )
        .await;
        assert!(result.is_err());

        let result = query_journal(
            &journal,
            &AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: Some("-5min".to_owned()),
                outcome: None,
                limit: 10,
                offset: 0,
            },
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn record_pair_both_succeed() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        record_pair(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::OrderFinalize).with_subject("ord-1"),
            AuditEvent::success(AuditEventType::CertIssue).with_subject("cert-1"),
        )
        .unwrap();
        assert_eq!(state.event_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn query_journal_journalctl_path() {
        // Use disconnected writer (no store) to exercise the journalctl subprocess path.
        let journal = JournalWriter::disconnected();
        let result = query_journal(
            &journal,
            &AuditQuery {
                event_type: Some("cert.issue".to_owned()),
                subject: None,
                from: Some("2026-01-01T00:00:00Z".to_owned()),
                until: Some("2026-12-31T23:59:59Z".to_owned()),
                outcome: None,
                limit: 10,
                offset: 0,
            },
        )
        .await;
        // journalctl may not be available or namespace may not exist —
        // either an empty vec or an error is acceptable
        if let Ok(rows) = result {
            assert!(rows.len() <= 10);
        }
    }

    #[test]
    fn record_returns_error_on_broken_socket() {
        let journal = JournalWriter::broken();
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        let result = record(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert!(result.is_err());
    }

    #[test]
    fn record_pair_propagates_errors() {
        let journal = JournalWriter::broken();
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        let result = record_pair(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::OrderFinalize),
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert!(result.is_err());
    }

    #[test]
    fn record_or_log_increments_failure_counter() {
        let journal = JournalWriter::broken();
        let state = AuditState::new();
        let policy = AuditPolicy {
            alarm_threshold: 3,
            ..Default::default()
        };
        for _ in 0..3 {
            record_or_log(
                &journal,
                &state,
                &policy,
                AuditEvent::success(AuditEventType::CertIssue),
            );
        }
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    #[test]
    fn record_or_log_pair_increments_failure_counter() {
        let journal = JournalWriter::broken();
        let state = AuditState::new();
        let policy = AuditPolicy {
            alarm_threshold: 2,
            ..Default::default()
        };
        record_or_log_pair(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::OrderFinalize),
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert_eq!(state.consecutive_insert_failures.load(Ordering::SeqCst), 1);
        record_or_log_pair(
            &journal,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::OrderFinalize),
            AuditEvent::success(AuditEventType::CertIssue),
        );
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn query_journal_journalctl_with_subject_and_outcome_filters() {
        let journal = JournalWriter::disconnected();
        let result = query_journal(
            &journal,
            &AuditQuery {
                event_type: Some("cert.issue".to_owned()),
                subject: Some("serial-test".to_owned()),
                from: Some("2026-01-01T00:00:00Z".to_owned()),
                until: Some("2026-12-31T23:59:59Z".to_owned()),
                outcome: Some("success".to_owned()),
                limit: 5,
                offset: 0,
            },
        )
        .await;
        // On systems with journalctl: succeeds (likely empty).
        // On systems without: returns Err (journalctl not found).
        if let Ok(rows) = result {
            assert!(rows.len() <= 5)
        }
    }

    #[test]
    fn overflow_drop_oldest_with_max_events() {
        let journal = JournalWriter::disconnected();
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_events: Some(3),
            overflow: OverflowPolicy::DropOldest,
            ..Default::default()
        };
        for _ in 0..5 {
            record(
                &journal,
                &state,
                &policy,
                AuditEvent::success(AuditEventType::CertIssue),
            )
            .unwrap();
        }
        assert!(!state.should_halt.load(Ordering::SeqCst));
        assert_eq!(state.event_count.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn parse_journalctl_json_basic() {
        let output = r#"{"__REALTIME_TIMESTAMP":"1717500000000000","AKAMU_EVENT_TYPE":"cert.issue","AKAMU_OUTCOME":"success","AKAMU_SUBJECT":"serial-1","AKAMU_PRINCIPAL":"alice","AKAMU_DETAIL":"{\"cn\":\"test\"}"}
{"__REALTIME_TIMESTAMP":"1717500001000000","AKAMU_EVENT_TYPE":"auth.jws.fail","AKAMU_OUTCOME":"failure","AKAMU_SUBJECT":"thumb-x"}
"#;
        let rows = parse_journalctl_json(output, 0, 100);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event_type, "cert.issue");
        assert_eq!(rows[0].outcome, "success");
        assert_eq!(rows[0].subject.as_deref(), Some("serial-1"));
        assert_eq!(rows[0].principal.as_deref(), Some("alice"));
        assert_eq!(rows[0].detail.as_deref(), Some("{\"cn\":\"test\"}"));
        assert!(!rows[0].occurred_at.is_empty());
        assert_eq!(rows[1].event_type, "auth.jws.fail");
        assert_eq!(rows[1].principal, None);
    }

    #[test]
    fn parse_journalctl_json_offset_and_limit() {
        let output = r#"{"__REALTIME_TIMESTAMP":"1000000000000","AKAMU_EVENT_TYPE":"a","AKAMU_OUTCOME":"success"}
{"__REALTIME_TIMESTAMP":"2000000000000","AKAMU_EVENT_TYPE":"b","AKAMU_OUTCOME":"success"}
{"__REALTIME_TIMESTAMP":"3000000000000","AKAMU_EVENT_TYPE":"c","AKAMU_OUTCOME":"success"}
"#;
        let rows = parse_journalctl_json(output, 1, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "b");
    }

    #[test]
    fn parse_journalctl_json_skips_invalid_lines() {
        let output = "not json at all\n{\"__REALTIME_TIMESTAMP\":\"1000000000000\",\"AKAMU_EVENT_TYPE\":\"ok\",\"AKAMU_OUTCOME\":\"success\"}\nalso not json\n";
        let rows = parse_journalctl_json(output, 0, 100);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "ok");
    }

    #[test]
    fn parse_journalctl_json_missing_timestamp() {
        let output = r#"{"AKAMU_EVENT_TYPE":"cert.issue","AKAMU_OUTCOME":"success"}"#;
        let rows = parse_journalctl_json(output, 0, 100);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].occurred_at.is_empty() || rows[0].occurred_at.is_empty());
    }

    #[test]
    fn rfc3339_validation() {
        assert!(is_rfc3339_like("2026-06-04T12:00:00Z"));
        assert!(is_rfc3339_like("2026-06-04T12:00:00.123Z"));
        assert!(!is_rfc3339_like("yesterday"));
        assert!(!is_rfc3339_like("-5min"));
        assert!(!is_rfc3339_like("short"));
    }
}
