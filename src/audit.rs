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
            max_events: cfg.audit_max_rows.map(|v| v.max(0) as u64),
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
        let mut times = state.violation_times.lock().unwrap_or_else(|e| {
            tracing::error!(
                "violation_times mutex poisoned — FAU_ARP.1 alarm state may be inconsistent"
            );
            e.into_inner()
        });
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
    if let Some(e) = err1 {
        return Err(e);
    }
    if let Some(e) = err2 {
        return Err(e);
    }
    Ok(())
}

pub async fn record_or_log_pair(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev1: AuditEvent,
    ev2: AuditEvent,
) {
    let ev1_type = ev1.event_type.as_str();
    let ev2_type = ev2.event_type.as_str();
    if let Err(e) = record_pair(journal, state, policy, ev1, ev2) {
        let n = state
            .consecutive_insert_failures
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        tracing::error!(
            error = %e,
            event_type1 = ev1_type,
            event_type2 = ev2_type,
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
    } else {
        state
            .consecutive_insert_failures
            .store(0, Ordering::Release);
    }
}

pub async fn record_or_log(
    journal: &JournalWriter,
    state: &AuditState,
    policy: &AuditPolicy,
    ev: AuditEvent,
) {
    let ev_type = ev.event_type.as_str();
    let ev_outcome = ev.outcome.as_str();
    if let Err(e) = record(journal, state, policy, ev) {
        let n = state
            .consecutive_insert_failures
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        tracing::error!(
            error = %e,
            event_type = ev_type,
            outcome = ev_outcome,
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
    } else {
        state
            .consecutive_insert_failures
            .store(0, Ordering::Release);
    }
}

// ── Journal query ─────────────────────────────────────────────────────────────

/// Query the journal for audit events.
///
/// When the journal writer has a built-in daemon (in-memory store), queries
/// it directly.  Otherwise shells out to `journalctl`.
pub async fn query_journal(
    journal: &JournalWriter,
    q: &AuditQuery,
) -> Result<Vec<AuditEventRow>, AcmeError> {
    if journal.has_store() {
        return Ok(journal.query(q));
    }

    let namespace = journal.namespace();
    let mut cmd = tokio::process::Command::new("journalctl");
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
        cmd.arg(format!("--since={from}"));
    }
    if let Some(ref until) = q.until {
        cmd.arg(format!("--until={until}"));
    }

    let fetch = q.limit.saturating_add(q.offset);
    cmd.arg(format!("--lines={fetch}"));

    let output = cmd.output().await.map_err(|e| {
        AcmeError::Database(format!("failed to run journalctl: {e}"))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Exit code 1 with empty output means "no matching entries"
        if output.status.code() == Some(1) && stderr.trim().is_empty() {
            return Ok(Vec::new());
        }
        return Err(AcmeError::Database(format!(
            "journalctl failed (exit {}): {stderr}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();

    for line in stdout.lines().skip(q.offset as usize) {
        if rows.len() >= q.limit as usize {
            break;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
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

    Ok(rows)
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
}
