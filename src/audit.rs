//! Structured audit trail (PP CA v2.1 FAU family).
//!
//! All ACME and administrative operations that must be logged for CC evaluation
//! call [`record`].  The function inserts one row into `audit_events`, enforces
//! the overflow policy (FAU_STG.4), and maintains the rolling SecurityViolation
//! counter for the alarm response (FAU_ARP.1).
//!
//! # Design notes
//!
//! * The `audit_events` table is append-only at the application level
//!   (FAU_STG.1(1)).  Only [`crate::db::audit::delete_oldest`] issues a DELETE,
//!   and only when the overflow policy is `drop_oldest`.
//! * [`AuditState`] lives in `AppState` and survives the lifetime of the server
//!   process.  It holds no DB handles; callers pass the pool explicitly so the
//!   same state type can be used from any async context.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use crate::db::Db;
use crate::error::AcmeError;

pub use crate::db::audit::{AuditEventRow, AuditQuery};

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
    // Order / certificate lifecycle
    OrderCreate,
    OrderFinalize,
    CertIssue,
    CertRevoke,
    CrlGenerate,
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
    // Security anomalies
    SecurityViolation,
}

impl AuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEventType::CaStart => "ca.start",
            AuditEventType::CaStop => "ca.stop",
            AuditEventType::AccountCreate => "account.create",
            AuditEventType::AccountDeactivate => "account.deactivate",
            AuditEventType::OrderCreate => "order.create",
            AuditEventType::OrderFinalize => "order.finalize",
            AuditEventType::CertIssue => "cert.issue",
            AuditEventType::CertRevoke => "cert.revoke",
            AuditEventType::CrlGenerate => "crl.generate",
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
            AuditEventType::SecurityViolation => "security.violation",
        }
    }
}

// ── Outcome ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl AuditOutcome {
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
    pub event_type: AuditEventType,
    /// JWK thumbprint, account UUID, certificate serial, or similar identifier.
    pub subject: Option<String>,
    /// Authenticated identity: operator name or `"acme:<jwk_thumbprint>"`.
    pub principal: Option<String>,
    pub outcome: AuditOutcome,
    /// JSON object with event-specific fields, or `None`.
    pub detail: Option<String>,
}

impl AuditEvent {
    pub fn success(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            subject: None,
            principal: None,
            outcome: AuditOutcome::Success,
            detail: None,
        }
    }

    pub fn failure(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            subject: None,
            principal: None,
            outcome: AuditOutcome::Failure,
            detail: None,
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

// ── Policy types ───────────────────────────────────────────────────────────────

/// What to do when the audit store reaches `max_rows` (FAU_STG.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Refuse new requests until an administrator intervenes.
    Halt,
    /// Delete the oldest rows to make room (rolling window).
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
    /// Maximum number of `audit_events` rows.  `None` = unlimited.
    pub max_rows: Option<i64>,
    pub overflow: OverflowPolicy,
    /// Number of `SecurityViolation` events in a rolling 5-minute window that
    /// triggers the FAU_ARP.1 alarm response.
    pub alarm_threshold: u32,
    pub alarm_action: AlarmAction,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            max_rows: None,
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
}

impl AuditState {
    pub fn new() -> Self {
        Self {
            violation_times: Mutex::new(VecDeque::new()),
            should_halt: AtomicBool::new(false),
        }
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Record ─────────────────────────────────────────────────────────────────────

/// RFC 3339 timestamp for the current moment (seconds precision, UTC, Z suffix).
fn now_rfc3339() -> String {
    let unix = crate::util::unix_now();
    let gt = synta::GeneralizedTime::from_unix(unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

/// Persist one audit event, enforce the overflow policy, and update the
/// FAU_ARP.1 alarm counter.
///
/// # Errors
///
/// Returns `AcmeError::Database` if the INSERT fails.  Overflow-policy errors
/// (failed `delete_oldest`) are also propagated.
pub async fn record(
    db: &Db,
    state: &AuditState,
    policy: &AuditPolicy,
    ev: AuditEvent,
) -> Result<(), AcmeError> {
    let is_violation = ev.event_type == AuditEventType::SecurityViolation;
    let occurred_at = now_rfc3339();

    crate::db::audit::insert(
        db,
        &occurred_at,
        ev.event_type.as_str(),
        ev.subject.as_deref(),
        ev.principal.as_deref(),
        ev.outcome.as_str(),
        ev.detail.as_deref(),
    )
    .await?;

    // FAU_STG.4: overflow enforcement.
    if let Some(max_rows) = policy.max_rows {
        let count = crate::db::audit::count(db).await?;
        if count >= max_rows {
            match policy.overflow {
                OverflowPolicy::Halt => {
                    tracing::error!(
                        max_rows,
                        count,
                        "AUDIT OVERFLOW: halting server (FAU_STG.4)"
                    );
                    state.should_halt.store(true, Ordering::Release);
                }
                OverflowPolicy::DropOldest => {
                    // Drop enough to stay below the cap; cap the single-pass deletion
                    // at 1 000 rows to bound the DELETE latency.
                    let excess = count - max_rows + 1;
                    let n = excess.clamp(1, 1000);
                    tracing::warn!(
                        dropping = n,
                        "audit store full; dropping oldest rows (FAU_STG.4)"
                    );
                    crate::db::audit::delete_oldest(db, n).await?;
                }
            }
        }
    }

    // FAU_ARP.1: rolling-window alarm for repeated SecurityViolation events.
    if is_violation {
        let threshold_exceeded = {
            let mut times = state
                .violation_times
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cutoff = Instant::now() - Duration::from_secs(300);
            times.retain(|&t| t >= cutoff);
            times.push_back(Instant::now());
            times.len() as u32 >= policy.alarm_threshold
        };

        if threshold_exceeded {
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
    }

    Ok(())
}

/// Like [`record`] but logs errors instead of propagating them.
pub async fn record_or_log(
    db: &Db,
    state: &AuditState,
    policy: &AuditPolicy,
    ev: AuditEvent,
) {
    if let Err(e) = record(db, state, policy, ev).await {
        tracing::error!(error = %e, "audit record failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use std::sync::Arc;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1).await.unwrap()
    }

    #[tokio::test]
    async fn record_inserts_event() {
        let db = open_db().await;
        let state = AuditState::new();
        let policy = AuditPolicy::default();
        let ev = AuditEvent::success(AuditEventType::CertIssue)
            .with_subject("acc-123")
            .with_principal("alice");
        record(&db, &state, &policy, ev).await.unwrap();
        assert_eq!(crate::db::audit::count(&db).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn overflow_drop_oldest_enforced() {
        let db = open_db().await;
        let state = AuditState::new();
        let policy = AuditPolicy {
            max_rows: Some(3),
            overflow: OverflowPolicy::DropOldest,
            ..Default::default()
        };
        for _ in 0..5 {
            record(
                &db,
                &state,
                &policy,
                AuditEvent::success(AuditEventType::CertIssue),
            )
            .await
            .unwrap();
        }
        // After 5 inserts with max_rows=3, excess rows should have been trimmed.
        let n = crate::db::audit::count(&db).await.unwrap();
        assert!(n <= 3, "expected ≤3 rows, got {n}");
    }

    #[tokio::test]
    async fn overflow_halt_sets_flag() {
        let db = open_db().await;
        let state = Arc::new(AuditState::new());
        let policy = AuditPolicy {
            max_rows: Some(1),
            overflow: OverflowPolicy::Halt,
            ..Default::default()
        };
        // First event — inserts fine.
        record(
            &db,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::CertIssue),
        )
        .await
        .unwrap();
        // Second event — triggers overflow halt.
        record(
            &db,
            &state,
            &policy,
            AuditEvent::success(AuditEventType::CertIssue),
        )
        .await
        .unwrap();
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn alarm_fires_after_threshold() {
        let db = open_db().await;
        let state = Arc::new(AuditState::new());
        let policy = AuditPolicy {
            max_rows: None,
            alarm_threshold: 3,
            alarm_action: AlarmAction::Halt,
            ..Default::default()
        };
        for _ in 0..3 {
            record(
                &db,
                &state,
                &policy,
                AuditEvent::failure(AuditEventType::SecurityViolation),
            )
            .await
            .unwrap();
        }
        assert!(state.should_halt.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn audit_event_builder_methods() {
        let ev = AuditEvent::failure(AuditEventType::AuthJwsFail)
            .with_subject("thumb-abc")
            .with_principal("acme:thumb-abc")
            .with_detail("{\"reason\":\"bad sig\"}");
        assert_eq!(ev.event_type, AuditEventType::AuthJwsFail);
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.subject.as_deref(), Some("thumb-abc"));
        assert_eq!(ev.principal.as_deref(), Some("acme:thumb-abc"));
    }
}
