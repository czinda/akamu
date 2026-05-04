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
    atomic::{AtomicBool, AtomicI64, Ordering},
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
    AccountKeyChange,
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
            AuditEventType::AccountKeyChange => "account.key-change",
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

impl AuditPolicy {
    /// Construct from the `[admin]` TOML config block.
    pub fn from_admin_config(cfg: &crate::config::AdminConfig) -> Self {
        Self {
            max_rows: cfg.audit_max_rows,
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
    /// Approximate total row count in `audit_events`.  Seeded once at startup by
    /// [`AuditState::seed_row_count`] and maintained via atomic increments and
    /// decrements to avoid `SELECT COUNT(*)` on every insert.  A value of `-1`
    /// means "not yet seeded"; `record` falls back to a DB count query in that case.
    pub row_count: AtomicI64,
    /// Consecutive audit insert failures (FAU_STG.1).  Reset to 0 on success;
    /// when this reaches `alarm_threshold`, `should_halt` is set.
    pub consecutive_insert_failures: std::sync::atomic::AtomicU32,
}

impl AuditState {
    pub fn new() -> Self {
        Self {
            violation_times: Mutex::new(VecDeque::new()),
            should_halt: AtomicBool::new(false),
            row_count: AtomicI64::new(-1),
            consecutive_insert_failures: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Seed the in-memory row count from the database.  Call once at startup
    /// after opening the connection pool.
    pub async fn seed_row_count(&self, db: &Db) -> Result<(), AcmeError> {
        let count = crate::db::audit::count(db).await?;
        self.row_count.store(count, Ordering::Release);
        Ok(())
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Record ─────────────────────────────────────────────────────────────────────

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
    let occurred_at = crate::util::rfc3339_now();

    // FAU_STG.1 / FAU_STG.4: INSERT and overflow enforcement must be atomic so
    // that concurrent writes cannot interleave between the COUNT and DELETE and
    // leave the table over the configured cap.
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AcmeError::Database(format!("begin audit transaction: {e}")))?;

    crate::db::audit::insert(
        &mut *tx,
        &occurred_at,
        ev.event_type.as_str(),
        ev.subject.as_deref(),
        ev.principal.as_deref(),
        ev.outcome.as_str(),
        ev.detail.as_deref(),
    )
    .await?;

    // FAU_STG.4: overflow enforcement (inside the same transaction).
    if let Some(max_rows) = policy.max_rows {
        // Use the atomic counter to avoid a COUNT(*) round-trip on every insert.
        // Seed it lazily on first use if not yet initialised (count = -1).
        let count = {
            let prev = state.row_count.fetch_add(1, Ordering::AcqRel);
            if prev < 0 {
                // Not seeded yet — fall back to a DB count and seed the atomic.
                let db_count = crate::db::audit::count(&mut *tx).await?;
                state.row_count.store(db_count, Ordering::Release);
                db_count
            } else {
                prev + 1
            }
        };
        if count >= max_rows {
            // The atomic gives an approximation; concurrent callers can all
            // cross the threshold simultaneously and would each delete based on
            // their (stale) atomic value, over-deleting the table.  Re-count
            // inside the transaction so the delete quantity is authoritative.
            let db_count = crate::db::audit::count(&mut *tx).await?;
            state.row_count.store(db_count, Ordering::Release);
            if db_count >= max_rows {
                match policy.overflow {
                    OverflowPolicy::Halt => {
                        tracing::error!(
                            max_rows,
                            count = db_count,
                            "AUDIT OVERFLOW: halting server (FAU_STG.4)"
                        );
                        state.should_halt.store(true, Ordering::Release);
                    }
                    OverflowPolicy::DropOldest => {
                        // Drop enough to stay below the cap; cap the single-pass
                        // deletion at 1 000 rows to bound the DELETE latency.
                        let excess = db_count - max_rows + 1;
                        let n = excess.clamp(1, 1000);
                        tracing::warn!(
                            dropping = n,
                            "audit store full; dropping oldest rows (FAU_STG.4)"
                        );
                        crate::db::audit::delete_oldest(&mut *tx, n).await?;
                        state.row_count.fetch_sub(n, Ordering::AcqRel);
                    }
                }
            }
        }
    }

    tx.commit()
        .await
        .map_err(|e| AcmeError::Database(format!("commit audit transaction: {e}")))?;

    // FAU_ARP.1: rolling-window alarm for repeated SecurityViolation events.
    if is_violation {
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
///
/// Tracks consecutive insert failures; when they reach `alarm_threshold`,
/// sets `should_halt` (FAU_STG.1 — audit store unavailable).
pub async fn record_or_log(db: &Db, state: &AuditState, policy: &AuditPolicy, ev: AuditEvent) {
    let ev_type = ev.event_type.as_str();
    let ev_outcome = ev.outcome.as_str();
    if let Err(e) = record(db, state, policy, ev).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use std::sync::Arc;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
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
