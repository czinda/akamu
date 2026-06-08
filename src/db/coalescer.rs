//! Write-coalescing channel for SQLite.
//!
//! Batches multiple write operations from concurrent handlers into a single
//! `BEGIN IMMEDIATE…COMMIT` transaction, reducing per-issuance transaction
//! overhead.  Each operation gets its own SAVEPOINT for per-op isolation.
//!
//! Only active when `DbKind::Sqlite`.  PostgreSQL and MariaDB use MVCC and
//! do not benefit from write coalescing.

use crate::db::schema::{AccountRow, AuthorizationRow, CertificateRow, OrderRow};
use crate::error::AcmeError;
use sqlx::Connection;
use tokio::sync::{mpsc, oneshot};

/// Inputs for one authorization to insert alongside an order.
pub struct CoalescerAuthzPlan {
    pub authz: AuthorizationRow,
    pub challenges: Vec<(String, String)>,
    pub token: String,
}

/// A write operation submitted to the coalescer.
pub(crate) enum WriteOp {
    NewOrder {
        order: OrderRow,
        authz_plans: Vec<CoalescerAuthzPlan>,
        tkauth_url: Option<String>,
        reply: oneshot::Sender<Result<(), AcmeError>>,
    },
    SetProcessing {
        challenge_id: String,
        now: i64,
        reply: oneshot::Sender<Result<u64, AcmeError>>,
    },
    OnValid {
        challenge_id: String,
        authz_id: String,
        order_id: String,
        now: i64,
        reply: oneshot::Sender<Result<(bool, bool), AcmeError>>,
    },
    OnInvalid {
        challenge_id: String,
        authz_id: String,
        order_id: Option<String>,
        error_json: String,
        now: i64,
        reply: oneshot::Sender<Result<bool, AcmeError>>,
    },
    Finalize {
        cert: CertificateRow,
        order_id: String,
        now: i64,
        pred_cert_uuid: Option<String>,
        star_csr_der: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<bool, AcmeError>>,
    },
    NewAccount {
        account: AccountRow,
        eab_kid: Option<String>,
        now: i64,
        reply: oneshot::Sender<Result<(), AcmeError>>,
    },
}

pub struct WriteCoalescer {
    tx: mpsc::Sender<WriteOp>,
}

impl WriteCoalescer {
    pub async fn new(db_url: &str) -> Result<Self, AcmeError> {
        let mut conn = <sqlx::AnyConnection as Connection>::connect(db_url)
            .await
            .map_err(|e| AcmeError::Database(format!("coalescer connection: {e}")))?;

        for (pragma, critical) in &[
            ("PRAGMA journal_mode=WAL", true),
            ("PRAGMA synchronous=NORMAL", false),
            ("PRAGMA foreign_keys=ON", true),
            ("PRAGMA mmap_size=134217728", false),
            ("PRAGMA cache_size=-65536", false),
            ("PRAGMA temp_store=MEMORY", false),
            ("PRAGMA wal_autocheckpoint=10000", false),
        ] {
            if let Err(e) = sqlx::query(pragma).execute(&mut conn).await {
                if *critical {
                    return Err(AcmeError::Database(format!(
                        "coalescer PRAGMA failed: {pragma}: {e}"
                    )));
                }
                tracing::warn!(pragma, error = %e, "non-critical coalescer PRAGMA failed");
            }
        }

        let (tx, rx) = mpsc::channel(256);
        // Supervisor task: if coalesce_loop panics, rx is dropped inside the
        // panicking task, so future tx.send() calls return Err ("coalescer gone").
        // In-flight ops whose oneshot senders were already queued will hang;
        // that is acceptable for a panic (catastrophic) vs. the previous silent
        // deadlock of all future callers.
        tokio::spawn(async move {
            if let Err(e) = tokio::spawn(coalesce_loop(rx, conn)).await {
                tracing::error!("write coalescer panicked: {e}");
            }
        });
        Ok(Self { tx })
    }

    pub async fn submit_new_order(
        &self,
        order: OrderRow,
        authz_plans: Vec<CoalescerAuthzPlan>,
        tkauth_url: Option<String>,
    ) -> Result<(), AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::NewOrder {
                order,
                authz_plans,
                tkauth_url,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }

    pub async fn submit_set_processing(
        &self,
        challenge_id: String,
        now: i64,
    ) -> Result<u64, AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::SetProcessing {
                challenge_id,
                now,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }

    pub async fn submit_on_valid(
        &self,
        challenge_id: String,
        authz_id: String,
        order_id: String,
        now: i64,
    ) -> Result<(bool, bool), AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::OnValid {
                challenge_id,
                authz_id,
                order_id,
                now,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }

    pub async fn submit_on_invalid(
        &self,
        challenge_id: String,
        authz_id: String,
        order_id: Option<String>,
        error_json: String,
        now: i64,
    ) -> Result<bool, AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::OnInvalid {
                challenge_id,
                authz_id,
                order_id,
                error_json,
                now,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }

    pub async fn submit_finalize(
        &self,
        cert: CertificateRow,
        order_id: String,
        now: i64,
        pred_cert_uuid: Option<String>,
        star_csr_der: Option<Vec<u8>>,
    ) -> Result<bool, AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::Finalize {
                cert,
                order_id,
                now,
                pred_cert_uuid,
                star_csr_der,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }

    pub async fn submit_new_account(
        &self,
        account: AccountRow,
        eab_kid: Option<String>,
        now: i64,
    ) -> Result<(), AcmeError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteOp::NewAccount {
                account,
                eab_kid,
                now,
                reply,
            })
            .await
            .map_err(|_| AcmeError::Database("coalescer gone".into()))?;
        rx.await
            .map_err(|_| AcmeError::Database("coalescer reply dropped".into()))?
    }
}

// ── Coalesce loop ────────────────────────────────────────────────────────────

use sqlx::AnyConnection;

async fn coalesce_loop(mut rx: mpsc::Receiver<WriteOp>, mut conn: AnyConnection) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while let Ok(op) = rx.try_recv() {
            batch.push(op);
        }

        let begin_ok = sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .is_ok();

        if !begin_ok {
            let err = AcmeError::Database("BEGIN IMMEDIATE failed".into());
            for op in batch {
                send_error(op, &err);
            }
            continue;
        }

        let mut deferred: Vec<Box<dyn FnOnce(bool) + Send>> = Vec::with_capacity(batch.len());

        for (i, op) in batch.into_iter().enumerate() {
            let sp = format!("sp{i}");
            let sp_ok = sqlx::query(&format!("SAVEPOINT {sp}"))
                .execute(&mut conn)
                .await
                .is_ok();
            if !sp_ok {
                send_error(op, &AcmeError::Database("savepoint failed".into()));
                continue;
            }

            let op_ok = execute_op(&mut conn, op, &sp, &mut deferred).await;

            if op_ok {
                let _ = sqlx::query(&format!("RELEASE {sp}"))
                    .execute(&mut conn)
                    .await;
            } else {
                let _ = sqlx::query(&format!("ROLLBACK TO {sp}"))
                    .execute(&mut conn)
                    .await;
                let _ = sqlx::query(&format!("RELEASE {sp}"))
                    .execute(&mut conn)
                    .await;
            }
        }

        let commit_ok = sqlx::query("COMMIT").execute(&mut conn).await.is_ok();
        if !commit_ok {
            let _ = sqlx::query("ROLLBACK").execute(&mut conn).await;
        }

        for f in deferred {
            f(commit_ok);
        }
    }
}

fn send_error(op: WriteOp, err: &AcmeError) {
    let err_str = err.to_string();
    match op {
        WriteOp::NewOrder { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
        WriteOp::SetProcessing { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
        WriteOp::OnValid { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
        WriteOp::OnInvalid { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
        WriteOp::Finalize { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
        WriteOp::NewAccount { reply, .. } => {
            let _ = reply.send(Err(AcmeError::Database(err_str)));
        }
    }
}

async fn execute_op(
    conn: &mut AnyConnection,
    op: WriteOp,
    _sp: &str,
    deferred: &mut Vec<Box<dyn FnOnce(bool) + Send>>,
) -> bool {
    match op {
        WriteOp::NewOrder {
            order,
            authz_plans,
            tkauth_url,
            reply,
        } => {
            let result = exec_new_order(conn, &order, &authz_plans, tkauth_url.as_deref()).await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
        WriteOp::SetProcessing {
            challenge_id,
            now,
            reply,
        } => {
            let result =
                crate::db::challenges::set_processing_if_pending(&mut *conn, &challenge_id, now)
                    .await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
        WriteOp::OnValid {
            challenge_id,
            authz_id,
            order_id,
            now,
            reply,
        } => {
            let result = exec_on_valid(conn, &challenge_id, &authz_id, &order_id, now).await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
        WriteOp::OnInvalid {
            challenge_id,
            authz_id,
            order_id,
            error_json,
            now,
            reply,
        } => {
            let result = exec_on_invalid(
                conn,
                &challenge_id,
                &authz_id,
                order_id.as_deref(),
                &error_json,
                now,
            )
            .await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
        WriteOp::Finalize {
            cert,
            order_id,
            now,
            pred_cert_uuid,
            star_csr_der,
            reply,
        } => {
            let result = exec_finalize(
                conn,
                cert,
                &order_id,
                now,
                pred_cert_uuid.as_deref(),
                star_csr_der,
            )
            .await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
        WriteOp::NewAccount {
            account,
            eab_kid,
            now,
            reply,
        } => {
            let result = exec_new_account(conn, account, eab_kid.as_deref(), now).await;
            let ok = result.is_ok();
            deferred.push(Box::new(move |commit_ok| {
                if !commit_ok && ok {
                    let _ = reply.send(Err(AcmeError::Database("batch commit failed".into())));
                } else {
                    let _ = reply.send(result);
                }
            }));
            ok
        }
    }
}

// ── Per-op execution ─────────────────────────────────────────────────────────

async fn exec_new_order(
    conn: &mut AnyConnection,
    order: &OrderRow,
    authz_plans: &[CoalescerAuthzPlan],
    tkauth_url: Option<&str>,
) -> Result<(), AcmeError> {
    crate::db::orders::insert(&mut *conn, order.clone()).await?;
    for plan in authz_plans {
        crate::db::authz::insert(&mut *conn, plan.authz.clone()).await?;
        crate::db::challenges::insert_batch(
            &mut *conn,
            &plan.authz.id,
            &plan.challenges,
            &plan.token,
            order.created,
            tkauth_url,
        )
        .await?;
    }
    Ok(())
}

async fn exec_on_valid(
    conn: &mut AnyConnection,
    challenge_id: &str,
    authz_id: &str,
    order_id: &str,
    now: i64,
) -> Result<(bool, bool), AcmeError> {
    let chall_rows = crate::db::query(
        "UPDATE challenges SET status = 'valid', validated = ?, updated = ?
         WHERE id = ? AND status = 'processing'",
    )
    .bind(now)
    .bind(now)
    .bind(challenge_id)
    .execute(&mut *conn)
    .await
    .map_err(AcmeError::from)?
    .rows_affected();

    if chall_rows == 0 {
        return Ok((false, false));
    }

    crate::db::query("UPDATE authorizations SET status = 'valid', updated = ? WHERE id = ?")
        .bind(now)
        .bind(authz_id)
        .execute(&mut *conn)
        .await
        .map_err(AcmeError::from)?;

    let rows = crate::db::query(
        "UPDATE orders SET status = 'ready', error = NULL, updated = ?
         WHERE id = ?
           AND NOT EXISTS (
               SELECT 1 FROM authorizations
               WHERE order_id = ? AND status != 'valid'
           )",
    )
    .bind(now)
    .bind(order_id)
    .bind(order_id)
    .execute(&mut *conn)
    .await
    .map_err(AcmeError::from)?
    .rows_affected();

    Ok((true, rows > 0))
}

async fn exec_on_invalid(
    conn: &mut AnyConnection,
    challenge_id: &str,
    authz_id: &str,
    order_id: Option<&str>,
    error_json: &str,
    now: i64,
) -> Result<bool, AcmeError> {
    let chall_rows = crate::db::query(
        "UPDATE challenges SET status = 'invalid', error = ?, updated = ?
         WHERE id = ? AND status = 'processing'",
    )
    .bind(error_json)
    .bind(now)
    .bind(challenge_id)
    .execute(&mut *conn)
    .await
    .map_err(AcmeError::from)?
    .rows_affected();

    if chall_rows == 0 {
        return Ok(false);
    }

    crate::db::query("UPDATE authorizations SET status = 'invalid', updated = ? WHERE id = ?")
        .bind(now)
        .bind(authz_id)
        .execute(&mut *conn)
        .await
        .map_err(AcmeError::from)?;

    let oid: Option<String> = if let Some(oid) = order_id {
        Some(oid.to_owned())
    } else {
        crate::db::query_as::<(String,)>("SELECT order_id FROM authorizations WHERE id = ?")
            .bind(authz_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AcmeError::from)?
            .map(|(s,)| s)
    };

    if let Some(oid) = oid {
        crate::db::query(
            "UPDATE orders SET status = 'invalid', error = ?, updated = ? WHERE id = ?",
        )
        .bind(error_json)
        .bind(now)
        .bind(&oid)
        .execute(&mut *conn)
        .await
        .map_err(AcmeError::from)?;
    }

    Ok(true)
}

async fn exec_finalize(
    conn: &mut AnyConnection,
    cert: CertificateRow,
    order_id: &str,
    now: i64,
    pred_cert_uuid: Option<&str>,
    star_csr_der: Option<Vec<u8>>,
) -> Result<bool, AcmeError> {
    let cert_id = cert.id.clone();
    crate::db::certs::insert(&mut *conn, cert).await?;

    crate::db::orders::set_certificate(&mut *conn, order_id, &cert_id, now)
        .await
        .map_err(|e| match e {
            AcmeError::Conflict(_) => AcmeError::OrderNotReady,
            other => other,
        })?;

    let pred_already_replaced = if let Some(pred_uuid) = pred_cert_uuid {
        !crate::db::certs::mark_replaced(&mut *conn, pred_uuid, &cert_id).await?
    } else {
        false
    };

    if let Some(csr_der) = star_csr_der {
        crate::db::orders::set_star_csr(&mut *conn, order_id, csr_der).await?;
    }

    Ok(pred_already_replaced)
}

async fn exec_new_account(
    conn: &mut AnyConnection,
    account: AccountRow,
    eab_kid: Option<&str>,
    now: i64,
) -> Result<(), AcmeError> {
    crate::db::accounts::insert(&mut *conn, account).await?;
    if let Some(kid) = eab_kid {
        crate::db::eab::mark_used(&mut *conn, kid, now).await?;
    }
    Ok(())
}
