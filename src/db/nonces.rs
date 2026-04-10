use tokio_rusqlite::Connection;

use crate::error::AcmeError;

/// Insert a new nonce (must be called before returning it to the client).
pub async fn insert(db: &Connection, nonce: &str) -> Result<(), AcmeError> {
    let nonce = nonce.to_string();
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO nonces (nonce, created) VALUES (?1, ?2)",
            rusqlite::params![nonce, now],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Consume a nonce: returns true if the nonce existed and was deleted,
/// false if it did not exist (replay or unknown).
pub async fn consume(db: &Connection, nonce: &str) -> Result<bool, AcmeError> {
    let nonce = nonce.to_string();
    db.call(move |conn| {
        let n = conn.execute("DELETE FROM nonces WHERE nonce = ?1", rusqlite::params![nonce])?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

/// Delete nonces older than `max_age_secs` seconds.
pub async fn sweep_expired(db: &Connection, max_age_secs: i64) -> Result<u64, AcmeError> {
    let cutoff = now_secs() - max_age_secs;
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM nonces WHERE created < ?1",
            rusqlite::params![cutoff],
        )?;
        Ok(n as u64)
    })
    .await
    .map_err(AcmeError::from)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
