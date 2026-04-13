pub mod accounts;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod eab;
pub mod nonces;
pub mod orders;
pub mod schema;

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{SqliteConnection, SqlitePool};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::error::AcmeError;

/// Unified database handle.
#[derive(Clone)]
pub struct Db(DbInner);

#[derive(Clone)]
enum DbInner {
    /// In-memory: one connection behind an async Tokio mutex.
    /// Mutex lock ≈ 100 ns; 400× cheaper than pool-semaphore acquire.
    Memory(Arc<Mutex<SqliteConnection>>),
    /// File-backed: WAL-mode pool, multiple concurrent readers.
    Pool(SqlitePool),
}

/// An acquired database connection.  Derefs to `&mut SqliteConnection`.
/// Drop to release back to the pool / unlock the mutex.
pub struct OwnedConn(OwnedConnInner);

enum OwnedConnInner {
    Memory(OwnedMutexGuard<SqliteConnection>),
    Pool(sqlx::pool::PoolConnection<sqlx::Sqlite>),
}

impl Deref for OwnedConn {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            OwnedConnInner::Memory(g) => g.deref(),
            OwnedConnInner::Pool(c) => c.deref(),
        }
    }
}

impl DerefMut for OwnedConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.0 {
            OwnedConnInner::Memory(g) => g.deref_mut(),
            OwnedConnInner::Pool(c) => c.deref_mut(),
        }
    }
}

impl Db {
    /// Acquire a connection.  For in-memory databases this locks the mutex;
    /// for file-backed databases this borrows one connection from the pool.
    pub async fn acquire(&self) -> Result<OwnedConn, AcmeError> {
        match &self.0 {
            DbInner::Memory(m) => Ok(OwnedConn(OwnedConnInner::Memory(
                Arc::clone(m).lock_owned().await,
            ))),
            DbInner::Pool(p) => Ok(OwnedConn(OwnedConnInner::Pool(
                p.acquire().await.map_err(|e| AcmeError::Database(e.to_string()))?,
            ))),
        }
    }
}

pub async fn open(path: &str) -> Result<Db, AcmeError> {
    if path == ":memory:" {
        let opts = SqliteConnectOptions::new()
            .filename(":memory:")
            .foreign_keys(true);
        use sqlx::Connection as _;
        let mut conn = SqliteConnection::connect_with(&opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open in-memory database: {}", e)))?;
        sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
            .await
            .map_err(|e| AcmeError::Database(format!("migration source: {}", e)))?
            .run(&mut conn)
            .await
            .map_err(|e| AcmeError::Database(format!("migration failed: {}", e)))?;
        Ok(Db(DbInner::Memory(Arc::new(Mutex::new(conn)))))
    } else {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open database '{}': {}", path, e)))?;
        sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
            .await
            .map_err(|e| AcmeError::Database(format!("migration source: {}", e)))?
            .run(&pool)
            .await
            .map_err(|e| AcmeError::Database(format!("migration failed: {}", e)))?;
        Ok(Db(DbInner::Pool(pool)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_in_memory_succeeds() {
        let db = open(":memory:").await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn open_file_path_creates_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db").to_string_lossy().into_owned();
        let db = open(&path).await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(row.0, 1);
    }
}
