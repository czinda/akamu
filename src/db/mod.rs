pub mod accounts;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod eab;
pub mod nonces;
pub mod orders;
pub mod schema;

use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::error::AcmeError;

/// Type alias for the shared SQLite connection pool.
pub type Db = sqlx::SqlitePool;

/// Initialise the database connection pool and run pending migrations.
///
/// # Connection pool sizing
///
/// SQLite serialises all writes, so for write-heavy workloads the practical
/// concurrency is determined by how fast SQLite can process writes, not by the
/// number of connections.  `max_connections(1)` is used for both `:memory:` and
/// file-backed databases:
///
/// - `:memory:` databases require it: every SQLite in-memory connection opens
///   its own private database, so N > 1 connections would produce N independent
///   empty databases.
/// - File-backed databases with WAL mode and multiple connections encounter
///   `SQLITE_BUSY_SNAPSHOT` (error code 517) under concurrent write load.  This
///   extended error is returned when sqlx tries to reuse a read-transaction
///   snapshot that has become stale after another connection committed new data.
///   Unlike `SQLITE_BUSY` (code 5), `SQLITE_BUSY_SNAPSHOT` bypasses the busy
///   handler entirely, so `busy_timeout` has no effect on it.  With a single
///   connection the snapshot is always current and no contention occurs.
///
/// WAL mode is still enabled for file-backed databases: it allows `PRAGMA
/// wal_checkpoint` to run without blocking readers, gives better write
/// throughput for single-writer workloads, and is the recommended mode for
/// concurrent-access scenarios if multiple processes (rather than multiple
/// pool connections) access the file.
pub async fn open(path: &str) -> Result<Db, AcmeError> {
    let pool = if path == ":memory:" {
        let opts = SqliteConnectOptions::new()
            .filename(":memory:")
            .foreign_keys(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open in-memory database: {}", e)))?
    } else {
        // File-backed database: WAL mode for better write throughput; single
        // connection to avoid SQLITE_BUSY_SNAPSHOT contention (see above).
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open database '{}': {}", path, e)))?
    };

    sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .map_err(|e| AcmeError::Database(format!("migration source: {}", e)))?
        .run(&pool)
        .await
        .map_err(|e| AcmeError::Database(format!("migration failed: {}", e)))?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_in_memory_succeeds() {
        let pool = open(":memory:").await.unwrap();
        // Basic sanity: can issue a query.
        let row: (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn open_file_path_creates_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db").to_string_lossy().into_owned();
        // Opens a real file — covers the file-path branch.
        let pool = open(&path).await.unwrap();
        // Verify the schema was created by checking that the accounts table exists.
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 1);
    }
}
