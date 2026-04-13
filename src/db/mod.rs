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
    open_with_connections(path, 1).await
}

/// Like [`open`] but with a configurable connection pool size.
///
/// `max_connections = 1` is the correct choice for production use (see [`open`]).
/// This variant exists for benchmarking scenarios where the caller wants to
/// measure the effect of a larger pool on file-backed databases.
///
/// **In-memory databases always use `max_connections = 1`** regardless of the
/// value passed: every SQLite in-memory connection opens its own private,
/// empty database, so multiple connections do not share any state.  The
/// `max_connections` argument is silently clamped to `1` when `path == ":memory:"`.
///
/// **When using `max_connections > 1`** all write transactions must be started
/// with [`begin_write`] (`BEGIN IMMEDIATE`) rather than `pool.begin()`
/// (`BEGIN DEFERRED`).  Deferred transactions capture a WAL read snapshot that
/// can become stale after another connection commits, causing
/// `SQLITE_BUSY_SNAPSHOT` (error 517), which bypasses the busy handler and
/// cannot be retried.  `BEGIN IMMEDIATE` acquires the write lock up-front so
/// the snapshot is always current; any resulting `SQLITE_BUSY` (error 5) is
/// handled transparently by the `busy_timeout` configured on the pool.
/// Begin a write transaction using `BEGIN IMMEDIATE`.
///
/// Unlike `pool.begin()` which issues `BEGIN DEFERRED`, this acquires the
/// SQLite write lock at transaction start so the WAL snapshot is always
/// current.  This prevents `SQLITE_BUSY_SNAPSHOT` (error 517) that otherwise
/// occurs in WAL mode when a deferred transaction's read snapshot becomes
/// stale after another connection commits — even when the two transactions
/// write to completely different rows.
///
/// Any `SQLITE_BUSY` (error 5) contention caused by serialising concurrent
/// writers is absorbed transparently by the `busy_timeout` configured on the
/// pool (5 s by default).
///
/// Use this for every transaction that performs writes.  Read-only queries
/// that never write can continue to use `&pool` directly (each query acquires
/// and immediately releases its own implicit read snapshot).
pub async fn begin_write(pool: &Db) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, AcmeError> {
    pool.begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|e| AcmeError::Database(format!("begin write transaction: {e}")))
}

pub async fn open_with_connections(path: &str, max_connections: u32) -> Result<Db, AcmeError> {
    let max_connections = max_connections.max(1);
    let pool = if path == ":memory:" {
        let opts = SqliteConnectOptions::new()
            .filename(":memory:")
            .foreign_keys(true);
        SqlitePoolOptions::new()
            .max_connections(1) // always 1 for :memory: — see module doc
            .connect_with(opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open in-memory database: {}", e)))?
    } else {
        // File-backed database: WAL mode for better write throughput.
        //
        // PRAGMA tuning:
        // - synchronous=NORMAL: in WAL mode only checkpoints sync to disk, not
        //   individual writes. Safe against application crash; the WAL file
        //   protects against OS crash. Reduces per-write latency vs FULL.
        // - mmap_size: map up to 128 MiB of the database file into virtual
        //   memory; reduces pread(2) syscalls for read-heavy workloads.
        // - cache_size: 64 MiB page cache (negative value = KB, not pages).
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5))
            .pragma("synchronous", "NORMAL")
            .pragma("mmap_size", "134217728")
            .pragma("cache_size", "-65536");
        SqlitePoolOptions::new()
            .max_connections(max_connections)
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
        let row: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
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
