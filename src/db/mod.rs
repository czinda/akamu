pub mod accounts;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod eab;
pub mod nonces;
pub mod orders;
pub mod schema;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

use crate::error::AcmeError;

/// Type alias for the shared SQLite connection pool.
pub type Db = sqlx::SqlitePool;

/// Initialise the database connection pool and run pending migrations.
pub async fn open(path: &str) -> Result<Db, AcmeError> {
    let opts = if path == ":memory:" {
        SqliteConnectOptions::new()
            .filename(":memory:")
            .foreign_keys(true)
    } else {
        SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
    };

    let pool = if path == ":memory:" {
        // In-memory databases require max_connections(1) so all operations
        // share the same connection (each connection would have its own empty DB).
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| AcmeError::Database(format!("open database '{}': {}", path, e)))?
    } else {
        SqlitePool::connect_with(opts)
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
