pub mod accounts;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod nonces;
pub mod orders;
pub mod schema;

use rusqlite_migration::{Migrations, M};
use tokio_rusqlite::Connection;

use crate::error::AcmeError;

/// Initialise the database connection and run pending migrations.
pub async fn open(path: &str) -> Result<Connection, AcmeError> {
    let conn = if path == ":memory:" {
        Connection::open_in_memory().await
    } else {
        Connection::open(path).await
    }
    .map_err(|e| AcmeError::Database(format!("open database '{}': {}", path, e)))?;

    // Run migrations synchronously inside the rusqlite background thread
    conn.call(|conn| {
        // Enable foreign-key enforcement before running migrations so that any
        // FK-violating data inserted by a future migration is rejected up-front.
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        let migrations = Migrations::new(vec![
            M::up(include_str!("../../migrations/001_initial.sql")),
            M::up(include_str!("../../migrations/002_renewal_info.sql")),
            M::up(include_str!("../../migrations/003_indexes.sql")),
            M::up(include_str!("../../migrations/004_ari_replaces.sql")),
            M::up(include_str!("../../migrations/005_subdomain_auth.sql")),
        ]);
        migrations.to_latest(conn).map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            )
        })?;
        // Enable WAL mode for this connection (after migrations complete).
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Ok(())
    })
    .await
    .map_err(|e| AcmeError::Database(format!("migration failed: {}", e)))?;

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_in_memory_succeeds() {
        let conn = open(":memory:").await.unwrap();
        // Basic sanity: can issue a query.
        conn.call(|c| {
            let _ = c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn open_file_path_creates_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db").to_string_lossy().into_owned();
        // Opens a real file — covers the `Connection::open(path)` branch.
        let conn = open(&path).await.unwrap();
        conn.call(|c| {
            // Verify the schema was created by checking that the accounts table exists.
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(n, 1);
            Ok(())
        })
        .await
        .unwrap();
    }
}
