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
        let migrations = Migrations::new(vec![
            M::up(include_str!("../../migrations/001_initial.sql")),
            M::up(include_str!("../../migrations/002_renewal_info.sql")),
        ]);
        migrations
            .to_latest(conn)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            ))?;
        // Enable WAL mode and foreign keys for this connection
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;",
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AcmeError::Database(format!("migration failed: {}", e)))?;

    Ok(conn)
}
