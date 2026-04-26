pub mod accounts;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod checkpoints;
pub mod eab;
pub mod nonces;
pub mod orders;
pub mod schema;

use crate::error::AcmeError;

/// Type alias for the shared connection pool (runtime-dispatch Any backend).
pub type Db = sqlx::AnyPool;

/// Which database backend is active.
///
/// Drives `begin_write` only: SQLite requires `BEGIN IMMEDIATE` to prevent
/// `SQLITE_BUSY_SNAPSHOT` (error 517) in WAL mode; PostgreSQL and MariaDB use
/// standard MVCC and need only `BEGIN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbKind {
    Sqlite,
    Postgres,
    MariaDb,
}

impl DbKind {
    /// Infer the backend from the connection URL scheme.
    pub fn from_url(url: &str) -> Self {
        if url.starts_with("postgres") {
            DbKind::Postgres
        } else if url.starts_with("mariadb") || url.starts_with("mysql") {
            DbKind::MariaDb
        } else {
            DbKind::Sqlite
        }
    }
}

/// Register all compiled-in sqlx drivers with the `Any` dispatcher.
///
/// Must be called once at startup, before any pool is created.  It is safe to
/// call multiple times (the registry is idempotent).
pub fn install_drivers() {
    sqlx::any::install_default_drivers();
}

/// Open a connection pool and run pending migrations.
///
/// `url` is a database URL: `sqlite://path`, `sqlite::memory:`,
/// `postgres://…`, or `mariadb://…`.
///
/// `max_connections` controls pool size.  Pass `1` for SQLite (multiple
/// connections cause `SQLITE_BUSY_SNAPSHOT` in WAL mode); pass a higher value
/// for PostgreSQL / MariaDB where MVCC allows real concurrency.
pub async fn open(url: &str, max_connections: u32, migrations_dir: &str) -> Result<Db, AcmeError> {
    // For SQLite file-backed databases, ensure the file is created on first
    // open.  The sqlx URL parser sets create_if_missing=false by default;
    // appending ?mode=rwc (read-write-create) enables it via the SQLite URI
    // parameter.  Skip for :memory: databases (always fresh) and for URLs
    // that already set a mode parameter.
    let owned;
    let effective_url =
        if url.starts_with("sqlite") && !url.contains(":memory:") && !url.contains("mode=") {
            owned = if url.contains('?') {
                format!("{url}&mode=rwc")
            } else {
                format!("{url}?mode=rwc")
            };
            owned.as_str()
        } else {
            url
        };

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(max_connections.max(1))
        .connect(effective_url)
        .await
        .map_err(|e| AcmeError::Database(format!("open database '{url}': {e}")))?;

    // SQLite-specific connection pragmas.  The Any driver forwards these as
    // plain SQL; non-SQLite backends ignore them (PRAGMA is not valid SQL for
    // PostgreSQL/MariaDB and the queries are sent but produce no effect — the
    // Any driver does not filter them, so we guard with a URL prefix check).
    if url.starts_with("sqlite") {
        for pragma in &[
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA mmap_size=134217728",
            "PRAGMA cache_size=-65536",
        ] {
            sqlx::query(pragma).execute(&pool).await.ok();
        }
    }

    sqlx::migrate::Migrator::new(std::path::Path::new(migrations_dir))
        .await
        .map_err(|e| AcmeError::Database(format!("migration source '{migrations_dir}': {e}")))?
        .run(&pool)
        .await
        .map_err(|e| AcmeError::Database(format!("migration failed: {e}")))?;

    Ok(pool)
}

/// Begin a write transaction.
///
/// SQLite needs `BEGIN IMMEDIATE` to prevent `SQLITE_BUSY_SNAPSHOT` (error 517)
/// when the pool has more than one connection in WAL mode.  PostgreSQL and
/// MariaDB use MVCC and need only a standard `BEGIN`.
pub async fn begin_write(
    pool: &Db,
    kind: DbKind,
) -> Result<sqlx::Transaction<'static, sqlx::Any>, AcmeError> {
    let tx = match kind {
        DbKind::Sqlite => pool.begin_with("BEGIN IMMEDIATE").await,
        _ => pool.begin().await,
    }
    .map_err(|e| AcmeError::Database(format!("begin write transaction: {e}")))?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrations_dir() -> &'static str {
        "./migrations/sqlite"
    }

    #[tokio::test]
    async fn open_in_memory_succeeds() {
        install_drivers();
        let pool = open("sqlite::memory:", 1, migrations_dir()).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn open_file_path_creates_and_migrates() {
        install_drivers();
        let dir = tempfile::tempdir().unwrap();
        let path = format!("sqlite://{}", dir.path().join("test.db").to_string_lossy());
        let pool = open(&path, 1, migrations_dir()).await.unwrap();
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 1);
    }

    #[test]
    fn db_kind_from_url() {
        assert_eq!(DbKind::from_url("sqlite::memory:"), DbKind::Sqlite);
        assert_eq!(DbKind::from_url("sqlite:///tmp/foo.db"), DbKind::Sqlite);
        assert_eq!(
            DbKind::from_url("postgres://localhost/acme"),
            DbKind::Postgres
        );
        // "postgresql" starts with "postgres" — both match
        assert_eq!(
            DbKind::from_url("postgresql://localhost/acme"),
            DbKind::Postgres
        );
        assert_eq!(
            DbKind::from_url("mariadb://localhost/acme"),
            DbKind::MariaDb
        );
        assert_eq!(DbKind::from_url("mysql://localhost/acme"), DbKind::MariaDb);
    }
}
