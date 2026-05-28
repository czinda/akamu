use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL.  SQLite: `sqlite://path/to/db` or `sqlite::memory:`.
    /// PostgreSQL: `postgres://user:pass@host/dbname`.
    /// MariaDB/MySQL: `mariadb://user:pass@host/dbname` or `mysql://…`.
    pub url: String,
    /// Maximum number of pooled connections.
    /// Defaults to 1 for SQLite (multiple connections cause SQLITE_BUSY_SNAPSHOT),
    /// 10 for PostgreSQL/MariaDB.
    pub max_connections: Option<u32>,
    /// Require TLS for database connections (FPT_ITT.1).
    ///
    /// When `true`, the server refuses to start unless the database URL contains
    /// an SSL/TLS mode parameter that enforces encryption:
    /// - PostgreSQL: `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full`
    /// - MariaDB/MySQL: `ssl-mode=REQUIRED`, `ssl-mode=VERIFY_CA`, or `ssl-mode=VERIFY_IDENTITY`
    /// - SQLite: ignored (local file, no network transport)
    #[serde(default)]
    pub require_tls: bool,
}
