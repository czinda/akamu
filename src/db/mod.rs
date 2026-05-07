//! Database access layer.
//!
//! Each submodule corresponds to one logical table or domain: accounts,
//! operators, orders, authorizations, challenges, certificates, EAB keys,
//! audit events, nonces, MTC checkpoints and cosignatures, and database
//! landmarks.
//!
//! The shared connection pool type [`Db`] is a runtime-dispatch `AnyPool`
//! that supports SQLite, PostgreSQL, and MariaDB via sqlx.  All write
//! transactions on SQLite should go through [`begin_write`] rather than
//! `pool.begin()` to avoid `SQLITE_BUSY_SNAPSHOT` in WAL mode.

pub mod accounts;
pub mod audit;
pub mod authz;
pub mod certs;
pub mod challenges;
pub mod checkpoints;
pub mod cosignatures;
pub mod cross_certs;
pub mod eab;
pub mod landmarks;
pub mod nonces;
pub mod operators;
pub mod orders;
pub mod schema;
pub mod stats;

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

/// Whether the active backend is PostgreSQL.
///
/// sqlx 0.8's `AnyPool` does not reliably rewrite `?` parameter placeholders
/// to `$N` when dispatching to the PostgreSQL backend, because PostgreSQL also
/// uses `?` as the JSONB existence operator and the two conflict in the parser.
/// Call [`pg_sql`] on every SQL string that contains `?` before passing it to
/// sqlx when the backend may be PostgreSQL.
///
/// MariaDB/MySQL use `?` natively, so no rewriting is required for that backend.
static IS_POSTGRES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Rewrite `?` → `$1`, `$2`, … for PostgreSQL; return the string unchanged for
/// all other backends.
///
/// The rewritten string is cached permanently (via `Box::leak`) keyed by the
/// pointer identity of the static string literal, so each unique query string
/// is rewritten at most once regardless of how often the function is called.
///
/// Usage:
/// ```rust,ignore
/// sqlx::query(pg_sql("SELECT … WHERE a = ? AND b = ?"))
///     .bind(v1).bind(v2).fetch_optional(executor).await?
/// ```
pub(crate) fn pg_sql(s: &'static str) -> &'static str {
    if !IS_POSTGRES.get().copied().unwrap_or(false) {
        return s;
    }
    // Cache rewritten strings by the pointer address of the static literal.
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, &'static str>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = s.as_ptr() as usize;
    {
        let guard = cache.lock().unwrap();
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }
    }
    // Slow path: rewrite then store for the lifetime of the process.
    let mut n = 0u32;
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if ch == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(ch);
        }
    }
    let leaked: &'static str = Box::leak(out.into_boxed_str());
    cache.lock().unwrap().insert(key, leaked);
    leaked
}

/// Convenience wrapper: rewrite `?` placeholders for PostgreSQL, then call
/// [`sqlx::query`].  Use this instead of `sqlx::query` for every SQL string
/// that contains at least one `?`.
///
/// The lifetime `'q` is left to the caller to infer from the `.bind()` chain,
/// matching the behaviour of `sqlx::query("literal")`.  `pg_sql` always
/// returns `&'static str` which is a subtype of `&'q str` for any `'q`, so
/// the coercion in the body is always sound.
#[inline]
pub(crate) fn query<'q>(
    sql: &'static str,
) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    sqlx::query(pg_sql(sql))
}

/// Convenience wrapper: rewrite `?` placeholders for PostgreSQL, then call
/// [`sqlx::query_as`].  Use this instead of `sqlx::query_as` for every SQL
/// string that contains at least one `?`.
#[inline]
pub(crate) fn query_as<'q, O>(
    sql: &'static str,
) -> sqlx::query::QueryAs<'q, sqlx::Any, O, sqlx::any::AnyArguments<'q>>
where
    O: for<'r> sqlx::FromRow<'r, sqlx::any::AnyRow>,
{
    sqlx::query_as::<sqlx::Any, O>(pg_sql(sql))
}

/// Dynamic query builder that emits `$N` placeholders for PostgreSQL and `?`
/// for all other backends, solving the same JSONB operator conflict that
/// [`pg_sql`] solves for static SQL strings.
pub(crate) struct DynQueryBuilder<'args> {
    sql: String,
    args: sqlx::any::AnyArguments<'args>,
    bind_count: u32,
    is_postgres: bool,
    /// Set to `true` while inside a `push_values` row so that `push_bind`
    /// emits `, ` before every placeholder except the first in that row.
    in_row: bool,
    /// Becomes `false` after the first `push_bind` call within a row.
    row_first: bool,
}

impl<'args> DynQueryBuilder<'args> {
    pub fn new(initial: &str) -> Self {
        Self {
            sql: initial.to_owned(),
            args: Default::default(),
            bind_count: 0,
            is_postgres: IS_POSTGRES.get().copied().unwrap_or(false),
            in_row: false,
            row_first: false,
        }
    }

    pub fn push(&mut self, sql: &str) -> &mut Self {
        self.sql.push_str(sql);
        self
    }

    pub fn push_bind<T>(&mut self, value: T) -> &mut Self
    where
        T: 'args + sqlx::Encode<'args, sqlx::Any> + sqlx::Type<sqlx::Any> + Send,
    {
        use sqlx::Arguments as _;
        if self.in_row && !self.row_first {
            self.sql.push_str(", ");
        }
        self.row_first = false;
        self.bind_count += 1;
        if self.is_postgres {
            self.sql.push('$');
            self.sql.push_str(&self.bind_count.to_string());
        } else {
            self.sql.push('?');
        }
        let _ = self.args.add(value);
        self
    }

    /// Emit a multi-row VALUES clause, analogous to `QueryBuilder::push_values`.
    ///
    /// Each call to the closure receives `&mut DynQueryBuilder` (so it can call
    /// `push_bind`) and one element from the iterator.  Rows are separated by
    /// `, ` and each row is wrapped in `( … )`.  Column values within a row are
    /// separated by `, ` automatically — the closure only needs to call
    /// `push_bind` for each column.
    pub fn push_values<I, F>(&mut self, iter: I, mut f: F) -> &mut Self
    where
        I: IntoIterator,
        F: FnMut(&mut DynQueryBuilder<'args>, I::Item),
    {
        let mut first_row = true;
        for item in iter {
            if !first_row {
                self.sql.push_str(", ");
            }
            first_row = false;
            self.sql.push('(');
            self.in_row = true;
            self.row_first = true;
            f(self, item);
            self.in_row = false;
            self.sql.push(')');
        }
        self
    }

    pub async fn execute<'e, E>(self, executor: E) -> Result<sqlx::any::AnyQueryResult, AcmeError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Any>,
    {
        Ok(sqlx::query_with::<sqlx::Any, _>(&self.sql, self.args)
            .execute(executor)
            .await?)
    }

    pub async fn fetch_all<'e, E, O>(self, executor: E) -> Result<Vec<O>, AcmeError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Any>,
        O: for<'r> sqlx::FromRow<'r, sqlx::any::AnyRow> + Send + Unpin,
    {
        Ok(sqlx::query_as_with::<sqlx::Any, O, _>(&self.sql, self.args)
            .fetch_all(executor)
            .await?)
    }
}

/// Register all compiled-in sqlx drivers with the `Any` dispatcher.
///
/// Must be called once at startup, before any pool is created.  It is safe to
/// call multiple times (the registry is idempotent).
///
/// Delegates to `install_default_drivers()`, which uses sqlx's own internal
/// feature flags (`#[cfg(feature = "postgres")]` etc.) evaluated in sqlx's
/// compilation context.  This is reliable regardless of how Cargo distributes
/// the `backend-*` feature flags across the workspace build graph: sqlx is
/// compiled with the union of all enabled features, so any backend enabled via
/// `backend-postgres = ["sqlx/postgres"]` is correctly reflected in sqlx's
/// own cfg flags.
pub fn install_drivers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        sqlx::any::install_default_drivers();
    });
}

/// Validate that `url` contains an SSL/TLS mode parameter appropriate for
/// the database backend.  Called at startup when `database.require_tls` is set.
fn validate_db_tls(url: &str) -> Result<(), AcmeError> {
    match DbKind::from_url(url) {
        DbKind::Sqlite => Ok(()),
        DbKind::Postgres => {
            let lower = url.to_lowercase();
            if lower.contains("sslmode=require")
                || lower.contains("sslmode=verify-ca")
                || lower.contains("sslmode=verify-full")
            {
                Ok(())
            } else {
                Err(AcmeError::Config(
                    "database.require_tls is set but the PostgreSQL URL does not contain \
                     sslmode=require, sslmode=verify-ca, or sslmode=verify-full"
                        .to_owned(),
                ))
            }
        }
        DbKind::MariaDb => {
            let lower = url.to_lowercase();
            if lower.contains("ssl-mode=required")
                || lower.contains("ssl-mode=verify_ca")
                || lower.contains("ssl-mode=verify_identity")
            {
                Ok(())
            } else {
                Err(AcmeError::Config(
                    "database.require_tls is set but the MariaDB/MySQL URL does not contain \
                     ssl-mode=REQUIRED, ssl-mode=VERIFY_CA, or ssl-mode=VERIFY_IDENTITY"
                        .to_owned(),
                ))
            }
        }
    }
}

/// Open a connection pool and run pending migrations.
///
/// `url` is a database URL: `sqlite://path`, `sqlite::memory:`,
/// `postgres://…`, or `mariadb://…`.
///
/// `max_connections` controls pool size.  Pass `1` for SQLite (multiple
/// connections cause `SQLITE_BUSY_SNAPSHOT` in WAL mode); pass a higher value
/// for PostgreSQL / MariaDB where MVCC allows real concurrency.
///
/// When `require_tls` is `true`, the URL is checked for an SSL/TLS mode
/// parameter before any connection is attempted (FPT_ITT.1).
pub async fn open(url: &str, max_connections: u32, require_tls: bool) -> Result<Db, AcmeError> {
    if require_tls {
        validate_db_tls(url)?;
    }

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

    IS_POSTGRES
        .set(matches!(DbKind::from_url(url), DbKind::Postgres))
        .ok();

    let map_err = |e| AcmeError::Database(format!("migration failed: {e}"));
    match DbKind::from_url(url) {
        DbKind::Sqlite => sqlx::migrate!("migrations/sqlite")
            .run(&pool)
            .await
            .map_err(map_err)?,
        DbKind::Postgres => sqlx::migrate!("migrations/postgres")
            .run(&pool)
            .await
            .map_err(map_err)?,
        DbKind::MariaDb => sqlx::migrate!("migrations/mariadb")
            .run(&pool)
            .await
            .map_err(map_err)?,
    }

    Ok(pool)
}

/// Open a read-only connection pool to a SQLite file-backed database.
///
/// Returns `None` for `:memory:` databases (each connection is private and
/// would see an empty schema) and for non-SQLite backends where read-write
/// pool splitting is not needed.  Does NOT run migrations.  Callers must
/// ensure the write pool has already opened and migrated the database file.
pub async fn open_ro(url: &str, max_connections: u32) -> Result<Option<Db>, AcmeError> {
    if !url.starts_with("sqlite") || url.contains(":memory:") {
        return Ok(None);
    }
    // Build the read-only URL, preserving existing query parameters but
    // replacing (or adding) `mode=ro`.  Naive `split_once('?')` would discard
    // all existing params; filter them individually instead.
    let ro_url = if let Some((base, query)) = url.split_once('?') {
        let filtered: Vec<&str> = query
            .split('&')
            .filter(|p| !p.starts_with("mode="))
            .collect();
        if filtered.is_empty() {
            format!("{base}?mode=ro")
        } else {
            format!("{base}?{}&mode=ro", filtered.join("&"))
        }
    } else {
        format!("{url}?mode=ro")
    };

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(max_connections.max(1))
        .connect(&ro_url)
        .await
        .map_err(|e| AcmeError::Database(format!("open read-only database '{url}': {e}")))?;

    for pragma in &["PRAGMA mmap_size=134217728", "PRAGMA cache_size=-65536"] {
        sqlx::query(pragma).execute(&pool).await.ok();
    }

    Ok(Some(pool))
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

/// Issue `SET LOCAL synchronous_commit = off` inside the current PostgreSQL
/// transaction, eliminating the per-commit WAL flush (~1–4 ms on SSD) for
/// state transitions that are eventually consistent by ACME protocol design.
///
/// Safe for challenge validation, order/authz creation, and the invalid-path
/// writes — the client re-polls if the server restarts mid-flight.  Do NOT
/// call this before inserting an issued certificate; cert durability is a hard
/// requirement.
///
/// No-op on SQLite and MariaDB.
pub(crate) async fn pg_local_async_commit(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    kind: DbKind,
) -> Result<(), sqlx::Error> {
    if kind == DbKind::Postgres {
        sqlx::query("SET LOCAL synchronous_commit = off")
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_in_memory_succeeds() {
        install_drivers();
        let pool = open("sqlite::memory:", 1, false).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn open_file_path_creates_and_migrates() {
        install_drivers();
        let dir = tempfile::tempdir().unwrap();
        let path = format!("sqlite://{}", dir.path().join("test.db").to_string_lossy());
        let pool = open(&path, 1, false).await.unwrap();
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

    #[tokio::test]
    async fn open_ro_returns_none_for_memory_db() {
        install_drivers();
        let result = open_ro("sqlite::memory:", 2).await.unwrap();
        assert!(result.is_none(), "open_ro must return None for :memory:");
    }

    #[tokio::test]
    async fn open_ro_returns_none_for_postgres_url() {
        install_drivers();
        // Not a SQLite URL — open_ro returns None without attempting a connection.
        let result = open_ro("postgres://localhost/acme", 2).await.unwrap();
        assert!(result.is_none(), "open_ro must return None for non-SQLite");
    }

    #[tokio::test]
    async fn open_ro_returns_pool_for_file_backed_sqlite() {
        install_drivers();
        let dir = tempfile::tempdir().unwrap();
        let path = format!(
            "sqlite://{}",
            dir.path().join("ro_test.db").to_string_lossy()
        );
        // Write pool must be opened first to create the schema.
        let _rw = open(&path, 1, false).await.unwrap();
        let ro = open_ro(&path, 2).await.unwrap();
        assert!(
            ro.is_some(),
            "open_ro must return Some for file-backed SQLite"
        );
        let pool = ro.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn open_ro_preserves_existing_query_params() {
        install_drivers();
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir
            .path()
            .join("param_test.db")
            .to_string_lossy()
            .to_string();
        // URL with an existing query param (immutable is not valid with mode=ro together
        // but cache=shared is a valid combination to test param preservation).
        let url_with_params = format!("sqlite://{}?cache=shared", base_path);
        let _rw = open(&format!("sqlite://{}", base_path), 1, false)
            .await
            .unwrap();
        // open_ro should preserve cache=shared and add mode=ro.
        let ro = open_ro(&url_with_params, 1).await.unwrap();
        assert!(ro.is_some(), "open_ro must work with existing query params");
    }

    #[test]
    fn validate_db_tls_sqlite_always_ok() {
        assert!(validate_db_tls("sqlite::memory:").is_ok());
        assert!(validate_db_tls("sqlite:///tmp/foo.db").is_ok());
    }

    #[test]
    fn validate_db_tls_postgres_requires_sslmode() {
        assert!(validate_db_tls("postgres://localhost/acme").is_err());
        assert!(validate_db_tls("postgres://localhost/acme?sslmode=prefer").is_err());
        assert!(validate_db_tls("postgres://localhost/acme?sslmode=require").is_ok());
        assert!(validate_db_tls("postgres://localhost/acme?sslmode=verify-ca").is_ok());
        assert!(validate_db_tls("postgres://localhost/acme?sslmode=verify-full").is_ok());
    }

    #[test]
    fn validate_db_tls_mariadb_requires_ssl_mode() {
        assert!(validate_db_tls("mysql://localhost/acme").is_err());
        assert!(validate_db_tls("mariadb://localhost/acme").is_err());
        assert!(validate_db_tls("mysql://localhost/acme?ssl-mode=REQUIRED").is_ok());
        assert!(validate_db_tls("mariadb://localhost/acme?ssl-mode=VERIFY_CA").is_ok());
        assert!(validate_db_tls("mysql://localhost/acme?ssl-mode=VERIFY_IDENTITY").is_ok());
    }
}
