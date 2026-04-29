//! Async wrapper around [`LdapConnection`].
//!
//! Each method dispatches the blocking OpenLDAP call to a dedicated thread
//! pool via [`tokio::task::spawn_blocking`], so callers never block the async
//! runtime.  The underlying connection is protected by a `tokio::sync::Mutex`
//! so that concurrent callers are serialised rather than creating multiple
//! connections.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{Auth, LdapConnection, LdapError, Scope, SearchEntry};

/// An async LDAP connection backed by a blocking [`LdapConnection`].
///
/// Construct with [`AsyncLdapConnection::connect`], authenticate with
/// [`bind`][Self::bind], then call [`search`][Self::search].
///
/// Cloning is cheap (the underlying connection is behind an `Arc`); all clones
/// share the same physical connection and are serialised by the internal mutex.
#[derive(Clone)]
pub struct AsyncLdapConnection {
    inner: Arc<Mutex<LdapConnection>>,
}

impl AsyncLdapConnection {
    /// Open an LDAP connection to `uri`.
    ///
    /// `tls_ca_cert_file` — if `Some(path)`, the PEM file at `path` is used as
    /// a trusted CA for TLS verification.  A plain `ldap://` URI with a CA
    /// path triggers STARTTLS.
    pub async fn connect(uri: &str, tls_ca_cert_file: Option<&str>) -> Result<Self, LdapError> {
        let uri = uri.to_owned();
        let tls = tls_ca_cert_file.map(str::to_owned);
        let conn = tokio::task::spawn_blocking(move || {
            LdapConnection::connect(&uri, tls.as_deref())
        })
        .await
        .map_err(|_| LdapError::TaskPanic)??;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    /// Authenticate the session.
    ///
    /// See [`Auth`] for supported mechanisms.
    pub async fn bind(&self, auth: Auth) -> Result<(), LdapError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut conn = inner.blocking_lock();
            conn.bind(&auth)
        })
        .await
        .map_err(|_| LdapError::TaskPanic)?
    }

    /// Perform an LDAP search and return all matching entries.
    ///
    /// Arguments are the same as [`LdapConnection::search`].
    pub async fn search(
        &self,
        base: impl Into<String>,
        scope: Scope,
        filter: impl Into<String>,
        attrs: Vec<String>,
    ) -> Result<Vec<SearchEntry>, LdapError> {
        let inner = Arc::clone(&self.inner);
        let base = base.into();
        let filter = filter.into();
        tokio::task::spawn_blocking(move || {
            let mut conn = inner.blocking_lock();
            let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
            conn.search(&base, scope, &filter, &attr_refs)
        })
        .await
        .map_err(|_| LdapError::TaskPanic)?
    }
}
