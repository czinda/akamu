//! Synchronous and asynchronous LDAP client with simple-bind and GSSAPI
//! (Kerberos) authentication.
//!
//! # Variants
//!
//! - **Synchronous** — [`LdapConnection`]: a thin safe wrapper around the
//!   OpenLDAP C library.  Use this when calling from a blocking context or
//!   `tokio::task::spawn_blocking`.
//! - **Asynchronous** — [`AsyncLdapConnection`]: wraps `LdapConnection` in an
//!   `Arc<Mutex<…>>` and dispatches each operation to a blocking thread via
//!   `tokio::task::spawn_blocking`.  Use this from `async fn` code.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use akamu_ldap::{Auth, AsyncLdapConnection, Scope};
//!
//! # async fn example() -> Result<(), akamu_ldap::LdapError> {
//! let conn = AsyncLdapConnection::connect("ldap://ipa.example.com", None, false, 10).await?;
//! conn.bind(Auth::Gssapi).await?;
//! let entries = conn.search(
//!     "ou=people,dc=example,dc=com",
//!     Scope::Subtree,
//!     "(uid=alice)",
//!     vec!["cn".into(), "mail".into()],
//! ).await?;
//! for e in entries {
//!     println!("{}: {:?}", e.dn, e.attrs);
//! }
//! # Ok(())
//! # }
//! ```

pub mod async_conn;
pub mod conn;
pub mod ffi;

pub use async_conn::AsyncLdapConnection;
pub use conn::{LdapConnection, SearchEntry};

use libc::c_int;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("LDAP protocol error {code}: {msg}")]
    Protocol { code: c_int, msg: String },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("NUL byte in argument: {0}")]
    NulByte(String),
    #[error("background task panicked")]
    TaskPanic,
}

impl From<std::ffi::NulError> for LdapError {
    fn from(e: std::ffi::NulError) -> Self {
        LdapError::NulByte(e.to_string())
    }
}

/// LDAP search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The base object only.
    Base,
    /// Immediate children of the base only.
    OneLevel,
    /// The base object and all descendants.
    Subtree,
}

impl Scope {
    pub(crate) fn as_int(self) -> c_int {
        match self {
            Scope::Base => ffi::LDAP_SCOPE_BASE,
            Scope::OneLevel => ffi::LDAP_SCOPE_ONELEVEL,
            Scope::Subtree => ffi::LDAP_SCOPE_SUBTREE,
        }
    }
}

/// Authentication credentials for an LDAP bind.
///
/// Owned strings are used so that `Auth` values can be sent to blocking
/// threads via `spawn_blocking` without lifetime restrictions.
///
/// Both `bind_dn` and `password` are zeroed on drop ([`zeroize::ZeroizeOnDrop`])
/// to reduce the window during which cleartext credentials live in process
/// memory after the bind completes.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub enum Auth {
    /// LDAP simple bind: DN + cleartext password.
    Simple { bind_dn: String, password: String },
    /// SASL GSSAPI bind using the Kerberos ticket-granting ticket in the
    /// current credential cache.  No explicit credentials are required.
    Gssapi,
}
