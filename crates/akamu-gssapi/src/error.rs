//! Error type for GSSAPI operations.

use crate::ffi::OmUint32;

/// An error from a GSSAPI call, carrying the major and minor status codes.
///
/// The `major` code follows the GSS-API bit layout defined in RFC 2743 §1.2.1.
/// The `minor` code is mechanism-specific; for Kerberos it is a MIT krb5 error
/// code that `com_err` can render as a human-readable string.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum GssError {
    /// `gss_import_name` failed to parse the service name string.
    ///
    /// This typically indicates an empty or structurally invalid service name.
    #[error("gss_import_name failed: major={major:#010x} minor={minor:#010x}")]
    ImportName { major: OmUint32, minor: OmUint32 },

    /// `gss_acquire_cred_from` failed to load acceptor credentials from the
    /// keytab.
    ///
    /// Common causes: the keytab file does not exist or is not readable by the
    /// akamu process, the file does not contain a key for the requested
    /// service principal, or the Kerberos libraries are not installed.
    #[error("gss_acquire_cred_from failed: major={major:#010x} minor={minor:#010x}")]
    AcquireCred { major: OmUint32, minor: OmUint32 },

    /// `gss_accept_sec_context` rejected the client token.
    ///
    /// Common causes: the service ticket has expired, the client targeted the
    /// wrong service principal, the token was replayed, or it was forged.
    #[error("gss_accept_sec_context failed: major={major:#010x} minor={minor:#010x}")]
    AcceptContext { major: OmUint32, minor: OmUint32 },

    /// `gss_display_name` failed to convert the authenticated name to a
    /// printable string.
    #[error("gss_display_name failed: major={major:#010x} minor={minor:#010x}")]
    DisplayName { major: OmUint32, minor: OmUint32 },

    /// The display name returned by `gss_display_name` is not valid UTF-8.
    ///
    /// In practice this should not occur with MIT Kerberos, which always
    /// returns ASCII-compatible principal name strings.
    #[error("principal name is not valid UTF-8")]
    InvalidUtf8,

    /// `service_name` passed to [`crate::GssServerCred::acquire`] contains an
    /// interior NUL byte and cannot be passed to the C GSSAPI library.
    #[error("service name contains an interior NUL byte")]
    NulInServiceName,

    /// `keytab_file` passed to [`crate::GssServerCred::acquire`] contains an
    /// interior NUL byte and cannot be passed to the C GSSAPI library.
    #[error("keytab path contains an interior NUL byte")]
    NulInKeytabPath,

    /// The keytab file does not exist or is not readable by the current process.
    ///
    /// Checked before calling into the GSSAPI library so the error message names
    /// the missing path explicitly rather than surfacing an opaque minor status.
    #[error("keytab file not readable: {path}: {source}")]
    KeytabNotReadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `gss_accept_sec_context` succeeded but the returned `ret_flags` do not
    /// include `GSS_C_REPLAY_FLAG`, meaning the context does not guarantee
    /// replay detection.
    #[error("insufficient GSSAPI context flags: ret_flags={ret_flags:#010x} (GSS_C_REPLAY_FLAG not set)")]
    InsufficientFlags { ret_flags: OmUint32 },

    /// `target_service` passed to [`crate::init_token`] contains an interior NUL byte.
    #[error("target service name contains an interior NUL byte")]
    NulInTargetName,

    /// `gss_init_sec_context` failed to produce the initial token.
    #[error("gss_init_sec_context failed: major={major:#010x} minor={minor:#010x}")]
    InitContext { major: OmUint32, minor: OmUint32 },
}
