//! Error type for GSSAPI operations.

use crate::ffi::OmUint32;

/// An error from a GSSAPI call, carrying the major and minor status codes.
#[derive(Debug, thiserror::Error)]
pub enum GssError {
    #[error("gss_import_name failed: major={major:#010x} minor={minor:#010x}")]
    ImportName { major: OmUint32, minor: OmUint32 },

    #[error("gss_acquire_cred_from failed: major={major:#010x} minor={minor:#010x}")]
    AcquireCred { major: OmUint32, minor: OmUint32 },

    #[error("gss_accept_sec_context failed: major={major:#010x} minor={minor:#010x}")]
    AcceptContext { major: OmUint32, minor: OmUint32 },

    #[error("gss_display_name failed: major={major:#010x} minor={minor:#010x}")]
    DisplayName { major: OmUint32, minor: OmUint32 },

    #[error("principal name is not valid UTF-8")]
    InvalidUtf8,

    #[error("service name contains an interior NUL byte")]
    NulInServiceName,

    #[error("keytab path contains an interior NUL byte")]
    NulInKeytabPath,
}
