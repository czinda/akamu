//! Server-side GSSAPI / SPNEGO support for akamu.
//!
//! # Typical usage
//!
//! At startup, acquire a server credential from the HTTP service keytab:
//!
//! ```no_run
//! let cred = akamu_gssapi::GssServerCred::acquire("HTTP", "/etc/akamu/http.keytab", false)
//!     .expect("GSSAPI credential");
//! ```
//!
//! For each incoming `Authorization: Negotiate <base64>` request, call
//! [`accept_token`] and match on [`AcceptStep`]:
//!
//! ```no_run
//! # let cred = akamu_gssapi::GssServerCred::acquire("HTTP", "/etc/akamu/http.keytab", false)
//! #     .expect("GSSAPI credential");
//! # let token_bytes: Vec<u8> = vec![];
//! match akamu_gssapi::accept_token(&cred, &token_bytes, None).expect("GSSAPI accept") {
//!     akamu_gssapi::AcceptStep::Complete { out_token, principal } => {
//!         // `principal` is e.g. "user@REALM"
//!         // `out_token` is the optional mutual-auth response (may be empty)
//!     }
//!     akamu_gssapi::AcceptStep::Continue { out_token, ctx } => {
//!         // Send `out_token` as `WWW-Authenticate: Negotiate <base64>` with 401.
//!         // On the next request, call `ctx.step(...)` with the client's new token.
//!     }
//! }
//! ```
//!
//! # Thread safety
//!
//! [`GssServerCred`] is `Send`.  When built against MIT Kerberos (the default;
//! controlled by `cfg(mit_kerberos)` in `build.rs`), it is also `Sync`, allowing
//! a single `Arc<GssServerCred>` to be shared across all request-handling threads.
//! MIT Kerberos guarantees that `gss_accept_sec_context` is safe for concurrent
//! use with the same acceptor credential; Heimdal does not.

pub mod error;
mod ffi;
mod status;
mod thread_ccache;

use std::ffi::{CStr, CString};
use std::ptr;

pub use error::GssError;
pub use status::format_gss_status;
pub use thread_ccache::{set_thread_ccache, thread_ccache_name};

// ── GssServerCred ─────────────────────────────────────────────────────────────

/// Server-side GSSAPI credential, acquired from a keytab at startup.
///
/// The underlying `gss_cred_id_t` is safe to use from multiple threads
/// simultaneously for `gss_accept_sec_context` calls (MIT Kerberos guarantees
/// this for acceptor credentials).
///
/// Drop releases the credential handle via `gss_release_cred`.
pub struct GssServerCred {
    raw: ffi::GssCredIdT,
}

impl std::fmt::Debug for GssServerCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssServerCred")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: gss_cred_id_t is a pointer owned exclusively by this struct.
// Moving it to another thread is safe; the raw pointer carries no thread affinity.
unsafe impl Send for GssServerCred {}

// SAFETY: MIT Kerberos explicitly documents that gss_accept_sec_context is
// thread-safe for concurrent calls with the same acceptor credential.
// This impl is gated on cfg(mit_kerberos) (set by build.rs) because Heimdal
// and other GSSAPI implementations do NOT make this guarantee.
#[cfg(mit_kerberos)]
unsafe impl Sync for GssServerCred {}

impl Drop for GssServerCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.  The pointer is set to null by gss_release_cred.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut self.raw) };
        }
    }
}

impl GssServerCred {
    /// Acquire a server credential for `service_name` using the keytab at
    /// `keytab_file`.
    ///
    /// The name format is auto-detected:
    ///
    /// - **Host-based service** (`"HTTP"` or `"HTTP@hostname"`) — imported with
    ///   `GSS_C_NT_HOSTBASED_SERVICE`.  MIT Kerberos appends `@<local-hostname>`
    ///   when no host part is given.
    /// - **Full Kerberos principal** (`"HTTP/host@REALM"`) — imported with
    ///   `GSS_KRB5_NT_PRINCIPAL_NAME`.  No canonicalization or lowercasing is
    ///   applied; the principal must match the keytab entry exactly.
    ///
    /// A name containing `/` is treated as a Kerberos principal; otherwise it is
    /// treated as a host-based service name.
    ///
    /// `for_impersonation` controls the GSSAPI credential usage flag:
    /// - `false` → `GSS_C_ACCEPT` — accept-only, for endpoints that only
    ///   validate incoming Negotiate tokens (e.g. admin GSSAPI auth).
    /// - `true` → `GSS_C_BOTH` — the credential must also work as an
    ///   initiator for `gss_acquire_cred_impersonate_name` (S4U2Self).
    ///   Requires a TGT in the default ccache or a client keytab entry.
    ///
    /// Uses `gss_acquire_cred_from()` (RFC 5587) with a credential store entry
    /// `{key="keytab", value=keytab_file}`, which avoids any environment-variable
    /// mutation and is safe to call from multiple threads.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInServiceName`] — `service_name` contains a NUL byte.
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the service name.
    /// - [`GssError::AcquireCred`] — `gss_acquire_cred_from` failed (keytab
    ///   missing, wrong principal, or Kerberos library error).
    pub fn acquire(
        service_name: &str,
        keytab_file: &str,
        for_impersonation: bool,
    ) -> Result<Self, GssError> {
        // Validate strings first so NUL-byte errors are reported before any I/O.
        let svc_cstr = CString::new(service_name).map_err(|_| GssError::NulInServiceName)?;
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        // Pre-flight readability check before calling into the GSSAPI library so that a
        // missing or wrong-path keytab produces a clear error rather than an
        // opaque major/minor status pair.
        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        let mut minor: ffi::OmUint32 = 0;

        // If the name contains '/', treat it as a full Kerberos principal
        // (e.g. "HTTP/host@REALM") and import with GSS_KRB5_NT_PRINCIPAL_NAME
        // to avoid the lowercasing and realm-resolution issues of the
        // host-based service name type.
        let svc_oid = if service_name.contains('/') {
            ffi::gss_krb5_nt_principal_name()
        } else {
            ffi::gss_c_nt_hostbased_service()
        };
        let svc_buf = ffi::GssBufferDesc {
            length: svc_cstr.as_bytes().len(),
            // SAFETY: gss_import_name treats input_name_buffer as read-only per
            // RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
            #[allow(clippy::as_ptr_cast_mut)]
            value: svc_cstr.as_ptr() as *mut _,
        };
        let mut svc_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: all arguments are valid: minor points to a local u32, svc_buf
        // wraps a valid CString slice, svc_oid is a well-formed OID descriptor,
        // svc_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const svc_buf,
                &raw const svc_oid,
                &raw mut svc_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (service name) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }

        // Build the credential store: one element {key="keytab", value=<path>}.
        let key_keytab = c"keytab";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_keytab.as_ptr(),
            value: kt_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        let cred_usage = if for_impersonation {
            ffi::GSS_C_BOTH
        } else {
            ffi::GSS_C_ACCEPT
        };

        // SAFETY: all arguments are valid; svc_name was returned by gss_import_name,
        // cred_store elements point to live CStrings, output pointers are valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                svc_name,
                0, // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                cred_usage,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        // Snapshot the error minor before cleanup calls overwrite it.
        let error_minor = minor;

        // Release the name and the actual_mechs set regardless of success/failure.
        // SAFETY: svc_name is a valid GssNameT returned by gss_import_name above.
        unsafe {
            ffi::gss_release_name(&raw mut minor, &raw mut svc_name);
            if !actual_mechs.is_null() {
                // SAFETY: actual_mechs is non-null and was set by gss_acquire_cred_from.
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            // Defensively release a potentially non-null cred_handle on failure.
            // RFC 2743 §2.1.1 says it is NULL on failure, but non-conformant
            // implementations may write a partial handle.
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (server keytab) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssServerCred { raw: cred_handle })
    }

    /// Acquire a server credential for `service_name` via gssproxy.
    ///
    /// Calls `gss_acquire_cred_from()` with a null credential store, which is
    /// equivalent to `gss_acquire_cred()`.  When gssproxy is active for this
    /// process (matching UID / service entry in `/etc/gssproxy/conf.d/`), it
    /// intercepts the call and supplies credentials from the configured keytab
    /// without requiring the process to have direct keytab file access.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInServiceName`] — `service_name` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the service name.
    /// - [`GssError::AcquireCred`] — gssproxy denied the request, the service
    ///   has no gssproxy entry, or the Kerberos library returned an error.
    pub fn from_gssproxy(_service_name: &str) -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // Pass GSS_C_NO_NAME (NULL) as desired_name so gssproxy selects the
        // acceptor credential from its configured keytab without any name
        // serialisation on our side.  Passing a stack-allocated OID descriptor
        // (as gss_c_nt_hostbased_service() returns) causes proxymech to call
        // generic_gss_release_oid on an OID whose elements point to static
        // memory, triggering a glibc heap-corruption abort.
        //
        // SAFETY: NULL cred_store == GSS_C_NO_CRED_STORE; gssproxy intercepts
        // based on the process UID matching the service entry.  All output
        // pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                // GSS_C_BOTH: must support INITIATE as well as ACCEPT so this
                // credential can serve as the impersonator in S4U2Self calls
                // (gss_acquire_cred_impersonate_name).  GSS_C_ACCEPT-only is
                // rejected by gssproxy for impersonation requests.
                ffi::GSS_C_BOTH,
                ptr::null(), // cred_store = GSS_C_NO_CRED_STORE → gssproxy
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (gssproxy) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssServerCred { raw: cred_handle })
    }

    /// Return the service principal name stored in this credential, e.g.
    /// `"HTTP/hostname@REALM"`.
    ///
    /// Calls `gss_inquire_cred` to retrieve the internal name, then
    /// `gss_display_name` to convert it to a UTF-8 string.  Returns `None`
    /// if either call fails or if the result is not valid UTF-8.
    pub fn principal_name(&self) -> Option<String> {
        let mut minor: ffi::OmUint32 = 0;
        let mut name: ffi::GssNameT = ptr::null_mut();

        // SAFETY: self.raw is a valid credential handle; name is an
        // output-only pointer; the three trailing outputs we don't need are
        // null (no-op).
        let major = unsafe {
            ffi::gss_inquire_cred(
                &raw mut minor,
                self.raw,
                &raw mut name,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if major != ffi::GSS_S_COMPLETE || name.is_null() {
            tracing::debug!(
                major,
                minor,
                "gss_inquire_cred failed or returned null name"
            );
            return None;
        }

        let mut buf = ffi::GssBufferDesc {
            length: 0,
            value: ptr::null_mut(),
        };
        let mut name_type: *mut ffi::GssOidDesc = ptr::null_mut();
        // SAFETY: name is non-null, buf and name_type are valid output-only locals.
        let major2 = unsafe {
            ffi::gss_display_name(&raw mut minor, name, &raw mut buf, &raw mut name_type)
        };

        let result = if major2 == ffi::GSS_S_COMPLETE && !buf.value.is_null() {
            // SAFETY: buf.value points to a GSSAPI-allocated buffer of length buf.length.
            let slice = unsafe { std::slice::from_raw_parts(buf.value as *const u8, buf.length) };
            std::str::from_utf8(slice).ok().map(str::to_owned)
        } else {
            None
        };

        // SAFETY: buf was returned by gss_display_name and must be released.
        unsafe {
            if !buf.value.is_null() {
                ffi::gss_release_buffer(&raw mut minor, &raw mut buf);
            }
            ffi::gss_release_name(&raw mut minor, &raw mut name);
        }

        result
    }
}

// ── GssClientCred ─────────────────────────────────────────────────────────────

/// Client-side GSSAPI credential loaded from a keytab.
///
/// Used to obtain service tickets for a target service (e.g. `"HTTP@hostname"`).
/// The underlying `gss_cred_id_t` is safe to use from multiple threads
/// simultaneously for `gss_init_sec_context` calls (MIT Kerberos guarantees
/// this for initiator credentials).
///
/// Drop releases the credential handle via `gss_release_cred`.
pub struct GssClientCred {
    raw: ffi::GssCredIdT,
}

impl std::fmt::Debug for GssClientCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssClientCred")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: gss_cred_id_t is a pointer owned exclusively by this struct.
// Moving it to another thread is always safe — no concurrent access occurs,
// which Send does not imply. Concurrent shared access requires MIT Kerberos
// (see cfg-gated Sync impl below).
unsafe impl Send for GssClientCred {}
#[cfg(mit_kerberos)]
unsafe impl Sync for GssClientCred {}

impl Drop for GssClientCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut self.raw) };
        }
    }
}

impl GssClientCred {
    /// Acquire an initiator credential from the caller's ambient Kerberos ticket cache.
    ///
    /// Equivalent to `from_ccache(false)`.  Requires a prior `kinit`; does not
    /// touch any keytab.  Intended for CLI tools that run in a user's login session.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcquireCred`] — no valid TGT in the ccache or the Kerberos
    ///   library returned an error.
    pub fn ambient() -> Result<Self, GssError> {
        Self::from_ccache(false)
    }

    /// Acquire a credential from the default Kerberos credential cache (ccache).
    ///
    /// The calling process must already hold a valid TGT (e.g. from `kinit`).
    /// No keytab is required.  Passing `GSS_C_NO_CRED_STORE` (NULL) for the
    /// credential store makes MIT Kerberos use the ambient ccache, identical
    /// to calling `gss_acquire_cred()` with default arguments.
    ///
    /// `for_impersonation` controls the GSSAPI credential usage flag:
    /// - `false` → `GSS_C_INITIATE` — for pure initiator use (LDAP bind,
    ///   token fetch). Use when the credential will never be passed to
    ///   `gss_acquire_cred_impersonate_name` or act as an ACCEPT responder.
    /// - `true` → `GSS_C_BOTH` — when the same credential must also serve as
    ///   the impersonator for S4U2Self or as an ACCEPT responder for SPNEGO.
    ///   Note: in gssproxy mode with an existing ACCEPT credential in the
    ///   union table, `GSS_C_BOTH` causes the union mechanism to pass that
    ///   credential as `input_cred_handle`, triggering an AS exchange; only
    ///   pass `true` when the impersonator role is actually required.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcquireCred`] — no valid TGT in the ccache, or the
    ///   Kerberos library returned an error.
    pub fn from_ccache(for_impersonation: bool) -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        let cred_usage = if for_impersonation {
            ffi::GSS_C_BOTH
        } else {
            ffi::GSS_C_INITIATE
        };

        // SAFETY: NULL for cred_store == GSS_C_NO_CRED_STORE; MIT Kerberos
        // falls back to the default ccache, matching gss_acquire_cred() behaviour.
        // desired_name = GSS_C_NO_NAME selects the default principal.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                cred_usage,
                ptr::null(), // cred_store = GSS_C_NO_CRED_STORE → default ccache
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (default ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire an initiator credential from the keytab at `keytab_file`.
    ///
    /// Passes `desired_name = NULL` so the GSSAPI library selects the credential
    /// from the keytab that can obtain a service ticket for the requested target.
    /// Uses `gss_acquire_cred_from()` (RFC 5587) with `GSS_C_INITIATE`.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::AcquireCred`] — `gss_acquire_cred_from` failed (keytab
    ///   missing, no usable credential, or Kerberos library error).
    pub fn from_keytab(keytab_file: &str) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        let mut minor: ffi::OmUint32 = 0;

        let key_keytab = c"keytab";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_keytab.as_ptr(),
            value: kt_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: all arguments are valid; desired_name=NULL lets the library
        // choose the credential; output pointers are valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = NULL
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // SAFETY: actual_mechs is non-null when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(keytab = keytab_file, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (keytab) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire a combined initiator+acceptor credential from the keytab at `keytab_file`.
    ///
    /// Sets both `{"client_keytab": path}` (for `GSS_C_INITIATE`) and
    /// `{"keytab": path}` (for `GSS_C_ACCEPT`) in the credential store, then calls
    /// `gss_acquire_cred_from()` with `GSS_C_BOTH`.  MIT Kerberos uses `client_keytab`
    /// to obtain a TGT automatically (no `kinit` required); gssproxy, when active, is
    /// told exactly which keytab to use for both roles via the same two keys.
    ///
    /// `desired_name = NULL` lets the library choose the principal from the keytab.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInCcacheName`] — `ccache` contains a NUL byte.
    /// - [`GssError::AcquireCred`] — `gss_acquire_cred_from` failed.  In
    ///   gssproxy mode the daemon reads the keytab; the process itself does not
    ///   need read permission on the file.
    pub fn from_keytab_combined(keytab_file: &str, ccache: Option<&str>) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let cc_cstr = ccache
            .map(CString::new)
            .transpose()
            .map_err(|_| GssError::NulInCcacheName)?;

        tracing::debug!(
            keytab = keytab_file,
            ccache,
            "gss_acquire_cred_from client_keytab+keytab+ccache GSS_C_BOTH"
        );

        let mut minor: ffi::OmUint32 = 0;

        let key_client_keytab = c"client_keytab";
        let key_keytab = c"keytab";
        let key_ccache = c"ccache";

        // Build element list: always keytab + client_keytab, add ccache when provided.
        // The ccache entry is what allows gssproxy to store the acquired TGT and return
        // a usable credential handle — without it gssproxy acquires the TGT but cannot
        // persist it and returns an error (matching mod_auth_gssapi's GssapiCredStore
        // keytab + client_keytab + ccache triple).
        let mut elements: Vec<ffi::GssKeyValueElementDesc> = vec![
            ffi::GssKeyValueElementDesc {
                key: key_client_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
            ffi::GssKeyValueElementDesc {
                key: key_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
        ];
        if let Some(ref cc) = cc_cstr {
            elements.push(ffi::GssKeyValueElementDesc {
                key: key_ccache.as_ptr(),
                value: cc.as_ptr(),
            });
        }
        let cred_store = ffi::GssKeyValueSetDesc {
            count: elements.len() as ffi::OmUint32,
            elements: elements.as_mut_ptr(),
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: elements lives until gss_acquire_cred_from returns; kt_cstr and
        // the two key literals are all live for this scope; output pointers are
        // valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_BOTH,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(keytab = keytab_file, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (keytab combined) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        tracing::debug!(
            keytab = keytab_file,
            lifetime_secs = time_rec,
            "gss_acquire_cred_from ok"
        );
        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire an initiator credential by getting a TGT from `keytab_file` for
    /// `principal` (equivalent to `kinit -k -t keytab principal`).
    ///
    /// Uses `krb5_get_init_creds_keytab` to obtain a TGT, stores it in the
    /// in-process ccache `MEMORY:akamu-initiator`, then acquires a GSSAPI
    /// initiator credential from that ccache.  The resulting credential can be
    /// passed to [`GssClientCred::impersonate`] for S4U2Self LDAP binds.
    ///
    /// **Single-use ccache constraint**: this function writes to a fixed in-process
    /// `MEMORY:akamu-initiator` ccache.  Calling it concurrently from multiple
    /// threads will race on that ccache.  The intended usage pattern is a single
    /// call at startup (inside a `spawn_blocking` task) followed by reuse of the
    /// returned credential handle.  For per-call ccache isolation use
    /// [`GssClientCred::from_keytab_initiate_named`] instead.
    ///
    /// The TGT is valid for the lifetime configured by the KDC (typically 24 h).
    /// Restart akamu to renew it.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInUserPrincipal`] — `principal` contains a NUL byte.
    /// - [`GssError::KeytabNotReadable`] — keytab file cannot be opened.
    /// - [`GssError::Krb5`] — libkrb5 TGT acquisition failed.
    /// - [`GssError::AcquireCred`] — GSSAPI credential acquisition from ccache failed.
    pub fn from_keytab_initiate(keytab_file: &str, principal: &str) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let principal_cstr = CString::new(principal).map_err(|_| GssError::NulInUserPrincipal)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        // SAFETY: each pointer is initialised before use; on error we clean up in
        // reverse-acquisition order (no double-free, no leak).
        unsafe {
            let mut ctx: ffi::Krb5Context = ptr::null_mut();
            let ret = ffi::krb5_init_context(&raw mut ctx);
            if ret != 0 {
                tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_init_context",
                });
            }

            let mut principal_h: ffi::Krb5Principal = ptr::null_mut();
            let ret = ffi::krb5_parse_name(ctx, principal_cstr.as_ptr(), &raw mut principal_h);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_parse_name failed");
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_parse_name",
                });
            }

            let mut kt: ffi::Krb5Keytab = ptr::null_mut();
            let ret = ffi::krb5_kt_resolve(ctx, kt_cstr.as_ptr(), &raw mut kt);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_kt_resolve",
                });
            }

            let ccache_name = c"MEMORY:akamu-initiator";
            let mut ccache: ffi::Krb5Ccache = ptr::null_mut();
            let ret = ffi::krb5_cc_resolve(ctx, ccache_name.as_ptr(), &raw mut ccache);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_resolve",
                });
            }

            let ret = ffi::krb5_cc_initialize(ctx, ccache, principal_h);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_initialize failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_initialize",
                });
            }

            let mut creds = ffi::Krb5Creds([0u8; 128]);
            let ret = ffi::krb5_get_init_creds_keytab(
                ctx,
                &raw mut creds,
                principal_h,
                kt,
                0,
                ptr::null(),
                ptr::null_mut(),
            );
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_get_init_creds_keytab failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_get_init_creds_keytab",
                });
            }

            let store_ret = ffi::krb5_cc_store_cred(ctx, ccache, &raw mut creds);
            ffi::krb5_free_cred_contents(ctx, &raw mut creds);
            if store_ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, store_ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{store_ret:#010x}"), errmsg, "krb5_cc_store_cred failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: store_ret,
                    msg: "krb5_cc_store_cred",
                });
            }
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_kt_close(ctx, kt);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
        }

        // Acquire GSSAPI initiator credential from the MEMORY: ccache.
        let key_ccache = c"ccache";
        let ccache_name = c"MEMORY:akamu-initiator";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_name.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: cred_store elements point to live c-string literals; output
        // pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: set by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (initiator ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Like [`from_keytab_initiate`][Self::from_keytab_initiate] but stores the
    /// TGT into a caller-named ccache instead of the default
    /// `MEMORY:akamu-initiator`.
    ///
    /// This is useful when multiple proxy threads need isolated credential
    /// stores (e.g. `MEMORY:akamu-proxy-initiator`).
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::NulInUserPrincipal`] — `principal` contains a NUL byte.
    /// - [`GssError::KeytabNotReadable`] — keytab file cannot be opened.
    /// - [`GssError::Krb5`] — libkrb5 TGT acquisition failed.
    /// - [`GssError::AcquireCred`] — GSSAPI credential acquisition from ccache failed.
    pub fn from_keytab_initiate_named(
        keytab_file: &str,
        principal: &str,
        ccache_name: &str,
    ) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let principal_cstr = CString::new(principal).map_err(|_| GssError::NulInUserPrincipal)?;
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        // SAFETY: each pointer is initialised before use; on error we clean up in
        // reverse-acquisition order (no double-free, no leak).
        unsafe {
            let mut ctx: ffi::Krb5Context = ptr::null_mut();
            let ret = ffi::krb5_init_context(&raw mut ctx);
            if ret != 0 {
                tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_init_context",
                });
            }

            let mut principal_h: ffi::Krb5Principal = ptr::null_mut();
            let ret = ffi::krb5_parse_name(ctx, principal_cstr.as_ptr(), &raw mut principal_h);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_parse_name failed");
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_parse_name",
                });
            }

            let mut kt: ffi::Krb5Keytab = ptr::null_mut();
            let ret = ffi::krb5_kt_resolve(ctx, kt_cstr.as_ptr(), &raw mut kt);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_kt_resolve",
                });
            }

            let mut ccache: ffi::Krb5Ccache = ptr::null_mut();
            let ret = ffi::krb5_cc_resolve(ctx, ccache_cstr.as_ptr(), &raw mut ccache);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_resolve",
                });
            }

            let ret = ffi::krb5_cc_initialize(ctx, ccache, principal_h);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_initialize failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_initialize",
                });
            }

            let mut creds = ffi::Krb5Creds([0u8; 128]);
            let ret = ffi::krb5_get_init_creds_keytab(
                ctx,
                &raw mut creds,
                principal_h,
                kt,
                0,
                ptr::null(),
                ptr::null_mut(),
            );
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_get_init_creds_keytab failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_get_init_creds_keytab",
                });
            }

            let store_ret = ffi::krb5_cc_store_cred(ctx, ccache, &raw mut creds);
            ffi::krb5_free_cred_contents(ctx, &raw mut creds);
            if store_ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, store_ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{store_ret:#010x}"), errmsg, "krb5_cc_store_cred failed");
                ffi::krb5_cc_close(ctx, ccache);
                ffi::krb5_kt_close(ctx, kt);
                ffi::krb5_free_principal(ctx, principal_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: store_ret,
                    msg: "krb5_cc_store_cred",
                });
            }
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_kt_close(ctx, kt);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
        }

        // Acquire GSSAPI initiator credential from the named ccache.
        let key_ccache = c"ccache";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: cred_store elements point to live CString values held on the
        // stack; output pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: set by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (named initiator ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire a delegated credential that acts as `user_principal` (S4U2Self).
    ///
    /// `initiator` must be an initiator credential obtained from the HTTP service
    /// keytab (e.g. via [`GssClientCred::from_keytab`]).  MIT Kerberos uses the
    /// keytab to authenticate as the service and then issues a service-for-user
    /// (S4U2Self) ticket.
    ///
    /// The returned credential can subsequently be stored into a thread-local
    /// credential cache and used for LDAP SASL GSSAPI binds.  When the KDC has
    /// constrained delegation configured for HTTP → LDAP, the SASL exchange
    /// automatically performs S4U2Proxy to obtain an LDAP ticket on behalf of
    /// the user.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInUserPrincipal`] — `user_principal` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the principal.
    /// - [`GssError::ImpersonateCred`] — `gss_acquire_cred_impersonate_name` failed
    ///   (KDC policy, missing delegation config, or unknown principal).
    pub fn impersonate(initiator: &GssClientCred, user_principal: &str) -> Result<Self, GssError> {
        let principal_cstr =
            CString::new(user_principal).map_err(|_| GssError::NulInUserPrincipal)?;
        let mut minor: ffi::OmUint32 = 0;

        // Import the user principal as a Kerberos principal name.
        let principal_oid = ffi::gss_krb5_nt_principal_name();
        let principal_buf = ffi::GssBufferDesc {
            length: principal_cstr.as_bytes().len(),
            // SAFETY: gss_import_name treats the buffer as read-only.
            #[allow(clippy::as_ptr_cast_mut)]
            value: principal_cstr.as_ptr() as *mut _,
        };
        let mut user_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: minor, principal_buf, and principal_oid are valid stack values;
        // user_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const principal_buf,
                &raw const principal_oid,
                &raw mut user_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (user principal for S4U2Self) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }

        let mut impersonated: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: initiator.raw is a live initiator credential; user_name was
        // returned by gss_import_name and is still valid; output pointers are
        // valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_impersonate_name(
                &raw mut minor,
                initiator.raw,
                user_name,
                0, // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw mut impersonated,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // Release the user name and actual_mechs set regardless of outcome.
        // SAFETY: user_name was returned by gss_import_name above.
        unsafe {
            ffi::gss_release_name(&raw mut minor, &raw mut user_name);
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !impersonated.is_null() {
                // SAFETY: impersonated was set by gss_acquire_cred_impersonate_name.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut impersonated) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_impersonate_name (S4U2Self) failed");
            return Err(GssError::ImpersonateCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: impersonated })
    }

    /// Return the underlying `gss_cred_id_t` as a raw C pointer.
    ///
    /// The pointer is valid only as long as `self` is alive.  Intended for
    /// injection into Cyrus SASL via `sasl_setprop(conn, SASL_GSS_CREDS, ptr)`.
    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.raw.cast()
    }

    /// Re-acquire an initiator credential from an existing named ccache.
    ///
    /// `ccache_name` must be a ccache previously populated by [`Self::store_into_ccache`].
    /// Calling this after [`Self::store_into_ccache`] produces a credential whose backing
    /// store is the named ccache — MIT Kerberos can then find the evidence ticket
    /// in that ccache when performing S4U2Proxy inside `gss_init_sec_context`.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::AcquireCred`] — `gss_acquire_cred_from` failed (the ccache
    ///   does not exist or contains no usable credential).
    pub fn from_named_ccache(ccache_name: &str) -> Result<Self, GssError> {
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        let key_ccache = c"ccache";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: ccache_cstr is a live CString; cred_store elements point to it
        // and to a static C string; output pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(ccache = ccache_name, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (named ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Store this credential into the named Kerberos credential cache.
    ///
    /// `ccache_name` should be a `MEMORY:` ccache name (e.g. `"MEMORY:akamu-7"`).
    /// After storing, call [`set_thread_ccache`] so that the SASL GSSAPI plugin
    /// finds this credential when it calls `gss_acquire_cred` on the same thread.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::StoreCred`] — `gss_store_cred_into` failed.
    pub fn store_into_ccache(&self, ccache_name: &str) -> Result<(), GssError> {
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        let key_ccache = c"ccache";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_cstr.as_ptr(),
        };
        let store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut elements_stored: ffi::GssOidSetT = ptr::null_mut();
        let mut usage_stored: i32 = 0;

        // SAFETY: self.raw is a live credential; store elements point to live CStrings;
        // output pointers are valid locals.
        let major = unsafe {
            ffi::gss_store_cred_into(
                &raw mut minor,
                self.raw,
                ffi::GSS_C_INITIATE,
                ptr::null(), // desired_mech = NULL: store all mechs
                1,           // overwrite_cred
                0,           // default_cred (we set thread-local explicitly)
                &raw const store,
                &raw mut elements_stored,
                &raw mut usage_stored,
            )
        };

        let error_minor = minor;
        unsafe {
            if !elements_stored.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut elements_stored);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(ccache = ccache_name, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_store_cred_into failed");
            return Err(GssError::StoreCred {
                detail,
                major,
                minor: error_minor,
            });
        }
        Ok(())
    }
}

// ── GssClientContext ──────────────────────────────────────────────────────────

/// In-progress GSSAPI client-side security context for multi-round-trip exchange.
///
/// Holds the evolving context handle and the imported target name so that
/// `gss_init_sec_context` can be called repeatedly with the server's response
/// tokens.  Use [`GssClientContext::new`] to create one and
/// [`GssClientContext::step`] to advance the exchange one HTTP round-trip at a time.
///
/// Drop releases the context handle via `gss_delete_sec_context` and the target
/// name via `gss_release_name`.
pub struct GssClientContext {
    raw: ffi::GssCtxIdT,
    target_name: ffi::GssNameT,
}

// SAFETY: moving a partially-initialised context to another thread is safe —
// only one thread ever calls step() at a time (no Sync impl).
unsafe impl Send for GssClientContext {}

impl std::fmt::Debug for GssClientContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssClientContext")
            .field("raw", &self.raw)
            .field("target_name", &self.target_name)
            .finish()
    }
}

impl Drop for GssClientContext {
    fn drop(&mut self) {
        let mut minor: ffi::OmUint32 = 0;
        if !self.raw.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: self.raw is a valid context handle set by gss_init_sec_context.
            unsafe {
                ffi::gss_delete_sec_context(&raw mut minor, &raw mut self.raw, &raw mut discard)
            };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard was populated by gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut discard) };
            }
        }
        if !self.target_name.is_null() {
            // SAFETY: self.target_name was returned by gss_import_name.
            unsafe { ffi::gss_release_name(&raw mut minor, &raw mut self.target_name) };
        }
    }
}

impl GssClientContext {
    /// Import `target_service` (e.g. `"HTTP@hostname"`) and prepare a new context.
    ///
    /// Call [`step`](Self::step) to begin the GSSAPI exchange.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInTargetName`] — `target_service` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the name.
    pub fn new(target_service: &str) -> Result<Self, GssError> {
        let svc_cstr = CString::new(target_service).map_err(|_| GssError::NulInTargetName)?;
        let mut minor: ffi::OmUint32 = 0;
        let svc_oid = ffi::gss_c_nt_hostbased_service();
        let svc_buf = ffi::GssBufferDesc {
            length: svc_cstr.as_bytes().len(),
            // SAFETY: gss_import_name treats the buffer as read-only.
            #[allow(clippy::as_ptr_cast_mut)]
            value: svc_cstr.as_ptr() as *mut _,
        };
        let mut target_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: svc_buf wraps a live CString; target_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const svc_buf,
                &raw const svc_oid,
                &raw mut target_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(target = target_service, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (target service) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }
        Ok(GssClientContext {
            raw: ffi::GSS_C_NO_CONTEXT,
            target_name,
        })
    }

    /// Advance the exchange by one step.
    ///
    /// `input_token` is `None` on the first call.  On subsequent calls pass the
    /// base64-decoded token from the server's `WWW-Authenticate: Negotiate` header.
    ///
    /// Returns `(output_token, complete)`.  Encode `output_token` as
    /// `Authorization: Negotiate <base64(output_token)>` and send it to the server.
    /// When `complete` is `false` and the server responds with a new
    /// `WWW-Authenticate: Negotiate` token, feed it back into the next `step` call.
    /// When the server returns HTTP 200 the exchange is done regardless of `complete`.
    ///
    /// Both `GSS_S_COMPLETE` and `GSS_S_CONTINUE_NEEDED` are treated as success —
    /// SPNEGO returns `CONTINUE_NEEDED` on the first call even when the Kerberos
    /// AP-REQ is fully formed and ready to send.
    ///
    /// # Errors
    ///
    /// - [`GssError::InitContext`] — `gss_init_sec_context` returned a status
    ///   other than `GSS_S_COMPLETE` or `GSS_S_CONTINUE_NEEDED`.
    pub fn step(
        &mut self,
        cred: &GssClientCred,
        input_token: Option<&[u8]>,
        channel_binding: Option<&[u8]>,
    ) -> Result<(Vec<u8>, bool), GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let input_storage;
        let input_ptr: *const ffi::GssBufferDesc = match input_token {
            None => ptr::null(),
            Some(data) => {
                input_storage = ffi::GssBufferDesc {
                    length: data.len(),
                    // SAFETY: gss_init_sec_context treats input_token as read-only.
                    #[allow(clippy::as_ptr_cast_mut)]
                    value: data.as_ptr() as *mut _,
                };
                &raw const input_storage
            }
        };

        let bindings_storage;
        let chan_bindings_ptr: *const ffi::GssChannelBindingsStruct = match channel_binding {
            None => ptr::null(),
            Some(data) => {
                bindings_storage = ffi::GssChannelBindingsStruct {
                    initiator_addrtype: ffi::GSS_C_AF_UNSET,
                    initiator_address: ffi::gss_c_no_buffer(),
                    acceptor_addrtype: ffi::GSS_C_AF_UNSET,
                    acceptor_address: ffi::gss_c_no_buffer(),
                    application_data: ffi::GssBufferDesc {
                        length: data.len(),
                        // SAFETY: application_data is treated as read-only.
                        #[allow(clippy::as_ptr_cast_mut)]
                        value: data.as_ptr() as *mut _,
                    },
                };
                &raw const bindings_storage
            }
        };

        let mut output_buf = ffi::gss_c_no_buffer();
        let mut ret_flags: ffi::OmUint32 = 0;
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: cred.raw is a live initiator credential; self.target_name was set
        // by gss_import_name and is retained for the struct's lifetime; self.raw
        // starts as GSS_C_NO_CONTEXT and is updated in-place by the library;
        // input_ptr is null or points to a live stack buffer; chan_bindings_ptr is
        // null or points to bindings_storage which lives until after this call.
        let major = unsafe {
            ffi::gss_init_sec_context(
                &raw mut minor,
                cred.raw,
                &raw mut self.raw,
                self.target_name,
                ptr::null(), // mech_type = default (SPNEGO)
                // No GSS_C_MUTUAL_FLAG: all callers use HTTPS where TLS
                // already provides server authentication.  Requesting mutual
                // auth forces a two-leg AP-REQ/AP-REP exchange; the IPA
                // JSON-RPC layer does not implement the second leg, causing
                // GSS_S_CONTINUE_NEEDED to be treated as an error.
                0,
                0, // time_req = library default
                chan_bindings_ptr,
                input_ptr,
                ptr::null_mut(), // actual_mech_type — not needed
                &raw mut output_buf,
                &raw mut ret_flags,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
            // SAFETY: output_buf.value points to output_buf.length valid bytes.
            let slice = unsafe {
                std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length)
            };
            let v = slice.to_vec();
            // SAFETY: output_buf was populated by gss_init_sec_context.
            unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut output_buf) };
            v
        } else {
            Vec::new()
        };

        if major != ffi::GSS_S_COMPLETE && major != ffi::GSS_S_CONTINUE_NEEDED {
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_init_sec_context failed");
            return Err(GssError::InitContext {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok((out_token, major == ffi::GSS_S_COMPLETE))
    }
}

// ── GssServerContext ──────────────────────────────────────────────────────────

/// Result of one GSSAPI server-side accept step.
///
/// Returned by [`accept_token`] and [`GssServerContext::step`].
#[derive(Debug)]
pub enum AcceptStep {
    /// Exchange is complete.  `principal` is the authenticated client identity
    /// (e.g. `"user@REALM"`).  `out_token` is the optional mutual-authentication
    /// response; encode it as `WWW-Authenticate: Negotiate <base64>` if non-empty.
    Complete {
        out_token: Vec<u8>,
        principal: String,
    },
    /// The mechanism needs another round-trip.  Send `out_token` as
    /// `WWW-Authenticate: Negotiate <base64>` with `401 Unauthorized`, then call
    /// [`GssServerContext::step`] with the client's next `Authorization: Negotiate`
    /// token.  `ctx` must be kept alive between the two HTTP requests.
    Continue {
        out_token: Vec<u8>,
        ctx: GssServerContext,
    },
}

/// In-progress GSSAPI server-side security context for multi-round-trip exchange.
///
/// Wraps the partially-initialized `gss_ctx_id_t` produced when
/// `gss_accept_sec_context` returns `GSS_S_CONTINUE_NEEDED`.  Call
/// [`GssServerContext::step`] with the client's next token to advance the exchange.
///
/// Drop releases the context handle via `gss_delete_sec_context`.
pub struct GssServerContext {
    raw: ffi::GssCtxIdT,
}

// SAFETY: moving a partially-initialized server context to another thread is
// safe — only one thread ever calls step() at a time (no Sync impl).
unsafe impl Send for GssServerContext {}

impl std::fmt::Debug for GssServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssServerContext")
            .field("raw", &self.raw)
            .finish()
    }
}

impl Drop for GssServerContext {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: self.raw is a valid context handle set by gss_accept_sec_context.
            unsafe {
                ffi::gss_delete_sec_context(&raw mut minor, &raw mut self.raw, &raw mut discard)
            };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard was populated by gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut discard) };
            }
        }
    }
}

impl GssServerContext {
    /// Advance the server-side SPNEGO exchange by one step.
    ///
    /// `input_token` is the SPNEGO/Kerberos token from the client's
    /// `Authorization: Negotiate` header (base64-decoded).
    /// `channel_binding` should be the `tls-server-end-point` bytes (RFC 5929 §4)
    /// or `None`.
    ///
    /// Consumes `self`; on [`AcceptStep::Continue`] the new [`GssServerContext`]
    /// inside the variant must be stored for the next call.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcceptContext`] — `gss_accept_sec_context` rejected the token.
    /// - [`GssError::DisplayName`] — the principal name could not be converted.
    /// - [`GssError::InvalidUtf8`] — the principal name is not valid UTF-8.
    pub fn step(
        mut self,
        cred: &GssServerCred,
        input_token: &[u8],
        channel_binding: Option<&[u8]>,
    ) -> Result<AcceptStep, GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let input_buf = ffi::GssBufferDesc {
            length: input_token.len(),
            // SAFETY: gss_accept_sec_context treats input_token_buffer as read-only
            // per RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
            #[allow(clippy::as_ptr_cast_mut)]
            value: input_token.as_ptr() as *mut _,
        };
        let mut output_buf = ffi::gss_c_no_buffer();
        let mut src_name: ffi::GssNameT = ptr::null_mut();
        let mut ret_flags: ffi::OmUint32 = 0;
        let mut time_rec: ffi::OmUint32 = 0;
        let mut delegated_cred: ffi::GssCredIdT = ptr::null_mut();

        // `bindings_storage` must outlive the FFI call below.
        let bindings_storage;
        let chan_bindings_ptr: *const ffi::GssChannelBindingsStruct = match channel_binding {
            None => ptr::null(),
            Some(data) => {
                bindings_storage = ffi::GssChannelBindingsStruct {
                    initiator_addrtype: ffi::GSS_C_AF_UNSET,
                    initiator_address: ffi::gss_c_no_buffer(),
                    acceptor_addrtype: ffi::GSS_C_AF_UNSET,
                    acceptor_address: ffi::gss_c_no_buffer(),
                    application_data: ffi::GssBufferDesc {
                        length: data.len(),
                        // SAFETY: gss_accept_sec_context treats application_data as
                        // read-only; *const → *mut cast is safe per RFC 2744 §2.
                        #[allow(clippy::as_ptr_cast_mut)]
                        value: data.as_ptr() as *mut _,
                    },
                };
                &raw const bindings_storage
            }
        };

        // SAFETY: self.raw is GSS_C_NO_CONTEXT (initial call) or a valid partial
        // context from a prior gss_accept_sec_context; cred.raw is a live acceptor
        // credential; chan_bindings_ptr is null or points to stack-allocated
        // bindings_storage which remains live until after this call returns.
        let major = unsafe {
            ffi::gss_accept_sec_context(
                &raw mut minor,
                &raw mut self.raw,
                cred.raw,
                &raw const input_buf,
                chan_bindings_ptr,
                &raw mut src_name,
                ptr::null_mut(), // mech_type — not needed
                &raw mut output_buf,
                &raw mut ret_flags,
                &raw mut time_rec,
                &raw mut delegated_cred,
            )
        };

        // Release delegated credential immediately — never used.
        if !delegated_cred.is_null() {
            // SAFETY: set by gss_accept_sec_context.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut delegated_cred) };
        }

        // Copy output token before freeing the GSSAPI buffer.
        let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
            // SAFETY: output_buf.value is valid for output_buf.length bytes.
            let slice = unsafe {
                std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length)
            };
            let v = slice.to_vec();
            // SAFETY: output_buf was populated by gss_accept_sec_context.
            unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut output_buf) };
            v
        } else {
            Vec::new()
        };

        let error_minor = minor;

        match major {
            ffi::GSS_S_COMPLETE => {
                if ret_flags & ffi::GSS_C_REPLAY_FLAG == 0 {
                    // Expected when the client is a browser over TLS — TLS provides
                    // replay protection so Kerberos replay detection is typically not
                    // negotiated.  Not actionable; logged at debug to avoid noise.
                    tracing::debug!("GSSAPI context established without replay detection flag");
                }
                // Extract the principal name string.
                let mut name_buf = ffi::gss_c_no_buffer();
                // SAFETY: src_name is a valid GssNameT set by gss_accept_sec_context.
                let major_dn = unsafe {
                    ffi::gss_display_name(
                        &raw mut minor,
                        src_name,
                        &raw mut name_buf,
                        ptr::null_mut(),
                    )
                };
                // Snapshot minor before gss_release_name overwrites it.
                let dn_minor = minor;
                // SAFETY: src_name is valid; gss_release_name takes ownership.
                unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };

                let principal = if major_dn == ffi::GSS_S_COMPLETE && !name_buf.value.is_null() {
                    // SAFETY: name_buf.value is valid for name_buf.length bytes.
                    let slice = unsafe {
                        std::slice::from_raw_parts(name_buf.value as *const u8, name_buf.length)
                    };
                    let s = std::str::from_utf8(slice)
                        .map(std::borrow::ToOwned::to_owned)
                        .map_err(|_| GssError::InvalidUtf8);
                    // SAFETY: name_buf was populated by gss_display_name.
                    unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut name_buf) };
                    s?
                } else {
                    // SAFETY: name_buf may be empty or null; gss_release_buffer handles both.
                    unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut name_buf) };
                    return Err(GssError::DisplayName {
                        detail: format_gss_status(major_dn, dn_minor),
                        major: major_dn,
                        minor: dn_minor,
                    });
                };

                // self goes out of scope here; Drop deletes self.raw.
                Ok(AcceptStep::Complete {
                    out_token,
                    principal,
                })
            }

            ffi::GSS_S_CONTINUE_NEEDED => {
                if !src_name.is_null() {
                    // SAFETY: src_name is valid (may be set even on CONTINUE_NEEDED).
                    unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };
                }
                // Transfer self.raw to a new GssServerContext for the caller to persist.
                // Setting self.raw to null prevents Drop from double-freeing.
                let raw = self.raw;
                self.raw = ffi::GSS_C_NO_CONTEXT;
                Ok(AcceptStep::Continue {
                    out_token,
                    ctx: GssServerContext { raw },
                })
            }

            _ => {
                if !src_name.is_null() {
                    // SAFETY: src_name is valid.
                    unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };
                }
                let detail = format_gss_status(major, error_minor);
                tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_accept_sec_context failed");
                // self goes out of scope here; Drop deletes self.raw.
                Err(GssError::AcceptContext {
                    detail,
                    major,
                    minor: error_minor,
                })
            }
        }
    }
}

// ── InitStep ──────────────────────────────────────────────────────────────────

/// Result of the first GSSAPI client-side init step.
///
/// Returned by [`init_token`].
#[derive(Debug)]
pub enum InitStep {
    /// The exchange is complete after the first token.  Encode `token` as
    /// `Authorization: Negotiate <base64>` and send it.
    Complete(Vec<u8>),
    /// The mechanism needs at least one more round-trip.  Send `token` to the
    /// server; if the server replies with `WWW-Authenticate: Negotiate <base64>`,
    /// decode the server token and pass it to [`GssClientContext::step`] on `ctx`.
    Continue {
        token: Vec<u8>,
        ctx: GssClientContext,
    },
}

// ── impersonate_with_server_cred ──────────────────────────────────────────────

/// Acquire a delegated credential acting as `user_principal` using the gssproxy-managed
/// server (acceptor) credential as the impersonator (S4U2Self).
///
/// This is the correct impersonation path when gssproxy manages the credential store.
/// Using a locally-acquired initiator credential as the impersonator causes the resulting
/// S4U2Self credential to also be local; when that credential is then passed to
/// `gss_init_sec_context`, gssproxy's proxymech falls back to `init_ctx_local`, which calls
/// `gpp_name_to_local` and crashes due to a static-OID free bug in gssproxy ≤ 0.9.2.
///
/// By contrast, the gssproxy-managed ACCEPT credential (from `GssServerCred::from_gssproxy`)
/// is already in gssproxy's credential table.  `gss_acquire_cred_impersonate_name` with that
/// credential produces a gssproxy-managed S4U2Self credential, so the subsequent
/// `gss_init_sec_context` is handled remotely without triggering `init_ctx_local`.
///
/// This mirrors the pattern used by mod_auth_gssapi for S4U2Self LDAP lookups.
///
/// # Errors
///
/// - [`GssError::NulInUserPrincipal`] — `user_principal` contains a NUL byte.
/// - [`GssError::ImportName`] — `gss_import_name` rejected the principal.
/// - [`GssError::ImpersonateCred`] — `gss_acquire_cred_impersonate_name` failed.
pub fn impersonate_with_server_cred(
    server: &GssServerCred,
    user_principal: &str,
) -> Result<GssClientCred, GssError> {
    let principal_cstr = CString::new(user_principal).map_err(|_| GssError::NulInUserPrincipal)?;
    let mut minor: ffi::OmUint32 = 0;

    let principal_oid = ffi::gss_krb5_nt_principal_name();
    let principal_buf = ffi::GssBufferDesc {
        length: principal_cstr.as_bytes().len(),
        #[allow(clippy::as_ptr_cast_mut)]
        value: principal_cstr.as_ptr() as *mut _,
    };
    let mut user_name: ffi::GssNameT = ptr::null_mut();
    // SAFETY: minor, principal_buf, and principal_oid are valid stack values.
    let major = unsafe {
        ffi::gss_import_name(
            &raw mut minor,
            &raw const principal_buf,
            &raw const principal_oid,
            &raw mut user_name,
        )
    };
    if major != ffi::GSS_S_COMPLETE {
        let detail = format_gss_status(major, minor);
        tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (user principal for server-cred S4U2Self) failed");
        return Err(GssError::ImportName {
            detail,
            major,
            minor,
        });
    }

    let mut impersonated: ffi::GssCredIdT = ptr::null_mut();
    let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
    let mut time_rec: ffi::OmUint32 = 0;

    // SAFETY: server.raw is the gssproxy-managed ACCEPT credential; user_name was
    // returned by gss_import_name and is still valid; output pointers are valid locals.
    let major = unsafe {
        ffi::gss_acquire_cred_impersonate_name(
            &raw mut minor,
            server.raw,
            user_name,
            0,
            ffi::GSS_C_NO_OID_SET,
            ffi::GSS_C_INITIATE,
            &raw mut impersonated,
            &raw mut actual_mechs,
            &raw mut time_rec,
        )
    };

    let error_minor = minor;
    unsafe {
        ffi::gss_release_name(&raw mut minor, &raw mut user_name);
        if !actual_mechs.is_null() {
            ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
        }
    }

    if major != ffi::GSS_S_COMPLETE {
        if !impersonated.is_null() {
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut impersonated) };
        }
        let detail = format_gss_status(major, error_minor);
        tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_impersonate_name (server-cred S4U2Self) failed");
        return Err(GssError::ImpersonateCred {
            detail,
            major,
            minor: error_minor,
        });
    }

    Ok(GssClientCred { raw: impersonated })
}

// ── init_token ────────────────────────────────────────────────────────────────

/// Produce the first SPNEGO/Kerberos token for `target_service`.
///
/// `target_service` must be in host-based format: `"HTTP@hostname"`.
/// `channel_binding` is the `tls-server-end-point` bytes (RFC 5929 §4) or `None`.
///
/// Returns [`InitStep::Complete`] when the token is ready to send and no
/// further steps are expected.  Returns [`InitStep::Continue`] when the
/// mechanism (e.g. IAKERB) requires additional round-trips; use the bundled
/// [`GssClientContext`] to drive the exchange to completion.
///
/// # Errors
///
/// - [`GssError::NulInTargetName`] — `target_service` contains a NUL byte.
/// - [`GssError::ImportName`] — `gss_import_name` rejected the target name.
/// - [`GssError::InitContext`] — `gss_init_sec_context` failed.
pub fn init_token(
    cred: &GssClientCred,
    target_service: &str,
    channel_binding: Option<&[u8]>,
) -> Result<InitStep, GssError> {
    let mut ctx = GssClientContext::new(target_service)?;
    let (token, complete) = ctx.step(cred, None, channel_binding)?;
    if complete {
        Ok(InitStep::Complete(token))
    } else {
        Ok(InitStep::Continue { token, ctx })
    }
}

// ── accept_token ──────────────────────────────────────────────────────────────

/// Process one SPNEGO/Kerberos token received in `Authorization: Negotiate`.
///
/// `channel_binding` should be the `tls-server-end-point` bytes (RFC 5929 §4)
/// when TLS is terminated by this server, or `None` when running without TLS or
/// when the server certificate uses an algorithm with no defined binding hash
/// (e.g. ML-DSA).
///
/// Returns [`AcceptStep::Complete`] when the client is authenticated.
/// Returns [`AcceptStep::Continue`] when the mechanism needs another round-trip;
/// send the enclosed token in `WWW-Authenticate: Negotiate` with `401` and call
/// [`GssServerContext::step`] with the client's response.
///
/// # Errors
///
/// - [`GssError::AcceptContext`] — `gss_accept_sec_context` rejected the token
///   (expired ticket, wrong service, replay, or forged token).
/// - [`GssError::DisplayName`] — the authenticated name could not be converted
///   to a printable string by `gss_display_name`.
/// - [`GssError::InvalidUtf8`] — the display name returned by the GSSAPI
///   library is not valid UTF-8.
pub fn accept_token(
    cred: &GssServerCred,
    input_token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<AcceptStep, GssError> {
    GssServerContext {
        raw: ffi::GSS_C_NO_CONTEXT,
    }
    .step(cred, input_token, channel_binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_nul_in_service_name_returns_error() {
        let err = GssServerCred::acquire("HTTP\0badname", "/tmp/fake.keytab", false).unwrap_err();
        assert!(matches!(err, GssError::NulInServiceName));
    }

    #[test]
    fn acquire_nul_in_keytab_path_returns_error() {
        let err = GssServerCred::acquire("HTTP", "/tmp/\0fake.keytab", false).unwrap_err();
        assert!(matches!(err, GssError::NulInKeytabPath));
    }

    #[test]
    fn from_keytab_nul_in_path_returns_error() {
        let err = GssClientCred::from_keytab("/tmp/\0bad.keytab").unwrap_err();
        assert!(matches!(err, GssError::NulInKeytabPath));
    }

    #[test]
    fn init_token_nul_in_target_returns_error() {
        // Safety: won't reach any FFI — NUL check fires before gss_import_name.
        // We use a zeroed cred to avoid a real keytab dependency; the NUL check
        // fires before any FFI call that would dereference the raw pointer.
        let cred = GssClientCred {
            raw: ptr::null_mut(),
        };
        let err = init_token(&cred, "HTTP\0bad.host", None).unwrap_err();
        assert!(matches!(err, GssError::NulInTargetName));
        // Prevent Drop from calling gss_release_cred on a null handle.
        std::mem::forget(cred);
    }
}
