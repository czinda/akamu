//! Server-side GSSAPI / SPNEGO support for akamu.
//!
//! # Typical usage
//!
//! At startup, acquire a server credential from the HTTP service keytab:
//!
//! ```no_run
//! let cred = akamu_gssapi::GssServerCred::acquire("HTTP", "/etc/akamu/http.keytab")
//!     .expect("GSSAPI credential");
//! ```
//!
//! For each incoming `Authorization: Negotiate <base64>` request, call:
//!
//! ```no_run
//! # let cred = unsafe { std::mem::zeroed() };
//! # let token_bytes: Vec<u8> = vec![];
//! let (out_token, principal) = akamu_gssapi::accept_token(&cred, &token_bytes)
//!     .expect("GSSAPI accept");
//! // `principal` is e.g. "user@REALM"
//! // `out_token` is the mutual-auth response (may be empty)
//! ```
//!
//! # Thread safety
//!
//! [`GssServerCred`] is `Send + Sync`.  MIT Kerberos allows concurrent
//! `gss_accept_sec_context` calls against the same acceptor credential, so a
//! single `Arc<GssServerCred>` shared across all request-handling threads is
//! the expected usage pattern.

pub mod error;
mod ffi;

use std::ffi::CString;
use std::ptr;

pub use error::GssError;

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

// SAFETY: gss_cred_id_t may be used concurrently from multiple threads for
// accept operations — MIT Kerberos documents this as safe.
unsafe impl Send for GssServerCred {}
unsafe impl Sync for GssServerCred {}

impl Drop for GssServerCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            unsafe { ffi::gss_release_cred(&mut minor, &mut self.raw) };
        }
    }
}

impl GssServerCred {
    /// Acquire a server credential for `service_name` (e.g. `"HTTP"`) using
    /// the keytab at `keytab_file`.
    ///
    /// MIT Kerberos appends `@<local-hostname>` when no realm is specified, so
    /// passing `"HTTP"` is usually sufficient for a single-homed host.
    /// Use `"HTTP@fully.qualified.hostname"` to be explicit.
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
    pub fn acquire(service_name: &str, keytab_file: &str) -> Result<Self, GssError> {
        let svc_cstr =
            CString::new(service_name).map_err(|_| GssError::NulInServiceName)?;
        let kt_cstr =
            CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        let mut minor: ffi::OmUint32 = 0;

        // Import "service_name" as a host-based service name.
        let svc_oid = ffi::gss_c_nt_hostbased_service();
        let svc_buf = ffi::GssBufferDesc {
            length: svc_cstr.as_bytes().len(),
            value: svc_cstr.as_ptr() as *mut _,
        };
        let mut svc_name: ffi::GssNameT = ptr::null_mut();
        let major = unsafe {
            ffi::gss_import_name(&mut minor, &svc_buf, &svc_oid, &mut svc_name)
        };
        if major != ffi::GSS_S_COMPLETE {
            return Err(GssError::ImportName { major, minor });
        }

        // Build the credential store: one element {key="keytab", value=<path>}.
        let key_keytab = c"keytab";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_keytab.as_ptr(),
            value: kt_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &mut element,
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &mut minor,
                svc_name,
                0, // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_ACCEPT,
                &cred_store,
                &mut cred_handle,
                &mut actual_mechs,
                &mut time_rec,
            )
        };

        // Release the name and the actual_mechs set regardless of success/failure.
        unsafe {
            ffi::gss_release_name(&mut minor, &mut svc_name);
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&mut minor, &mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            return Err(GssError::AcquireCred { major, minor });
        }

        Ok(GssServerCred { raw: cred_handle })
    }
}

// ── accept_token ──────────────────────────────────────────────────────────────

/// Process one SPNEGO/Kerberos token received in `Authorization: Negotiate`.
///
/// Returns `(output_token, principal_name)` on success.
/// `output_token` is the optional mutual-authentication response for the client
/// (may be empty if the client did not request mutual auth).
/// `principal_name` is the authenticated client identity, e.g. `"user@REALM"`.
///
/// Creates and immediately destroys a per-call security context.  HTTP SPNEGO
/// with Kerberos is a single-round-trip exchange, so no context persistence is
/// needed across requests.
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
) -> Result<(Vec<u8>, String), GssError> {
    let mut minor: ffi::OmUint32 = 0;

    let input_buf = ffi::GssBufferDesc {
        length: input_token.len(),
        value: input_token.as_ptr() as *mut _,
    };
    let mut output_buf = ffi::gss_c_no_buffer();
    let mut ctx: ffi::GssCtxIdT = ffi::GSS_C_NO_CONTEXT;
    let mut src_name: ffi::GssNameT = ptr::null_mut();
    let mut ret_flags: ffi::OmUint32 = 0;
    let mut time_rec: ffi::OmUint32 = 0;
    let mut delegated_cred: ffi::GssCredIdT = ptr::null_mut();

    let major = unsafe {
        ffi::gss_accept_sec_context(
            &mut minor,
            &mut ctx,
            cred.raw,
            &input_buf,
            ptr::null(), // no channel bindings
            &mut src_name,
            ptr::null_mut(), // mech_type — not needed
            &mut output_buf,
            &mut ret_flags,
            &mut time_rec,
            &mut delegated_cred,
        )
    };

    // Release the delegated credential immediately — we never use it.
    if !delegated_cred.is_null() {
        unsafe { ffi::gss_release_cred(&mut minor, &mut delegated_cred) };
    }

    // Copy output token before freeing the GSSAPI buffer.
    let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
        let slice = unsafe {
            std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length)
        };
        let v = slice.to_vec();
        unsafe { ffi::gss_release_buffer(&mut minor, &mut output_buf) };
        v
    } else {
        Vec::new()
    };

    if major != ffi::GSS_S_COMPLETE {
        // Clean up context on failure.
        if !ctx.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 {
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        if !src_name.is_null() {
            unsafe { ffi::gss_release_name(&mut minor, &mut src_name) };
        }
        return Err(GssError::AcceptContext { major, minor });
    }

    // Extract the principal name string.
    let mut name_buf = ffi::gss_c_no_buffer();
    let major_dn = unsafe {
        ffi::gss_display_name(&mut minor, src_name, &mut name_buf, ptr::null_mut())
    };
    unsafe { ffi::gss_release_name(&mut minor, &mut src_name) };

    let principal = if major_dn == ffi::GSS_S_COMPLETE && !name_buf.value.is_null() {
        let slice = unsafe {
            std::slice::from_raw_parts(name_buf.value as *const u8, name_buf.length)
        };
        let s = std::str::from_utf8(slice)
            .map(|s| s.to_owned())
            .map_err(|_| GssError::InvalidUtf8);
        unsafe { ffi::gss_release_buffer(&mut minor, &mut name_buf) };
        // Clean up context before returning error.
        if s.is_err() {
            let mut discard = ffi::gss_c_no_buffer();
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 {
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        s?
    } else {
        unsafe { ffi::gss_release_buffer(&mut minor, &mut name_buf) };
        let mut discard = ffi::gss_c_no_buffer();
        unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
        if discard.length > 0 {
            unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
        }
        return Err(GssError::DisplayName { major: major_dn, minor });
    };

    // Delete the security context — not needed after principal extraction.
    let mut discard = ffi::gss_c_no_buffer();
    unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
    if discard.length > 0 {
        unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
    }

    Ok((out_token, principal))
}
