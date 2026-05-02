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
//! let (out_token, principal) = akamu_gssapi::accept_token(&cred, &token_bytes, None)
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

impl std::fmt::Debug for GssServerCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssServerCred")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: gss_cred_id_t may be used concurrently from multiple threads for
// accept operations.
//
// THIS IMPL IS ONLY SOUND WHEN LINKED AGAINST MIT KERBEROS.  MIT Kerberos
// explicitly documents that gss_accept_sec_context is thread-safe for concurrent
// use with the same acceptor credential (see the MIT Kerberos thread-safety
// documentation at https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/).
// Heimdal and other GSSAPI implementations do NOT make this guarantee; using
// this type with a non-MIT Kerberos library is unsound.
unsafe impl Send for GssServerCred {}
unsafe impl Sync for GssServerCred {}

impl Drop for GssServerCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.  The pointer is set to null by gss_release_cred.
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
        let svc_cstr = CString::new(service_name).map_err(|_| GssError::NulInServiceName)?;
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        let mut minor: ffi::OmUint32 = 0;

        // Import "service_name" as a host-based service name.
        let svc_oid = ffi::gss_c_nt_hostbased_service();
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
        let major = unsafe { ffi::gss_import_name(&mut minor, &svc_buf, &svc_oid, &mut svc_name) };
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

        // SAFETY: all arguments are valid; svc_name was returned by gss_import_name,
        // cred_store elements point to live CStrings, output pointers are valid locals.
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

        // Snapshot the error minor before cleanup calls overwrite it.
        let error_minor = minor;

        // Release the name and the actual_mechs set regardless of success/failure.
        // SAFETY: svc_name is a valid GssNameT returned by gss_import_name above.
        unsafe {
            ffi::gss_release_name(&mut minor, &mut svc_name);
            if !actual_mechs.is_null() {
                // SAFETY: actual_mechs is non-null and was set by gss_acquire_cred_from.
                ffi::gss_release_oid_set(&mut minor, &mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            // Defensively release a potentially non-null cred_handle on failure.
            // RFC 2743 §2.1.1 says it is NULL on failure, but non-conformant
            // implementations may write a partial handle.
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&mut minor, &mut cred_handle) };
            }
            return Err(GssError::AcquireCred {
                major,
                minor: error_minor,
            });
        }

        Ok(GssServerCred { raw: cred_handle })
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

// SAFETY: same MIT Kerberos thread-safety guarantee as GssServerCred.
// THIS IMPL IS ONLY SOUND WHEN LINKED AGAINST MIT KERBEROS.
unsafe impl Send for GssClientCred {}
unsafe impl Sync for GssClientCred {}

impl Drop for GssClientCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.
            unsafe { ffi::gss_release_cred(&mut minor, &mut self.raw) };
        }
    }
}

impl GssClientCred {
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

        let mut minor: ffi::OmUint32 = 0;

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

        // SAFETY: all arguments are valid; desired_name=NULL lets the library
        // choose the credential; output pointers are valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &mut minor,
                ptr::null_mut(), // desired_name = NULL
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &cred_store,
                &mut cred_handle,
                &mut actual_mechs,
                &mut time_rec,
            )
        };

        let error_minor = minor;

        // SAFETY: actual_mechs is non-null when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&mut minor, &mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&mut minor, &mut cred_handle) };
            }
            return Err(GssError::AcquireCred {
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }
}

// ── init_token ────────────────────────────────────────────────────────────────

/// Produce the initial SPNEGO/Kerberos token for `target_service`.
///
/// `target_service` must be in host-based format: `"HTTP@hostname"`.
/// `channel_binding` is the `tls-server-end-point` bytes (RFC 5929 §4) or `None`.
///
/// Returns the raw token bytes to encode as `Authorization: Negotiate <base64>`.
///
/// Basic Kerberos SPNEGO is a single-round-trip exchange (`GSS_S_COMPLETE` is
/// expected immediately); `GSS_S_CONTINUE_NEEDED` is treated as an error.
///
/// The security context is created and immediately deleted after token extraction —
/// akamu does not persist per-request client contexts.
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
) -> Result<Vec<u8>, GssError> {
    let svc_cstr = CString::new(target_service).map_err(|_| GssError::NulInTargetName)?;

    let mut minor: ffi::OmUint32 = 0;

    // Import the target name as a host-based service.
    let svc_oid = ffi::gss_c_nt_hostbased_service();
    let svc_buf = ffi::GssBufferDesc {
        length: svc_cstr.as_bytes().len(),
        // SAFETY: gss_import_name treats input_name_buffer as read-only per
        // RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
        #[allow(clippy::as_ptr_cast_mut)]
        value: svc_cstr.as_ptr() as *mut _,
    };
    let mut target_name: ffi::GssNameT = ptr::null_mut();
    // SAFETY: all arguments are valid locals; target_name is a valid output pointer.
    let major = unsafe { ffi::gss_import_name(&mut minor, &svc_buf, &svc_oid, &mut target_name) };
    if major != ffi::GSS_S_COMPLETE {
        return Err(GssError::ImportName { major, minor });
    }

    // Build channel bindings struct on the stack when provided.
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
                    // SAFETY: gss_init_sec_context treats application_data as
                    // read-only; *const → *mut cast is safe per RFC 2744 §2.
                    #[allow(clippy::as_ptr_cast_mut)]
                    value: data.as_ptr() as *mut _,
                },
            };
            &bindings_storage
        }
    };

    let mut ctx: ffi::GssCtxIdT = ffi::GSS_C_NO_CONTEXT;
    let mut output_buf = ffi::gss_c_no_buffer();
    let mut ret_flags: ffi::OmUint32 = 0;
    let mut time_rec: ffi::OmUint32 = 0;

    // SAFETY: all arguments are valid; cred.raw is a live initiator credential;
    // target_name was returned by gss_import_name; chan_bindings_ptr either null
    // or points to the stack-allocated bindings_storage which remains live here;
    // input_token = NULL for the initial (only) call.
    let major = unsafe {
        ffi::gss_init_sec_context(
            &mut minor,
            cred.raw,
            &mut ctx,
            target_name,
            ptr::null(), // mech_type = default (Kerberos)
            ffi::GSS_C_MUTUAL_FLAG,
            0, // time_req = library default
            chan_bindings_ptr,
            ptr::null(),     // input_token = NULL (first call)
            ptr::null_mut(), // actual_mech_type — not needed
            &mut output_buf,
            &mut ret_flags,
            &mut time_rec,
        )
    };

    // SAFETY: target_name is a valid GssNameT set by gss_import_name.
    unsafe { ffi::gss_release_name(&mut minor, &mut target_name) };

    // Copy output token before freeing the GSSAPI buffer.
    let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
        // SAFETY: output_buf.value is a valid pointer to output_buf.length bytes
        // allocated by gss_init_sec_context; we copy before releasing.
        let slice =
            unsafe { std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length) };
        let v = slice.to_vec();
        // SAFETY: output_buf was populated by gss_init_sec_context.
        unsafe { ffi::gss_release_buffer(&mut minor, &mut output_buf) };
        v
    } else {
        Vec::new()
    };

    let error_minor = minor;

    if major != ffi::GSS_S_COMPLETE {
        // Clean up the context on failure (includes CONTINUE_NEEDED, which we
        // do not support for this single-round-trip use case).
        if !ctx.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: ctx is a valid context handle set by gss_init_sec_context.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        return Err(GssError::InitContext {
            major,
            minor: error_minor,
        });
    }

    // Delete the context — we do not need it after token extraction.
    if !ctx.is_null() {
        let mut discard = ffi::gss_c_no_buffer();
        // SAFETY: ctx is a valid context handle from gss_init_sec_context.
        unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
        if discard.length > 0 && !discard.value.is_null() {
            // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
            unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
        }
    }

    Ok(out_token)
}

// ── accept_token ──────────────────────────────────────────────────────────────

/// Process one SPNEGO/Kerberos token received in `Authorization: Negotiate`.
///
/// Returns `(output_token, principal_name)` on success.
/// `output_token` is the optional mutual-authentication response for the client
/// (may be empty if the client did not request mutual auth).
/// `principal_name` is the authenticated client identity, e.g. `"user@REALM"`.
///
/// `channel_binding` should be the `tls-server-end-point` binding bytes (RFC 5929 §4)
/// when TLS is terminated by this server, or `None` when running without TLS or when
/// the server certificate uses an algorithm with no defined binding hash (e.g. ML-DSA).
///
/// Creates and immediately destroys a per-call security context.  HTTP SPNEGO
/// with Kerberos is a single-round-trip exchange, so no context persistence is
/// needed across requests.
///
/// # Errors
///
/// - [`GssError::AcceptContext`] — `gss_accept_sec_context` rejected the token
///   (expired ticket, wrong service, replay, or forged token).
/// - [`GssError::InsufficientFlags`] — the accepted context does not have
///   replay detection enabled (`GSS_C_REPLAY_FLAG` not set in `ret_flags`).
/// - [`GssError::DisplayName`] — the authenticated name could not be converted
///   to a printable string by `gss_display_name`.
/// - [`GssError::InvalidUtf8`] — the display name returned by the GSSAPI
///   library is not valid UTF-8.
pub fn accept_token(
    cred: &GssServerCred,
    input_token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<(Vec<u8>, String), GssError> {
    let mut minor: ffi::OmUint32 = 0;

    let input_buf = ffi::GssBufferDesc {
        length: input_token.len(),
        // SAFETY: gss_accept_sec_context treats input_token_buffer as read-only
        // per RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
        #[allow(clippy::as_ptr_cast_mut)]
        value: input_token.as_ptr() as *mut _,
    };
    let mut output_buf = ffi::gss_c_no_buffer();
    let mut ctx: ffi::GssCtxIdT = ffi::GSS_C_NO_CONTEXT;
    let mut src_name: ffi::GssNameT = ptr::null_mut();
    let mut ret_flags: ffi::OmUint32 = 0;
    let mut time_rec: ffi::OmUint32 = 0;
    let mut delegated_cred: ffi::GssCredIdT = ptr::null_mut();

    // Build channel bindings struct on the stack when provided.
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
            &bindings_storage
        }
    };

    // SAFETY: all arguments are valid locals; cred.raw is a live acceptor credential;
    // chan_bindings_ptr either null or points to the stack-allocated bindings_storage
    // which remains live until after this call returns.
    let major = unsafe {
        ffi::gss_accept_sec_context(
            &mut minor,
            &mut ctx,
            cred.raw,
            &input_buf,
            chan_bindings_ptr,
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
        // SAFETY: delegated_cred is non-null and was set by gss_accept_sec_context.
        unsafe { ffi::gss_release_cred(&mut minor, &mut delegated_cred) };
    }

    // Copy output token before freeing the GSSAPI buffer.
    let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
        // SAFETY: output_buf.value is a valid pointer to output_buf.length bytes
        // allocated by gss_accept_sec_context; we copy before releasing.
        let slice =
            unsafe { std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length) };
        let v = slice.to_vec();
        // SAFETY: output_buf was populated by gss_accept_sec_context.
        unsafe { ffi::gss_release_buffer(&mut minor, &mut output_buf) };
        v
    } else {
        Vec::new()
    };

    // Snapshot the error minor before cleanup calls overwrite it.
    let error_minor = minor;

    if major != ffi::GSS_S_COMPLETE {
        // Clean up context on failure.
        if !ctx.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: ctx is a valid context handle set by gss_accept_sec_context.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        if !src_name.is_null() {
            // SAFETY: src_name is a valid GssNameT set by gss_accept_sec_context.
            unsafe { ffi::gss_release_name(&mut minor, &mut src_name) };
        }
        return Err(GssError::AcceptContext {
            major,
            minor: error_minor,
        });
    }

    // Require anti-replay protection; reject contexts where the GSSAPI library
    // does not guarantee replay detection.
    if ret_flags & ffi::GSS_C_REPLAY_FLAG == 0 {
        if !ctx.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: ctx is a valid context handle set by gss_accept_sec_context.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        if !src_name.is_null() {
            // SAFETY: src_name is a valid GssNameT set by gss_accept_sec_context.
            unsafe { ffi::gss_release_name(&mut minor, &mut src_name) };
        }
        return Err(GssError::InsufficientFlags { ret_flags });
    }

    // Extract the principal name string.
    let mut name_buf = ffi::gss_c_no_buffer();
    // SAFETY: src_name is a valid GssNameT set by gss_accept_sec_context.
    let major_dn =
        unsafe { ffi::gss_display_name(&mut minor, src_name, &mut name_buf, ptr::null_mut()) };
    // SAFETY: src_name is valid; gss_release_name takes ownership.
    unsafe { ffi::gss_release_name(&mut minor, &mut src_name) };

    let principal = if major_dn == ffi::GSS_S_COMPLETE && !name_buf.value.is_null() {
        // SAFETY: name_buf.value is a valid pointer to name_buf.length bytes
        // allocated by gss_display_name; we copy before releasing.
        let slice =
            unsafe { std::slice::from_raw_parts(name_buf.value as *const u8, name_buf.length) };
        let s = std::str::from_utf8(slice)
            .map(|s| s.to_owned())
            .map_err(|_| GssError::InvalidUtf8);
        // SAFETY: name_buf was populated by gss_display_name.
        unsafe { ffi::gss_release_buffer(&mut minor, &mut name_buf) };
        // Clean up context before returning error.
        if s.is_err() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: ctx is a valid context handle from gss_accept_sec_context.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        s?
    } else {
        // SAFETY: name_buf may be empty or null; gss_release_buffer handles both safely.
        unsafe { ffi::gss_release_buffer(&mut minor, &mut name_buf) };
        let mut discard = ffi::gss_c_no_buffer();
        // SAFETY: ctx is a valid context handle from gss_accept_sec_context.
        unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
        if discard.length > 0 && !discard.value.is_null() {
            // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
            unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
        }
        return Err(GssError::DisplayName {
            major: major_dn,
            minor,
        });
    };

    // Delete the security context — not needed after principal extraction.
    let mut discard = ffi::gss_c_no_buffer();
    // SAFETY: ctx is a valid context handle from gss_accept_sec_context.
    unsafe { ffi::gss_delete_sec_context(&mut minor, &mut ctx, &mut discard) };
    if discard.length > 0 && !discard.value.is_null() {
        // SAFETY: discard is a non-null, non-empty buffer from gss_delete_sec_context.
        unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
    }

    Ok((out_token, principal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_nul_in_service_name_returns_error() {
        let err = GssServerCred::acquire("HTTP\0badname", "/tmp/fake.keytab").unwrap_err();
        assert!(matches!(err, GssError::NulInServiceName));
    }

    #[test]
    fn acquire_nul_in_keytab_path_returns_error() {
        let err = GssServerCred::acquire("HTTP", "/tmp/\0fake.keytab").unwrap_err();
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
