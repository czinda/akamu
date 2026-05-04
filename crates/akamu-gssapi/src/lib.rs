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
//! # let cred = akamu_gssapi::GssServerCred::acquire("HTTP", "/etc/akamu/http.keytab")
//! #     .expect("GSSAPI credential");
//! # let token_bytes: Vec<u8> = vec![];
//! let (out_token, principal) = akamu_gssapi::accept_token(&cred, &token_bytes, None)
//!     .expect("GSSAPI accept");
//! // `principal` is e.g. "user@REALM"
//! // `out_token` is the mutual-auth response (may be empty)
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
#[cfg(mit_kerberos)]
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
    /// Acquire an initiator credential from the default Kerberos credential
    /// cache (ccache).
    ///
    /// The calling process must already hold a valid TGT (e.g. from `kinit`).
    /// No keytab is required.  Passing `GSS_C_NO_CRED_STORE` (NULL) for the
    /// credential store makes MIT Kerberos use the ambient ccache, identical
    /// to calling `gss_acquire_cred()` with default arguments.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcquireCred`] — no valid TGT in the ccache, or the
    ///   Kerberos library returned an error.
    pub fn from_ccache() -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: NULL for cred_store == GSS_C_NO_CRED_STORE; MIT Kerberos
        // falls back to the default ccache, matching gss_acquire_cred() behaviour.
        // desired_name = GSS_C_NO_NAME selects the default principal.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                ptr::null(),     // cred_store = GSS_C_NO_CRED_STORE → default ccache
                &mut cred_handle,
                &mut actual_mechs,
                &mut time_rec,
            )
        };

        let error_minor = minor;
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&mut minor, &mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                unsafe { ffi::gss_release_cred(&mut minor, &mut cred_handle) };
            }
            return Err(GssError::AcquireCred { major, minor: error_minor });
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

impl Drop for GssClientContext {
    fn drop(&mut self) {
        let mut minor: ffi::OmUint32 = 0;
        if !self.raw.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: self.raw is a valid context handle set by gss_init_sec_context.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut self.raw, &mut discard) };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard was populated by gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&mut minor, &mut discard) };
            }
        }
        if !self.target_name.is_null() {
            // SAFETY: self.target_name was returned by gss_import_name.
            unsafe { ffi::gss_release_name(&mut minor, &mut self.target_name) };
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
        let major = unsafe { ffi::gss_import_name(&mut minor, &svc_buf, &svc_oid, &mut target_name) };
        if major != ffi::GSS_S_COMPLETE {
            return Err(GssError::ImportName { major, minor });
        }
        Ok(GssClientContext { raw: ffi::GSS_C_NO_CONTEXT, target_name })
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
                &input_storage
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
                &bindings_storage
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
                &mut minor,
                cred.raw,
                &mut self.raw,
                self.target_name,
                ptr::null(),     // mech_type = default (SPNEGO)
                ffi::GSS_C_MUTUAL_FLAG,
                0,               // time_req = library default
                chan_bindings_ptr,
                input_ptr,
                ptr::null_mut(), // actual_mech_type — not needed
                &mut output_buf,
                &mut ret_flags,
                &mut time_rec,
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
            unsafe { ffi::gss_release_buffer(&mut minor, &mut output_buf) };
            v
        } else {
            Vec::new()
        };

        if major != ffi::GSS_S_COMPLETE && major != ffi::GSS_S_CONTINUE_NEEDED {
            return Err(GssError::InitContext { major, minor: error_minor });
        }

        Ok((out_token, major == ffi::GSS_S_COMPLETE))
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
/// This is a single-step convenience wrapper around [`GssClientContext`].
/// Callers that need multi-round-trip exchange should use [`GssClientContext`] directly.
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
    let mut ctx = GssClientContext::new(target_service)?;
    let (token, _complete) = ctx.step(cred, None, channel_binding)?;
    Ok(token)
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
    // Snapshot minor before gss_release_name overwrites it, so DisplayName errors
    // carry the actual failure status rather than the release-name minor code.
    let dn_minor = minor;
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
            minor: dn_minor,
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
