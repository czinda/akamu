//! Safe, idiomatic Rust wrapper around the raw LDAP FFI layer.
//!
//! # Design
//!
//! [`LdapConnection`] is an RAII handle: it calls `ldap_unbind_ext_s` on drop
//! so connections are never leaked.  All unsafe pointer work is contained here;
//! nothing leaks raw C types into the public API.
//!
//! Synchronous `_s` variants of libldap functions are used throughout.
//! Callers should run this code in `tokio::task::spawn_blocking` when
//! integrating with async runtimes.

use std::collections::HashMap;
use std::ffi::{CStr, CString, NulError};
use std::ptr;

use libc::{c_char, c_int, c_void};
use tracing::debug;

use crate::ffi::{self, berval, BerElement, LDAP};
use crate::{Auth, LdapError, Scope};

// ── SASL interact callback ────────────────────────────────────────────────────

/// SASL interactive callback that answers every prompt with an empty string.
///
/// This is correct for GSSAPI (the Kerberos TGT in the credential cache
/// provides all credentials) and for EXTERNAL (the TLS client certificate does
/// the same).  libldap calls this when it needs user input; we tell it there is
/// none to give.
pub(crate) unsafe extern "C" fn sasl_interact_noop(
    _ld: *mut LDAP,
    _flags: libc::c_uint,
    _defaults: *mut c_void,
    interact_raw: *mut c_void,
) -> c_int {
    // The `interact` parameter is a pointer to a NULL-terminated array of
    // `sasl_interact_t` structs.  Walk it and fill every entry with an empty
    // response before returning.
    let mut interact = interact_raw as *mut ffi::sasl_interact;
    while (*interact).id != ffi::SASL_CB_LIST_END {
        (*interact).result = b"\0".as_ptr() as *const c_void;
        (*interact).len = 0;
        interact = interact.add(1);
    }
    ffi::LDAP_SUCCESS
}

// ── LdapConnection ────────────────────────────────────────────────────────────

/// A synchronous LDAP session handle.
///
/// The connection is opened immediately on construction.  Use [`Auth::Simple`]
/// or [`Auth::Gssapi`] to authenticate before calling [`search`][Self::search].
///
/// The underlying `LDAP *` handle is freed (via `ldap_unbind_ext_s`) when this
/// value is dropped, even if no explicit `unbind` call was made.
pub struct LdapConnection {
    /// Raw OpenLDAP session pointer.  Always non-null after construction.
    ld: *mut LDAP,
}

// SAFETY: OpenLDAP connections use a single connection handle internally; we
// never share a raw *mut LDAP between threads — the caller must ensure the
// connection is used from one thread at a time (or inside spawn_blocking).
// Making the type Send allows moving it into a blocking task.
unsafe impl Send for LdapConnection {}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        // ldap_unbind_ext_s always succeeds for session teardown; the return
        // value is discarded intentionally.
        unsafe {
            ffi::ldap_unbind_ext_s(self.ld, ptr::null_mut(), ptr::null_mut());
        }
    }
}

impl LdapConnection {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Open an LDAP connection to `uri` (e.g. `"ldap://host:389"` or
    /// `"ldaps://host:636"`).
    ///
    /// When `tls_ca_cert_file` is `Some(path)`, the PEM file at `path` is
    /// used to verify the server's TLS certificate.  For `ldap://` URIs with a
    /// CA cert, STARTTLS is negotiated before any credentials are sent.  For
    /// `ldaps://` URIs the TLS handshake happens immediately on connect.
    ///
    /// For GSSAPI binds over plain `ldap://`, pass `tls_ca_cert_file = None`:
    /// GSSAPI provides its own cryptographic protection, so transport-layer
    /// encryption is not required.
    pub fn connect(uri: &str, tls_ca_cert_file: Option<&str>) -> Result<Self, LdapError> {
        let needs_tls = tls_ca_cert_file.is_some() || uri.starts_with("ldaps://");
        let starttls = needs_tls && uri.starts_with("ldap://");
        debug!(uri, tls = needs_tls, starttls, "LDAP connect");

        let uri_c = cstr(uri)?;
        let mut ld: *mut LDAP = ptr::null_mut();

        let rc = unsafe { ffi::ldap_initialize(&mut ld, uri_c.as_ptr()) };
        check(rc, "ldap_initialize")?;

        // Enforce LDAPv3.
        let v3: c_int = 3;
        unsafe {
            ffi::ldap_set_option(
                ld,
                ffi::LDAP_OPT_PROTOCOL_VERSION,
                &v3 as *const c_int as *const _,
            );
        }

        if let Some(ca_path) = tls_ca_cert_file {
            std::fs::metadata(ca_path).map_err(|e| {
                LdapError::Tls(format!("cannot read TLS CA cert '{ca_path}': {e}"))
            })?;
            let path_c = cstr(ca_path)?;
            let rc = unsafe {
                ffi::ldap_set_option(
                    ld,
                    ffi::LDAP_OPT_X_TLS_CACERTFILE,
                    path_c.as_ptr() as *const _,
                )
            };
            if rc == ffi::LDAP_OPT_ERROR {
                return Err(LdapError::Tls(format!(
                    "ldap_set_option(CACERTFILE, '{ca_path}') failed"
                )));
            }
            // Rebuild the TLS context so the new CA takes effect.
            let zero: c_int = 0;
            let rc = unsafe {
                ffi::ldap_set_option(
                    ld,
                    ffi::LDAP_OPT_X_TLS_NEWCTX,
                    &zero as *const c_int as *const _,
                )
            };
            if rc == ffi::LDAP_OPT_ERROR {
                return Err(LdapError::Tls(
                    "ldap_set_option(NEWCTX) failed — CA cert may be invalid or unsupported".into(),
                ));
            }
        }

        if starttls {
            let rc =
                unsafe { ffi::ldap_start_tls_s(ld, ptr::null_mut(), ptr::null_mut()) };
            if rc != ffi::LDAP_SUCCESS {
                return Err(LdapError::Tls(format!(
                    "STARTTLS failed: {}",
                    err_string(rc)
                )));
            }
        }

        Ok(Self { ld })
    }

    // ── Bind ──────────────────────────────────────────────────────────────────

    /// Authenticate the session.
    ///
    /// # Authentication methods
    ///
    /// | Variant | Mechanism | Pre-condition |
    /// |---------|-----------|---------------|
    /// | [`Auth::Simple`] | LDAP simple bind (DN + password) | `bind_dn` and `password` |
    /// | [`Auth::Gssapi`] | SASL GSSAPI (Kerberos) | valid TGT in the credential cache |
    pub fn bind(&mut self, auth: &Auth) -> Result<(), LdapError> {
        match auth {
            Auth::Simple { bind_dn, password } => {
                debug!(bind_dn, "LDAP simple bind");
                self.bind_simple(bind_dn, password)
            }
            Auth::Gssapi => {
                debug!("LDAP GSSAPI bind");
                self.bind_gssapi()
            }
        }
    }

    fn bind_simple(&mut self, bind_dn: &str, password: &str) -> Result<(), LdapError> {
        let dn_c = cstr(bind_dn)?;
        let pw_bytes = password.as_bytes();
        let mut pw_bv = berval {
            bv_len: pw_bytes.len() as ffi::ber_len_t,
            bv_val: pw_bytes.as_ptr() as *mut c_char,
        };
        let mut msgid: c_int = -1;
        let rc = unsafe {
            ffi::ldap_sasl_bind(
                self.ld,
                dn_c.as_ptr(),
                ptr::null(), // mechanism = NULL → simple bind
                &mut pw_bv,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut msgid,
            )
        };
        check(rc, "ldap_sasl_bind (simple)")?;
        self.collect_result(msgid, "simple bind")
    }

    fn bind_gssapi(&mut self) -> Result<(), LdapError> {
        // Drive the SASL GSSAPI exchange: call ldap_sasl_interactive_bind in a
        // loop until LDAP_SUCCESS; the TGT in the Kerberos credential cache
        // supplies all credentials so the interact callback is a no-op.
        let mut result: *mut ffi::LDAPMessage = ptr::null_mut();
        let mut rmech: *const c_char = ptr::null();
        loop {
            let mut msgid: c_int = -1;
            let rc = unsafe {
                ffi::ldap_sasl_interactive_bind(
                    self.ld,
                    c"".as_ptr(),
                    c"GSSAPI".as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ffi::LDAP_SASL_QUIET,
                    Some(sasl_interact_noop),
                    ptr::null_mut(),
                    result, // NULL on first call; partial result on subsequent calls
                    &mut rmech,
                    &mut msgid,
                )
            };
            // Free the previous partial result, if any.
            if !result.is_null() {
                unsafe { ffi::ldap_msgfree(result) };
                result = ptr::null_mut();
            }
            if rc == ffi::LDAP_SUCCESS {
                return Ok(());
            }
            if rc != ffi::LDAP_SASL_BIND_IN_PROGRESS {
                return check(rc, "GSSAPI bind");
            }
            // More round-trips needed; collect the partial response.
            let rc2 = unsafe {
                ffi::ldap_result(
                    self.ld,
                    msgid,
                    ffi::LDAP_MSG_ALL,
                    ptr::null_mut(), // block until result arrives
                    &mut result,
                )
            };
            if rc2 < 0 {
                return Err(LdapError::Protocol {
                    code: rc2,
                    msg: "ldap_result during GSSAPI exchange failed".into(),
                });
            }
        }
    }

    /// Wait (blocking) for the result of a previously sent request identified
    /// by `msgid`, then assert it succeeded.
    fn collect_result(&mut self, msgid: c_int, context: &str) -> Result<(), LdapError> {
        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(), // NULL timeout → block until result arrives
                &mut res,
            )
        };
        if !res.is_null() {
            unsafe { ffi::ldap_msgfree(res) };
        }
        if rc < 0 {
            return Err(LdapError::Protocol {
                code: rc,
                msg: format!("ldap_result for {context} failed"),
            });
        }
        Ok(())
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// Perform a synchronous LDAP search.
    ///
    /// Returns one [`SearchEntry`] per result entry, each containing every
    /// requested attribute decoded as both UTF-8 strings and raw bytes (for
    /// binary attributes like `certProfileConfig`).
    ///
    /// # Arguments
    ///
    /// * `base`   — Base DN for the search.
    /// * `scope`  — [`Scope::Base`], [`Scope::OneLevel`], or [`Scope::Subtree`].
    /// * `filter` — RFC 4515 filter string, e.g. `"(objectClass=certProfile)"`.
    /// * `attrs`  — Attribute names to retrieve.  An empty slice requests all
    ///   attributes.
    pub fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, LdapError> {
        debug!(base, ?scope, filter, "LDAP search");

        let base_c = cstr(base)?;
        let filter_c = cstr(filter)?;

        // Build a NULL-terminated *mut *mut c_char array for the attribute list.
        let attr_cstrings: Vec<CString> = attrs
            .iter()
            .map(|a| cstr(a))
            .collect::<Result<_, _>>()?;
        let mut attr_ptrs: Vec<*mut c_char> = attr_cstrings
            .iter()
            .map(|s| s.as_ptr() as *mut c_char)
            .collect();
        attr_ptrs.push(ptr::null_mut()); // NULL sentinel

        let attrs_arg = if attrs.is_empty() {
            ptr::null_mut()
        } else {
            attr_ptrs.as_mut_ptr()
        };

        let mut msgid: c_int = -1;
        let rc = unsafe {
            ffi::ldap_search_ext(
                self.ld,
                base_c.as_ptr(),
                scope.as_int(),
                filter_c.as_ptr(),
                attrs_arg,
                0,              // attrsonly = false
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(), // no timeout
                0,               // no size limit
                &mut msgid,
            )
        };
        check(rc, "ldap_search_ext")?;

        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(), // block until complete result arrives
                &mut res,
            )
        };
        if rc < 0 {
            return Err(LdapError::Protocol {
                code: rc,
                msg: format!("ldap_result for search failed"),
            });
        }

        // `res` now owns the result chain; walk it and build SearchEntry values.
        let entries = unsafe { collect_entries(self.ld, res) };
        // Free the entire result chain.
        unsafe { ffi::ldap_msgfree(res) };
        entries
    }
}

// ── SearchEntry ───────────────────────────────────────────────────────────────

/// One LDAP entry returned from a search.
#[derive(Debug, Default)]
pub struct SearchEntry {
    /// DN of the entry.
    pub dn: String,
    /// Attribute values decoded as UTF-8 strings (best-effort).
    ///
    /// Keys are lower-cased attribute names; values are lists of strings.
    /// Attributes whose values are not valid UTF-8 appear here with
    /// replacement characters; use [`bin_attrs`][Self::bin_attrs] for
    /// reliable binary access.
    pub attrs: HashMap<String, Vec<String>>,
    /// Raw binary attribute values.
    ///
    /// Keys are lower-cased attribute names; values are raw byte vectors.
    /// Always populated, even when [`attrs`][Self::attrs] contains the
    /// same value as valid UTF-8.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Walk the libldap result chain and decode each entry's attributes.
///
/// # Safety
///
/// `res` must be a valid (possibly NULL) result chain from `ldap_search_ext_s`.
/// The caller must free `res` with `ldap_msgfree` after this function returns.
unsafe fn collect_entries(
    ld: *mut LDAP,
    res: *mut ffi::LDAPMessage,
) -> Result<Vec<SearchEntry>, LdapError> {
    let mut entries = Vec::new();
    let mut entry = ffi::ldap_first_entry(ld, res);
    while !entry.is_null() {
        entries.push(decode_entry(ld, entry)?);
        entry = ffi::ldap_next_entry(ld, entry);
    }
    Ok(entries)
}

/// Decode one LDAP entry into a [`SearchEntry`].
unsafe fn decode_entry(
    ld: *mut LDAP,
    entry: *mut ffi::LDAPMessage,
) -> Result<SearchEntry, LdapError> {
    let mut se = SearchEntry::default();

    // DN
    let dn_ptr = ffi::ldap_get_dn(ld, entry);
    if !dn_ptr.is_null() {
        se.dn = CStr::from_ptr(dn_ptr)
            .to_string_lossy()
            .into_owned();
        ffi::ldap_memfree(dn_ptr as *mut c_void);
    }

    // Attribute iteration
    let mut ber: *mut BerElement = ptr::null_mut();
    let mut attr_ptr = ffi::ldap_first_attribute(ld, entry, &mut ber);
    while !attr_ptr.is_null() {
        let attr_name = CStr::from_ptr(attr_ptr)
            .to_string_lossy()
            .to_ascii_lowercase();

        let vals_ptr = ffi::ldap_get_values_len(ld, entry, attr_ptr);
        if !vals_ptr.is_null() {
            let (str_vals, bin_vals) = decode_bervals(vals_ptr);
            se.attrs.entry(attr_name.clone()).or_default().extend(str_vals);
            se.bin_attrs.entry(attr_name).or_default().extend(bin_vals);
            ffi::ldap_value_free_len(vals_ptr);
        }

        ffi::ldap_memfree(attr_ptr as *mut c_void);
        attr_ptr = ffi::ldap_next_attribute(ld, entry, ber);
    }
    if !ber.is_null() {
        ffi::ber_free(ber, 0);
    }

    Ok(se)
}

/// Decode a NULL-terminated `berval**` into parallel string and byte vectors.
unsafe fn decode_bervals(vals_ptr: *mut *mut berval) -> (Vec<String>, Vec<Vec<u8>>) {
    let mut str_vals = Vec::new();
    let mut bin_vals = Vec::new();
    let mut i = 0usize;
    loop {
        let bv = *vals_ptr.add(i);
        if bv.is_null() {
            break;
        }
        let bytes = std::slice::from_raw_parts((*bv).bv_val as *const u8, (*bv).bv_len as usize);
        bin_vals.push(bytes.to_vec());
        str_vals.push(String::from_utf8_lossy(bytes).into_owned());
        i += 1;
    }
    (str_vals, bin_vals)
}

/// Convert an `&str` to a `CString`, mapping interior-NUL errors to `LdapError`.
pub(crate) fn cstr(s: &str) -> Result<CString, LdapError> {
    CString::new(s).map_err(|e: NulError| LdapError::NulByte(e.to_string()))
}

/// Convert an LDAP result code to an owned error message string.
fn err_string(code: c_int) -> String {
    let ptr = unsafe { ffi::ldap_err2string(code) };
    if ptr.is_null() {
        return format!("code {code}");
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("(invalid UTF-8)")
        .to_owned()
}

/// Return `Ok(())` if `rc` is `LDAP_SUCCESS`, otherwise map to `LdapError`.
fn check(rc: c_int, context: &str) -> Result<(), LdapError> {
    if rc == ffi::LDAP_SUCCESS {
        Ok(())
    } else {
        Err(LdapError::Protocol {
            code: rc,
            msg: format!("{context}: {}", err_string(rc)),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scope;

    #[test]
    fn connect_to_nonexistent_host_returns_error() {
        // ldap_initialize merely parses the URI; the error surfaces on first I/O.
        // A search against a host that is not listening should fail quickly.
        let mut conn =
            LdapConnection::connect("ldap://127.0.0.1:38999", None).expect("initialize");
        let err = conn
            .search("dc=test", Scope::Base, "(objectClass=*)", &[])
            .expect_err("search to closed port should fail");
        assert!(
            matches!(err, LdapError::Protocol { .. }),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn connect_with_nonexistent_ca_cert_returns_tls_error() {
        let err = LdapConnection::connect("ldap://127.0.0.1:389", Some("/nonexistent/ca.pem"))
            .expect_err("should fail on missing CA cert");
        assert!(
            matches!(err, LdapError::Tls(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn scope_as_int_values_match_rfc() {
        assert_eq!(Scope::Base.as_int(), 0);
        assert_eq!(Scope::OneLevel.as_int(), 1);
        assert_eq!(Scope::Subtree.as_int(), 2);
    }
}
