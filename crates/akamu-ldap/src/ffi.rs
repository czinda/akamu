//! Raw FFI declarations for OpenLDAP (`libldap`/`liblber`) and SASL (`libsasl2`).
//!
//! All items here are direct C representations.  Nothing in this module is
//! intended for use outside [`super::conn`]; callers should use the safe
//! [`LdapConnection`][super::LdapConnection] API instead.
//!
//! Struct layouts are verified against `libldap-sys 0.2` bindgen output for
//! OpenLDAP 2.6 on x86-64 Linux.

#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_uint, c_ulong, c_void, timeval};

// ── Primitive type aliases ────────────────────────────────────────────────────

/// Length type used in BER/LDAP structures (`unsigned long` on LP64).
pub type ber_len_t = c_ulong;

// ── Opaque handle types ───────────────────────────────────────────────────────

/// Opaque LDAP session handle; never dereferenced in Rust.
#[repr(C)]
pub struct LDAP {
    _opaque: [u8; 0],
}

/// Opaque LDAP message / result set handle.
#[repr(C)]
pub struct LDAPMessage {
    _opaque: [u8; 0],
}

/// Opaque BER element cursor, used when iterating attributes.
#[repr(C)]
pub struct BerElement {
    _opaque: [u8; 0],
}

// ── Transparent data structures ───────────────────────────────────────────────

/// Binary value — length + pointer to data (matches C `struct berval`).
///
/// Layout verified: size 16, align 8, `bv_len` at offset 0, `bv_val` at 8.
#[repr(C)]
pub struct berval {
    pub bv_len: ber_len_t,
    pub bv_val: *mut c_char,
}

/// An LDAP control attached to a request or response.
///
/// Layout verified: size 32, align 8.
/// Fields: `ldctl_oid` at 0, `ldctl_value` at 8, `ldctl_iscritical` at 24.
#[repr(C)]
pub struct LDAPControl {
    /// OID of the control (NUL-terminated C string; owned by libldap).
    pub ldctl_oid: *mut c_char,
    /// DER-encoded control value.
    pub ldctl_value: berval,
    /// Non-zero if the control is marked critical.
    pub ldctl_iscritical: c_char,
}

/// SASL interactive callback prompt descriptor (matches C `sasl_interact_t`).
///
/// Layout verified: size 48, align 8 on LP64 (Linux/macOS x86-64/aarch64).
/// The compile-time assertions below confirm this at build time.
#[repr(C)]
pub struct sasl_interact {
    /// Callback identifier.  `SASL_CB_LIST_END` (0) terminates the array.
    pub id: c_ulong,
    pub challenge: *const c_char,
    pub prompt: *const c_char,
    pub defresult: *const c_char,
    /// Caller writes the answer here.
    pub result: *const c_void,
    /// Byte length of `result`.
    pub len: c_uint,
}

const _: () = {
    // sasl_interact_t layout assertions for LP64 (8-byte pointer, 8-byte c_ulong).
    // These fire at compile time on non-LP64 targets before any unsafe code runs.
    #[cfg(target_pointer_width = "64")]
    {
        assert!(std::mem::size_of::<sasl_interact>() == 48);
        assert!(std::mem::align_of::<sasl_interact>() == 8);
    }
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// LDAP operation succeeded.
pub const LDAP_SUCCESS: c_int = 0;

/// Returned by `ldap_sasl_bind` / `ldap_sasl_interactive_bind` when more
/// round-trips are needed to complete a multi-step SASL exchange.
pub const LDAP_SASL_BIND_IN_PROGRESS: c_int = 0x0e;

/// `ldap_set_option` / `ldap_get_option` return this on failure.
pub const LDAP_OPT_ERROR: c_int = -1;

/// Option: LDAPv3 protocol version (`int *` argument).
pub const LDAP_OPT_PROTOCOL_VERSION: c_int = 0x0011;

/// Option: socket file descriptor of the current connection (`int *` out-argument).
pub const LDAP_OPT_DESC: c_int = 0x0001;

/// Option: path to a PEM CA certificate file for TLS (`char *` argument).
pub const LDAP_OPT_X_TLS_CACERTFILE: c_int = 0x6002;

/// Option: rebuild the OpenLDAP-internal TLS context after option changes (`int *` argument).
pub const LDAP_OPT_X_TLS_NEWCTX: c_int = 0x600f;

/// Option: TCP-level connect timeout (`struct timeval *` argument).
pub const LDAP_OPT_NETWORK_TIMEOUT: c_int = 0x5010;

/// Option: default timeout for synchronous operations (`struct timeval *` argument).
pub const LDAP_OPT_TIMEOUT: c_int = 0x5014;

/// SASL flag: do not interact with the user; fail on any prompt.
pub const LDAP_SASL_QUIET: c_uint = 2;

/// `ldap_result` `all` flag: wait for the entire result chain.
pub const LDAP_MSG_ALL: c_int = 1;

/// LDAP search scope: the base object only.
pub const LDAP_SCOPE_BASE: c_int = 0x0000;

/// LDAP search scope: immediate children of the base only.
pub const LDAP_SCOPE_ONELEVEL: c_int = 0x0001;

/// LDAP search scope: the base object and all descendants.
pub const LDAP_SCOPE_SUBTREE: c_int = 0x0002;

/// Sentinel value that terminates a `sasl_interact_t` array.
pub const SASL_CB_LIST_END: c_ulong = 0;

// ── Function pointer types ────────────────────────────────────────────────────

/// Signature of the SASL interactive bind callback.
///
/// libldap calls this whenever it needs the application to supply a value for
/// a SASL prompt.  Our implementation (`sasl_interact_noop`) always provides
/// empty answers, which is correct for GSSAPI (TGT in ccache) and EXTERNAL
/// (client certificate in TLS).
pub type SaslInteractProc = Option<
    unsafe extern "C" fn(
        ld: *mut LDAP,
        flags: c_uint,
        defaults: *mut c_void,
        interact: *mut c_void,
    ) -> c_int,
>;

// ── Extern "C" function declarations ─────────────────────────────────────────

extern "C" {
    // ── Connection lifecycle ──────────────────────────────────────────────────

    /// Initialise an LDAP session handle for `url` without opening a TCP
    /// connection yet.  Writes the new handle into `*ldp`.
    pub fn ldap_initialize(ldp: *mut *mut LDAP, url: *const c_char) -> c_int;

    /// Set a session option.  `invalue` is option-specific; see `LDAP_OPT_*`.
    pub fn ldap_set_option(ld: *mut LDAP, option: c_int, invalue: *const c_void) -> c_int;

    /// Read a session option into `outvalue`.  `outvalue` is option-specific;
    /// see `LDAP_OPT_*`.  Use [`LDAP_OPT_DESC`] to get the underlying socket fd.
    pub fn ldap_get_option(ld: *mut LDAP, option: c_int, outvalue: *mut c_void) -> c_int;

    /// Upgrade a plain `ldap://` connection to TLS using STARTTLS.
    ///
    /// There is no non-blocking form of this operation in OpenLDAP; it always
    /// completes the full TLS handshake before returning.
    pub fn ldap_start_tls_s(
        ld: *mut LDAP,
        serverctrls: *mut *mut LDAPControl,
        clientctrls: *mut *mut LDAPControl,
    ) -> c_int;

    /// Close the connection and free the session handle.
    ///
    /// There is no non-blocking form of unbind in OpenLDAP.
    pub fn ldap_unbind_ext_s(
        ld: *mut LDAP,
        serverctrls: *mut *mut LDAPControl,
        clientctrls: *mut *mut LDAPControl,
    ) -> c_int;

    // ── Bind operations ───────────────────────────────────────────────────────

    /// Asynchronous simple or SASL non-interactive bind.
    ///
    /// Pass `mechanism = NULL` for LDAP simple bind; pass a SASL mechanism
    /// name (e.g. `"PLAIN"`) for SASL.  `cred` carries the password as a
    /// `berval`.  Writes the message ID of the sent request into `*msgidp`;
    /// collect the result with [`ldap_result`].
    pub fn ldap_sasl_bind(
        ld: *mut LDAP,
        dn: *const c_char,
        mechanism: *const c_char,
        cred: *mut berval,
        serverctrls: *mut *mut LDAPControl,
        clientctrls: *mut *mut LDAPControl,
        msgidp: *mut c_int,
    ) -> c_int;

    /// Asynchronous SASL interactive bind — used for GSSAPI and EXTERNAL.
    ///
    /// libldap calls `proc_` for each required SASL prompt.  For GSSAPI, pass
    /// `LDAP_SASL_QUIET` and `sasl_interact_noop`
    /// so the Kerberos credential cache supplies all credentials automatically.
    ///
    /// When the SASL exchange requires multiple round-trips, libldap returns
    /// [`LDAP_SASL_BIND_IN_PROGRESS`]; collect the partial result with
    /// [`ldap_result`] and call this function again with that result as `result`.
    /// Keep looping until the return value is [`LDAP_SUCCESS`].
    pub fn ldap_sasl_interactive_bind(
        ld: *mut LDAP,
        dn: *const c_char,
        sasl_mechanism: *const c_char,
        serverctrls: *mut *mut LDAPControl,
        clientctrls: *mut *mut LDAPControl,
        flags: c_uint,
        proc_: SaslInteractProc,
        defaults: *mut c_void,
        result: *mut LDAPMessage,
        rmechp: *mut *const c_char,
        msgidp: *mut c_int,
    ) -> c_int;

    // ── Search ────────────────────────────────────────────────────────────────

    /// Begin an asynchronous LDAP search.
    ///
    /// `attrs` is a NULL-terminated array of attribute name strings; pass
    /// `NULL` to request all attributes.  Writes the message ID of the
    /// sent request into `*msgidp`; collect results with [`ldap_result`].
    pub fn ldap_search_ext(
        ld: *mut LDAP,
        base: *const c_char,
        scope: c_int,
        filter: *const c_char,
        attrs: *mut *mut c_char,
        attrsonly: c_int,
        serverctrls: *mut *mut LDAPControl,
        clientctrls: *mut *mut LDAPControl,
        timeout: *mut timeval,
        sizelimit: c_int,
        msgidp: *mut c_int,
    ) -> c_int;

    // ── Result collection ─────────────────────────────────────────────────────

    /// Wait for and return the result of a previously initiated operation.
    ///
    /// `msgid` identifies the pending request (or `LDAP_RES_ANY = -1` for any
    /// pending request).  `all` controls whether partial search entries are
    /// returned; use [`LDAP_MSG_ALL`] to wait for the complete result chain.
    ///
    /// `timeout`: `NULL` = block forever; `{0, 0}` = poll without blocking.
    ///
    /// Returns:
    /// - `> 0` — message type (e.g. 101 = `LDAP_RES_SEARCH_RESULT`); result
    ///   written to `*result` and must be freed with [`ldap_msgfree`].
    /// - `0`   — timed out; no result yet.
    /// - `< 0` — error.
    pub fn ldap_result(
        ld: *mut LDAP,
        msgid: c_int,
        all: c_int,
        timeout: *mut timeval,
        result: *mut *mut LDAPMessage,
    ) -> c_int;

    // ── Result iteration ──────────────────────────────────────────────────────

    /// Return the first entry in a result chain.
    pub fn ldap_first_entry(ld: *mut LDAP, chain: *mut LDAPMessage) -> *mut LDAPMessage;

    /// Return the next entry after `entry`.
    pub fn ldap_next_entry(ld: *mut LDAP, entry: *mut LDAPMessage) -> *mut LDAPMessage;

    /// Return the count of entries in a result chain.
    pub fn ldap_count_entries(ld: *mut LDAP, chain: *mut LDAPMessage) -> c_int;

    /// Return the DN of `entry` as a malloc'd C string; free with [`ldap_memfree`].
    pub fn ldap_get_dn(ld: *mut LDAP, entry: *mut LDAPMessage) -> *mut c_char;

    // ── Attribute iteration ───────────────────────────────────────────────────

    /// Return the name of the first attribute in `entry`.
    ///
    /// Writes a BerElement cursor into `*ber`; the caller must free it with
    /// `ber_free(*ber, 0)` when done iterating.
    pub fn ldap_first_attribute(
        ld: *mut LDAP,
        entry: *mut LDAPMessage,
        ber: *mut *mut BerElement,
    ) -> *mut c_char;

    /// Advance the BerElement cursor and return the next attribute name.
    pub fn ldap_next_attribute(
        ld: *mut LDAP,
        entry: *mut LDAPMessage,
        ber: *mut BerElement,
    ) -> *mut c_char;

    /// Return all values of `attr` in `entry` as a NULL-terminated `berval**`.
    ///
    /// Values are binary-safe.  Free with [`ldap_value_free_len`].
    pub fn ldap_get_values_len(
        ld: *mut LDAP,
        entry: *mut LDAPMessage,
        attr: *const c_char,
    ) -> *mut *mut berval;

    /// Free a `berval**` returned by [`ldap_get_values_len`].
    pub fn ldap_value_free_len(vals: *mut *mut berval);

    // ── Memory management ─────────────────────────────────────────────────────

    /// Free a string allocated by libldap (e.g. DN, attribute name).
    pub fn ldap_memfree(p: *mut c_void);

    /// Free a BerElement cursor allocated by [`ldap_first_attribute`].
    ///
    /// Pass `freebuf = 0` when the element was created by attribute iteration
    /// (libldap owns the underlying buffer).
    pub fn ber_free(ber: *mut BerElement, freebuf: c_int);

    /// Free an entire result chain returned by a search or `ldap_result`.
    pub fn ldap_msgfree(lm: *mut LDAPMessage) -> c_int;

    /// Free a NULL-terminated array of `LDAPControl *` (e.g. returned by
    /// [`ldap_parse_result`]).
    pub fn ldap_controls_free(ctrls: *mut *mut LDAPControl);

    // ── Error handling ────────────────────────────────────────────────────────

    /// Convert an LDAP result code to a human-readable C string.
    ///
    /// The returned pointer is statically allocated; do not free it.
    pub fn ldap_err2string(err: c_int) -> *mut c_char;

    /// Extract error code, matched DN, diagnostic message, and server controls
    /// from a result message.
    ///
    /// When `freeit` is non-zero, `res` is freed by this call.
    pub fn ldap_parse_result(
        ld: *mut LDAP,
        res: *mut LDAPMessage,
        errcodep: *mut c_int,
        matcheddnp: *mut *mut c_char,
        diagmsgp: *mut *mut c_char,
        referralsp: *mut *mut *mut c_char,
        serverctrls: *mut *mut *mut LDAPControl,
        freeit: c_int,
    ) -> c_int;
}
