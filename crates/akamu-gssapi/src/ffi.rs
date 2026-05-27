//! Raw FFI bindings to libgssapi_krb5.
//!
//! Only the subset needed for server-side SPNEGO acceptance is declared here.
//! All pointer types use opaque enum structs to prevent accidental dereferencing.

use libc::{c_char, c_int, c_uint, c_void, size_t};
use std::ptr;

pub type OmUint32 = u32;

/// Opaque GSSAPI security context handle.
pub enum GssCtxIdStruct {}
pub type GssCtxIdT = *mut GssCtxIdStruct;

/// Opaque GSSAPI credential handle.
pub enum GssCredIdStruct {}
pub type GssCredIdT = *mut GssCredIdStruct;

/// Opaque GSSAPI name handle.
pub enum GssNameStruct {}
pub type GssNameT = *mut GssNameStruct;

/// Opaque GSSAPI OID set handle.
pub enum GssOidSetStruct {}
pub type GssOidSetT = *mut GssOidSetStruct;

/// Variable-length byte buffer used for tokens and name strings.
#[repr(C)]
pub struct GssBufferDesc {
    pub length: size_t,
    pub value: *mut c_void,
}

/// OID descriptor: a DER-encoded object identifier.
#[repr(C)]
pub struct GssOidDesc {
    pub length: c_uint,
    pub elements: *mut c_void,
}

/// One key-value pair in a credential store (RFC 5587 extension).
#[repr(C)]
pub struct GssKeyValueElementDesc {
    pub key: *const c_char,
    pub value: *const c_char,
}

/// Array of key-value pairs for gss_acquire_cred_from().
#[repr(C)]
pub struct GssKeyValueSetDesc {
    pub count: OmUint32,
    pub elements: *mut GssKeyValueElementDesc,
}

// ── Constants ──────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub const GSS_S_COMPLETE: OmUint32 = 0;
#[allow(dead_code)]
pub const GSS_S_CONTINUE_NEEDED: OmUint32 = 1;

#[allow(dead_code)]
pub const GSS_C_ACCEPT: i32 = 2;

pub const GSS_C_NO_CONTEXT: GssCtxIdT = ptr::null_mut();
#[allow(dead_code)]
pub const GSS_C_NO_CREDENTIAL: GssCredIdT = ptr::null_mut();
#[allow(dead_code)]
pub const GSS_C_NO_NAME: GssNameT = ptr::null_mut();
pub const GSS_C_NO_OID_SET: GssOidSetT = ptr::null_mut();

pub fn gss_c_no_buffer() -> GssBufferDesc {
    GssBufferDesc {
        length: 0,
        value: ptr::null_mut(),
    }
}

/// Usage flag: credential may be used by an initiator (client).
pub const GSS_C_INITIATE: i32 = 1;

/// Usage flag: credential may be used by both an initiator (client) and acceptor (server).
pub const GSS_C_BOTH: i32 = 0;

/// Status type: interpret `status_value` as a GSS-API major code.
pub const GSS_C_GSS_CODE: i32 = 1;
/// Status type: interpret `status_value` as a mechanism-specific minor code.
pub const GSS_C_MECH_CODE: i32 = 2;

/// Request flag: ask the acceptor to perform mutual authentication.
#[allow(dead_code)]
pub const GSS_C_MUTUAL_FLAG: OmUint32 = 2;

/// Return flag: replay detection is active on this context (RFC 2744).
pub const GSS_C_REPLAY_FLAG: OmUint32 = 4;

/// Address family "unset" — used in channel bindings for non-IP endpoints.
pub const GSS_C_AF_UNSET: OmUint32 = 0;

/// gss_channel_bindings_struct (RFC 2744 Appendix B).
///
/// For tls-server-end-point channel bindings:
///   - initiator/acceptor_addrtype = GSS_C_AF_UNSET
///   - initiator/acceptor_address  = empty GssBufferDesc
///   - application_data            = the channel binding bytes
#[repr(C)]
pub struct GssChannelBindingsStruct {
    pub initiator_addrtype: OmUint32,
    pub initiator_address: GssBufferDesc,
    pub acceptor_addrtype: OmUint32,
    pub acceptor_address: GssBufferDesc,
    pub application_data: GssBufferDesc,
}

// NT_HOSTBASED_SERVICE OID: 1.3.6.1.5.6.2 (DER encoding: 2b 06 01 05 06 02)
static GSS_C_NT_HOSTBASED_SERVICE_OID_BYTES: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x06, 0x02];

// GSS_KRB5_NT_PRINCIPAL_NAME OID: 1.2.840.113554.1.2.2.1
// Accepts "user@REALM" Kerberos principal strings for gss_import_name.
static GSS_KRB5_NT_PRINCIPAL_NAME_OID_BYTES: [u8; 10] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];

/// OID descriptor for GSS_C_NT_HOSTBASED_SERVICE (e.g. "HTTP@host").
///
/// The GSSAPI C API takes `*mut c_void` for the OID elements even though it
/// never writes through the pointer; casting from `*const` is safe here.
pub fn gss_c_nt_hostbased_service() -> GssOidDesc {
    GssOidDesc {
        length: 6,
        #[allow(clippy::as_ptr_cast_mut)]
        elements: GSS_C_NT_HOSTBASED_SERVICE_OID_BYTES.as_ptr() as *mut c_void,
    }
}

/// OID descriptor for `GSS_KRB5_NT_PRINCIPAL_NAME` (Kerberos principal, e.g. "user@REALM").
pub fn gss_krb5_nt_principal_name() -> GssOidDesc {
    GssOidDesc {
        length: 10,
        #[allow(clippy::as_ptr_cast_mut)]
        elements: GSS_KRB5_NT_PRINCIPAL_NAME_OID_BYTES.as_ptr() as *mut c_void,
    }
}

// ── libkrb5 opaque types ───────────────────────────────────────────────────────

pub enum Krb5ContextStruct {}
pub type Krb5Context = *mut Krb5ContextStruct;

pub enum Krb5KeytabStruct {}
pub type Krb5Keytab = *mut Krb5KeytabStruct;

pub enum Krb5CcacheStruct {}
pub type Krb5Ccache = *mut Krb5CcacheStruct;

pub enum Krb5PrincipalStruct {}
pub type Krb5Principal = *mut Krb5PrincipalStruct;

/// Opaque byte buffer matching `sizeof(krb5_creds)` on 64-bit Linux (120 bytes,
/// measured against MIT Kerberos 1.21 on Fedora 42). Zeroed before every use;
/// only passed to `krb5_get_init_creds_keytab`, `krb5_cc_store_cred`, and
/// `krb5_free_cred_contents` — we never inspect its fields.
///
/// # Safety
///
/// The buffer size (128 bytes, `align(8)`) must be at least as large as the
/// real `krb5_creds` struct on all supported targets. If MIT Kerberos changes
/// its ABI layout and the struct grows beyond 128 bytes, writing through a
/// `*mut Krb5Creds` pointer will silently overflow the buffer. The size was
/// validated against MIT Kerberos 1.21 on x86-64 Fedora 42; re-validate when
/// upgrading the library or porting to a new architecture.
#[repr(C, align(8))]
pub struct Krb5Creds(pub [u8; 128]); // 128 ≥ 120, aligned to pointer size

// ── libkrb5 extern functions ───────────────────────────────────────────────────

#[link(name = "krb5")]
extern "C" {
    pub fn krb5_init_context(context: *mut Krb5Context) -> c_int;
    pub fn krb5_free_context(context: Krb5Context);
    pub fn krb5_parse_name(
        context: Krb5Context,
        name: *const c_char,
        principal_out: *mut Krb5Principal,
    ) -> c_int;
    pub fn krb5_free_principal(context: Krb5Context, val: Krb5Principal);
    pub fn krb5_kt_resolve(context: Krb5Context, name: *const c_char, id: *mut Krb5Keytab)
        -> c_int;
    pub fn krb5_kt_close(context: Krb5Context, id: Krb5Keytab) -> c_int;
    pub fn krb5_cc_resolve(
        context: Krb5Context,
        name: *const c_char,
        cache: *mut Krb5Ccache,
    ) -> c_int;
    pub fn krb5_cc_initialize(
        context: Krb5Context,
        cache: Krb5Ccache,
        principal: Krb5Principal,
    ) -> c_int;
    pub fn krb5_cc_close(context: Krb5Context, cache: Krb5Ccache) -> c_int;
    pub fn krb5_get_init_creds_keytab(
        context: Krb5Context,
        creds: *mut Krb5Creds,
        client: Krb5Principal,
        arg_keytab: Krb5Keytab,
        start_time: i32,
        in_tkt_service: *const c_char,
        k5_gic_options: *mut c_void,
    ) -> c_int;
    pub fn krb5_cc_store_cred(
        context: Krb5Context,
        cache: Krb5Ccache,
        creds: *mut Krb5Creds,
    ) -> c_int;
    pub fn krb5_free_cred_contents(context: Krb5Context, val: *mut Krb5Creds);
    pub fn krb5_get_error_message(ctx: Krb5Context, code: c_int) -> *const c_char;
    pub fn krb5_free_error_message(ctx: Krb5Context, msg: *const c_char);
}

// ── Extern functions ───────────────────────────────────────────────────────────

extern "C" {
    /// Parse a host-based service name string into a `GssNameT`.
    pub fn gss_import_name(
        minor_status: *mut OmUint32,
        input_name_buffer: *const GssBufferDesc,
        input_name_type: *const GssOidDesc,
        output_name: *mut GssNameT,
    ) -> OmUint32;

    /// Acquire server credentials from a credential store (RFC 5587).
    /// Pass a `GssKeyValueSetDesc` with `{"keytab", "/path"}` to select the keytab.
    pub fn gss_acquire_cred_from(
        minor_status: *mut OmUint32,
        desired_name: GssNameT,
        time_req: OmUint32,
        desired_mechs: GssOidSetT,
        cred_usage: i32,
        cred_store: *const GssKeyValueSetDesc,
        output_cred_handle: *mut GssCredIdT,
        actual_mechs: *mut GssOidSetT,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    /// Process one client SPNEGO/Kerberos token on the server side.
    pub fn gss_accept_sec_context(
        minor_status: *mut OmUint32,
        context_handle: *mut GssCtxIdT,
        acceptor_cred_handle: GssCredIdT,
        input_token_buffer: *const GssBufferDesc,
        input_chan_bindings: *const GssChannelBindingsStruct,
        src_name: *mut GssNameT,
        mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
        delegated_cred_handle: *mut GssCredIdT,
    ) -> OmUint32;

    /// Convert a `GssNameT` to a human-readable string (e.g. "user@REALM").
    pub fn gss_display_name(
        minor_status: *mut OmUint32,
        input_name: GssNameT,
        output_name_buffer: *mut GssBufferDesc,
        output_name_type: *mut *mut GssOidDesc,
    ) -> OmUint32;

    /// Release a name handle.
    pub fn gss_release_name(minor_status: *mut OmUint32, name: *mut GssNameT) -> OmUint32;

    /// Release a buffer allocated by GSSAPI.
    pub fn gss_release_buffer(minor_status: *mut OmUint32, buffer: *mut GssBufferDesc) -> OmUint32;

    /// Release a credential handle.
    pub fn gss_release_cred(minor_status: *mut OmUint32, cred_handle: *mut GssCredIdT) -> OmUint32;

    /// Delete a security context, releasing all associated state.
    pub fn gss_delete_sec_context(
        minor_status: *mut OmUint32,
        context_handle: *mut GssCtxIdT,
        output_token: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Release an OID set (e.g. from `gss_acquire_cred_from` `actual_mechs` output).
    pub fn gss_release_oid_set(minor_status: *mut OmUint32, set: *mut GssOidSetT) -> OmUint32;

    /// Convert a major or minor status code to a human-readable string.
    pub fn gss_display_status(
        minor_status: *mut OmUint32,
        status_value: OmUint32,
        status_type: i32,
        mech_type: *const GssOidDesc,
        message_context: *mut OmUint32,
        status_string: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Return information about an existing credential: the associated name, remaining
    /// lifetime, usage flags, and supported mechanisms.  Pass `ptr::null_mut()` for
    /// outputs you do not need.
    pub fn gss_inquire_cred(
        minor_status: *mut OmUint32,
        cred_handle: GssCredIdT,
        name: *mut GssNameT,
        lifetime: *mut OmUint32,
        cred_usage: *mut i32,
        mechanisms: *mut GssOidSetT,
    ) -> OmUint32;

    /// Acquire an initiator credential that impersonates `desired_name` (S4U2Self).
    ///
    /// `impersonator_cred_handle` must be an initiator (`GSS_C_INITIATE` or
    /// `GSS_C_BOTH`) credential for the HTTP service.  MIT Kerberos uses it to
    /// obtain a Kerberos TGT (via the keytab it refers to) and then issues a
    /// service-for-user (S4U2Self) ticket.  The returned credential can be used
    /// with `gss_init_sec_context` to request service tickets on behalf of the
    /// user (S4U2Proxy), subject to the KDC's constrained-delegation policy.
    pub fn gss_acquire_cred_impersonate_name(
        minor_status: *mut OmUint32,
        impersonator_cred_handle: GssCredIdT,
        desired_name: GssNameT,
        time_req: OmUint32,
        desired_mechs: GssOidSetT,
        cred_usage: i32,
        output_cred_handle: *mut GssCredIdT,
        actual_mechs: *mut GssOidSetT,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    /// Store a credential into a named credential store (RFC 7512 extension).
    ///
    /// Pass `{"ccache", "MEMORY:name"}` in `elements` to write into a named
    /// in-process credential cache.  Combined with `gss_krb5_ccache_name`,
    /// this lets a blocking thread use a specific credential for SASL GSSAPI
    /// without mutating the process-wide default ccache.
    pub fn gss_store_cred_into(
        minor_status: *mut OmUint32,
        input_cred_handle: GssCredIdT,
        cred_usage: i32,
        desired_mech: *const GssOidDesc,
        overwrite_cred: OmUint32,
        default_cred: OmUint32,
        elements: *const GssKeyValueSetDesc,
        elements_stored: *mut GssOidSetT,
        cred_usage_stored: *mut i32,
    ) -> OmUint32;

    /// Set the thread-local default Kerberos credential cache for GSSAPI calls.
    ///
    /// MIT Kerberos extension (from `<gssapi/gssapi_krb5.h>`).  When `name` is
    /// non-null, the GSSAPI library uses the named ccache (e.g. `"MEMORY:foo"`)
    /// for `gss_acquire_cred` on the calling thread instead of the process-wide
    /// default.  The previous ccache name is written to `*old_name` if non-null;
    /// call this function again with the old name to restore the prior state.
    pub fn gss_krb5_ccache_name(
        minor_status: *mut OmUint32,
        name: *const c_char,
        old_name: *mut *const c_char,
    ) -> OmUint32;

    /// Initiate a security context (client side); produces the outbound SPNEGO token.
    pub fn gss_init_sec_context(
        minor_status: *mut OmUint32,
        initiator_cred_handle: GssCredIdT,
        context_handle: *mut GssCtxIdT,
        target_name: GssNameT,
        mech_type: *const GssOidDesc,
        req_flags: OmUint32,
        time_req: OmUint32,
        input_chan_bindings: *const GssChannelBindingsStruct,
        input_token: *const GssBufferDesc,
        actual_mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
}
