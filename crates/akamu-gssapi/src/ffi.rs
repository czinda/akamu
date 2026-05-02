//! Raw FFI bindings to libgssapi_krb5.
//!
//! Only the subset needed for server-side SPNEGO acceptance is declared here.
//! All pointer types use opaque enum structs to prevent accidental dereferencing.

use libc::{c_char, c_void};
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
    pub length: usize,
    pub value: *mut c_void,
}

/// OID descriptor: a DER-encoded object identifier.
#[repr(C)]
pub struct GssOidDesc {
    pub length: u32,
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

pub const GSS_C_ACCEPT: i32 = 2;

/// Flag bit: context provides per-message replay detection (RFC 2743 §1.2.3).
pub const GSS_C_REPLAY_FLAG: OmUint32 = 4;

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

/// Request flag: ask the acceptor to perform mutual authentication.
pub const GSS_C_MUTUAL_FLAG: OmUint32 = 2;

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

    /// Release an OID set (e.g. from gss_acquire_cred_from actual_mechs output).
    pub fn gss_release_oid_set(minor_status: *mut OmUint32, set: *mut GssOidSetT) -> OmUint32;

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
