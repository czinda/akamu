//! GSSAPI status code formatting helpers.

use std::ptr;

use crate::ffi;

/// Convert a single GSSAPI status code to a human-readable string.
///
/// `status_type` must be `GSS_C_GSS_CODE` (1) for a major code or
/// `GSS_C_MECH_CODE` (2) for a mechanism-specific minor code.
/// Returns `None` if `gss_display_status` itself fails.
pub(crate) fn display_one_status(status_value: ffi::OmUint32, status_type: i32) -> Option<String> {
    let mut minor: ffi::OmUint32 = 0;
    let mut msg_ctx: ffi::OmUint32 = 0;
    let mut buf = ffi::gss_c_no_buffer();

    // SAFETY: minor, msg_ctx, and buf are valid stack variables; mech_type is
    // null (use default mechanism); gss_display_status only reads status_value.
    let major = unsafe {
        ffi::gss_display_status(
            &raw mut minor,
            status_value,
            status_type,
            ptr::null(),
            &raw mut msg_ctx,
            &raw mut buf,
        )
    };
    if major != ffi::GSS_S_COMPLETE || buf.length == 0 || buf.value.is_null() {
        return None;
    }
    // SAFETY: buf was populated by gss_display_status and is buf.length bytes.
    let s = unsafe { std::slice::from_raw_parts(buf.value as *const u8, buf.length) };
    let text = String::from_utf8_lossy(s).into_owned();
    unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut buf) };
    Some(text)
}

/// Format a GSSAPI major+minor status pair as a human-readable string.
///
/// Example output: `"An invalid status code was supplied (major 0x000d0000);
/// Ticket expired (minor 0x96c73a20)"`.
#[must_use]
pub fn format_gss_status(major: ffi::OmUint32, minor: ffi::OmUint32) -> String {
    let maj_text =
        display_one_status(major, ffi::GSS_C_GSS_CODE).unwrap_or_else(|| "unknown".into());
    let min_text =
        display_one_status(minor, ffi::GSS_C_MECH_CODE).unwrap_or_else(|| "unknown".into());
    format!("{maj_text} (major {major:#010x}); {min_text} (minor {minor:#010x})")
}
