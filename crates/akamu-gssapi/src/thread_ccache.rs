//! Thread-local Kerberos credential cache management (MIT Kerberos).

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::GssError;
use crate::ffi;
use crate::status::format_gss_status;

/// Set the thread-local Kerberos credential cache for GSSAPI calls (MIT Kerberos).
///
/// Returns the previous ccache name so it can be restored.  Pass `None` to
/// reset to the process-wide default.  This function is safe to call
/// concurrently from multiple threads: MIT Kerberos stores the name in a
/// `pthread_key_t`, so each thread has its own value.
///
/// Typically called from a `tokio::task::spawn_blocking` closure immediately
/// before an LDAP SASL GSSAPI bind, and again after the bind to restore the
/// old name.
pub fn set_thread_ccache(name: Option<&str>) -> Result<Option<String>, GssError> {
    let name_cstr = name
        .map(CString::new)
        .transpose()
        .map_err(|_| GssError::NulInKeytabPath)?;
    let name_ptr: *const libc::c_char = name_cstr
        .as_deref()
        .map(CStr::as_ptr)
        .unwrap_or(ptr::null());

    let mut minor: ffi::OmUint32 = 0;
    let mut old_name: *const libc::c_char = ptr::null();

    // SAFETY: name_ptr is null or points to a live CString; old_name is a
    // valid output pointer.  gss_krb5_ccache_name writes a pointer to a
    // thread-local string into *old_name; it remains valid until the next call
    // to gss_krb5_ccache_name on this thread.
    let major = unsafe { ffi::gss_krb5_ccache_name(&raw mut minor, name_ptr, &raw mut old_name) };

    if major != ffi::GSS_S_COMPLETE {
        return Err(GssError::SetCcache {
            detail: format_gss_status(major, minor),
            major,
            minor,
        });
    }

    let old = if old_name.is_null() {
        None
    } else {
        // SAFETY: old_name is a non-null pointer to a NUL-terminated thread-local
        // string maintained by the MIT Kerberos library.
        Some(
            unsafe { CStr::from_ptr(old_name) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    Ok(old)
}

/// Generate a unique `MEMORY:` credential cache name for the calling thread.
///
/// Each blocking thread gets its own stable name, so repeated impersonation
/// calls on the same thread overwrite the same MEMORY: ccache rather than
/// creating new ones.
pub fn thread_ccache_name() -> String {
    thread_local! {
        static NAME: std::cell::OnceCell<String> = const { std::cell::OnceCell::new() };
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    NAME.with(|c| {
        c.get_or_init(|| {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            format!("MEMORY:akamu-thread-{n}")
        })
        .clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_ccache_name_starts_with_memory_prefix() {
        let name = thread_ccache_name();
        assert!(
            name.starts_with("MEMORY:akamu-thread-"),
            "unexpected name: {name}"
        );
    }

    #[test]
    fn thread_ccache_name_is_stable_within_same_thread() {
        let a = thread_ccache_name();
        let b = thread_ccache_name();
        assert_eq!(a, b, "name must be stable per thread");
    }

    #[test]
    fn thread_ccache_name_differs_across_threads() {
        let name_main = thread_ccache_name();
        let name_other = std::thread::spawn(thread_ccache_name).join().unwrap();
        assert_ne!(
            name_main, name_other,
            "different threads must get different names"
        );
    }

    #[test]
    fn thread_ccache_name_contains_monotonic_counter() {
        let n1: u64 = thread_ccache_name()
            .rsplit('-')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let n2: u64 = std::thread::spawn(thread_ccache_name)
            .join()
            .unwrap()
            .rsplit('-')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(n2 > n1 || n1 > n2, "counter values must differ: {n1}, {n2}");
    }
}
