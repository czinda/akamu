fn main() {
    // Probe for the MIT Kerberos GSSAPI library via pkg-config first.
    // The canonical Fedora pkg-config name is "krb5-gssapi"; Debian/Ubuntu use "mit-krb5-gssapi".
    // Fall back to a hardcoded link directive if pkg-config is unavailable (e.g. cross-compile).
    if pkg_config::probe_library("krb5-gssapi")
        .or_else(|_| pkg_config::probe_library("mit-krb5-gssapi"))
        .is_err()
    {
        println!("cargo:rustc-link-lib=gssapi_krb5");
    }
}
