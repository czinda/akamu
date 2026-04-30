fn main() {
    // MIT Kerberos GSSAPI — provides gss_accept_sec_context, gss_acquire_cred_from, etc.
    println!("cargo:rustc-link-lib=gssapi_krb5");
}
