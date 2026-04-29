fn main() {
    // OpenLDAP client library and its BER encoding companion.
    println!("cargo:rustc-link-lib=ldap");
    println!("cargo:rustc-link-lib=lber");
    // SASL library — required by OpenLDAP for SASL mechanism dispatch (GSSAPI, EXTERNAL, …).
    println!("cargo:rustc-link-lib=sasl2");
    // MIT Kerberos GSSAPI implementation — required for SASL GSSAPI binds.
    println!("cargo:rustc-link-lib=gssapi_krb5");
}
