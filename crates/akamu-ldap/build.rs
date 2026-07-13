fn main() {
    // Probe for OpenLDAP via pkg-config.  Fall back to bare -l flags for
    // systems where OpenLDAP is in a standard system path or Homebrew keg.
    if pkg_config::probe_library("ldap").is_err() {
        if let Some(prefix) = homebrew_prefix("openldap") {
            println!("cargo:rustc-link-search=native={prefix}/lib");
        }
        println!("cargo:rustc-link-lib=ldap");
        println!("cargo:rustc-link-lib=lber");
    }

    // SASL library — required by OpenLDAP for SASL mechanism dispatch.
    if pkg_config::probe_library("libsasl2").is_err() {
        println!("cargo:rustc-link-lib=sasl2");
    }

    // MIT Kerberos GSSAPI — required for SASL GSSAPI binds.
    if pkg_config::probe_library("krb5-gssapi")
        .or_else(|_| pkg_config::probe_library("mit-krb5-gssapi"))
        .is_err()
    {
        if let Some(prefix) = homebrew_prefix("krb5") {
            println!("cargo:rustc-link-search=native={prefix}/lib");
        }
        println!("cargo:rustc-link-lib=gssapi_krb5");
    }
}

fn homebrew_prefix(formula: &str) -> Option<String> {
    std::process::Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
}
