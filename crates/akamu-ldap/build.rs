fn main() {
    // Use pkg-config when available (Linux packages, Homebrew on macOS) so the
    // linker gets the correct -L search path alongside -l flags.  Fall back to
    // bare -l flags for systems where OpenLDAP is installed in a standard
    // system path (e.g. /usr/lib on some Linux distributions).
    let ldap_found = pkg_config("ldap");
    if !ldap_found {
        println!("cargo:rustc-link-lib=ldap");
        println!("cargo:rustc-link-lib=lber");
    }

    // SASL library — required by OpenLDAP for SASL mechanism dispatch.
    if !pkg_config("libsasl2") {
        println!("cargo:rustc-link-lib=sasl2");
    }

    // MIT Kerberos GSSAPI — required for SASL GSSAPI binds.
    println!("cargo:rustc-link-lib=gssapi_krb5");
}

/// Run `pkg-config --libs <lib>` and emit the resulting -L and -l flags.
/// Returns true if pkg-config succeeded, false otherwise.
fn pkg_config(lib: &str) -> bool {
    let output = std::process::Command::new("pkg-config")
        .args(["--libs", lib])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };

    let flags = String::from_utf8_lossy(&output.stdout);
    for flag in flags.split_whitespace() {
        if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(name) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={name}");
        }
    }
    true
}
