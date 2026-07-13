fn main() {
    // Declare the cfg flag so rustc knows it is intentional (suppresses
    // the `unexpected_cfg` lint when compiling the crate).
    println!("cargo::rustc-check-cfg=cfg(mit_kerberos)");

    // Probe for the MIT Kerberos GSSAPI library via pkg-config first.
    // The canonical Fedora pkg-config name is "krb5-gssapi"; Debian/Ubuntu use "mit-krb5-gssapi".
    // Fall back to a hardcoded link directive if pkg-config is unavailable (e.g. cross-compile).
    if pkg_config::probe_library("krb5-gssapi")
        .or_else(|_| pkg_config::probe_library("mit-krb5-gssapi"))
        .is_err()
    {
        // Homebrew keg-only: libraries are not symlinked into /opt/homebrew/lib.
        if let Some(prefix) = homebrew_prefix("krb5") {
            println!("cargo:rustc-link-search=native={prefix}/lib");
        }
        println!("cargo:rustc-link-lib=gssapi_krb5");
    }
    // All three paths above resolve to MIT Kerberos; emit the cfg so that the
    // unsafe Sync impl (only sound with MIT Kerberos) is conditionally compiled.
    println!("cargo:rustc-cfg=mit_kerberos");
}

fn homebrew_prefix(formula: &str) -> Option<String> {
    std::process::Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
}
