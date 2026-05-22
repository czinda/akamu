AKAMU(8) "akamu" "System Administration"

# NAME

akamu - ACME certificate authority server with MTC transparency support

# SYNOPSIS

*akamu* [_config-file_]

# DESCRIPTION

*akamu* is an ACME (RFC 8555) certificate authority server.  It issues
X.509 certificates in response to automated certificate management
requests from ACME clients such as *certbot*, *acme.sh*, *akamu-cli*,
and any other RFC 8555-compliant client.

Key features:

- Supports *http-01*, *dns-01*, *dns-persist-01*, and *tls-alpn-01*
  challenges.
- Issues STAR certificates (RFC 8739) for short-lived auto-renewing
  certificates.
- Supports *Merkle Tree Certificates* (MTC) for post-quantum transparency
  logging alongside traditional X.509 issuance.
- Optional DNS-over-TLS (RFC 7858) for challenge validation queries.
- DNSSEC validation for *dns-01*, *dns-persist-01*, and CAA lookups.
- External Account Binding (EAB, RFC 8555 §7.3.4) with optional
  HKDF-SHA-256 self-service key derivation.
- Administration REST API secured by mTLS and/or GSSAPI/Kerberos.
- Audit trail (FAU_GEN.1) with operator role-based access control.
- Multiple CA instances (*multi-CA*) with per-CA ACME directory
  endpoints, per-CA CRL/OCSP, cross-signing, and CA-scoped operator
  roles.

Configuration is supplied via a TOML file.  An annotated example is
installed at */etc/akamu/config.toml.example*.

# ARGUMENTS

_config-file_
	Path to the TOML configuration file.  Defaults to *config.toml*
	in the current working directory.  When running under systemd the
	unit file passes */etc/akamu/config.toml*.

# ENVIRONMENT

*RUST_LOG*
	Log filter directive.  Uses the *tracing-subscriber* format
	(e.g. *info*, *akamu=debug*, *akamu::routes=trace*).
	Default: *info*.

# FILES

*/etc/akamu/config.toml*
	Main configuration file read by the systemd unit.

*/etc/akamu/config.toml.example*
	Annotated example configuration file.

*/etc/akamu/certs/ca.key.pem*
	Auto-generated CA private key (mode 0640, owner akamu:akamu).

*/etc/akamu/certs/ca.cert.pem*
	Auto-generated CA certificate.

*/var/lib/akamu/acme.db*
	Default SQLite database file (SQLite backend only).  When PostgreSQL
	or MariaDB is configured, no local database file is created; the path
	is unused.

*/var/lib/akamu/mtc.log*
	Merkle Tree Certificate transparency log (when MTC is enabled).

# SIGNALS

*SIGTERM*, *SIGINT*
	Graceful shutdown.  In-flight requests are allowed to complete
	before the process exits.

# EXIT STATUS

*0*	Server shut down cleanly.

*1*	Fatal startup error (configuration parse failure, missing key
	file, database error, etc.).  Details are written to the log.

# EXAMPLES

Start the server with a non-default configuration file:

	akamu /etc/akamu/staging.toml

Minimal single-CA configuration with SQLite and no TLS (behind a reverse
proxy):

```
listen_addr = "unix:/run/akamu/akamu.sock"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/acme.db"

[ca]
key_file  = "/etc/akamu/certs/ca.key.pem"
cert_file = "/etc/akamu/certs/ca.cert.pem"
key_type  = "ec:P-256"
common_name  = "Example ACME CA"
organization = "Example Org"

[server]
external_account_required = false
validate_dnssec = true
```

Multi-CA configuration with a default CA and a secondary CA for STAR
certificates:

```
listen_addr = "0.0.0.0:8443"
base_url    = "https://acme.example.com"

[database]
url = "postgres://akamu:pass@db.example.com/akamu"
require_tls = true

[[ca]]
id          = "main"
is_default  = true
key_file    = "/etc/akamu/certs/main-ca.key.pem"
cert_file   = "/etc/akamu/certs/main-ca.cert.pem"
key_type    = "ec:P-384"
common_name = "Example CA"

[[ca]]
id          = "star"
is_default  = false
key_file    = "/etc/akamu/certs/star-ca.key.pem"
cert_file   = "/etc/akamu/certs/star-ca.cert.pem"
key_type    = "ec:P-256"
common_name = "Example STAR CA"
```

# CONFIGURATION FILE

The configuration file is a TOML document.  See *akamu.conf*(5) for the
complete reference.  An annotated example is installed at
*/etc/akamu/config.toml.example*.

# SEE ALSO

*akamu-cosigner*(8), *akamuctl*(1), *akamu-cli*(1),
*akamu.conf*(5), *systemd*(1), *systemd.service*(5)

RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile++
RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)++
RFC 6960 - X.509 Internet PKI Online Certificate Status Protocol (OCSP)++
RFC 7858 - Specification for DNS over Transport Layer Security (TLS)++
RFC 8555 - Automatic Certificate Management Environment (ACME)++
RFC 8657 - CAA Record Extensions for Account URI and ACME Method Binding++
RFC 8659 - DNS Certification Authority Authorization (CAA) Resource Record++
RFC 8737 - ACME TLS-ALPN-01 Challenge Extension++
RFC 8738 - ACME IP Identifier Validation Extension++
RFC 8739 - Support for Short-Term, Automatically Renewed (STAR) Certificates++
RFC 8823 - Extensions for the Use of ACME for Email Challenge Validation++
RFC 9115 - An ACME Profile for Generating Delegated Certificates++
RFC 9162 - Certificate Transparency Version 2.0++
RFC 9444 - Automated Certificate Management Environment (ACME) for Subdomains++
RFC 9773 - ACME Renewal Information (ARI)++
RFC 9799 - ACME Extensions for .onion Special-Use Domain Names++
draft-ietf-acme-dns-persist - Persistent DNS-01 Challenge for ACME++
RFC 9964 - ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)++
draft-ietf-plants-merkle-tree-certs - Merkle Tree Certificates for TLS++
draft-ietf-lamps-pq-composite-sigs - Composite ML-DSA for use in Internet PKI++
draft-ietf-acme-profiles-01 - ACME Certificate Profiles

# AUTHORS

The akamu project contributors.
