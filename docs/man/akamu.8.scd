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
	Default SQLite database (SQLite backend only).

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

# SEE ALSO

*akamu-cosigner*(8), *akamuctl*(1), *akamu-cli*(1),
*systemd*(1), *systemd.service*(5)

RFC 8555 — Automatic Certificate Management Environment (ACME)++
RFC 8739 — Support for Short-Term, Automatically Renewed (STAR) Certificates++
RFC 9773 — ACME Renewal Information (ARI)

# AUTHORS

The akamu project contributors.
