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

# CONFIGURATION FILE

The configuration file is a TOML document.  An annotated example is
installed at */etc/akamu/config.toml.example*.

## [database] — new keys

*require_tls* = _bool_
	When *true*, the server refuses to start unless the database URL
	explicitly enables SSL/TLS (FPT_ITT.1).  PostgreSQL requires
	_sslmode=require_ (or stronger); MariaDB/MySQL requires
	_ssl-mode=REQUIRED_ (or stronger).  Ignored for SQLite.
	Default: *false*.

## [ca] — encrypted key enforcement

*require_encrypted_key* = _bool_
	When *true*, plaintext PEM private keys are rejected at startup
	(FCS_STG_EXT.1).  Only PKCS#8 encrypted PEM
	(*ENCRYPTED PRIVATE KEY*) or PKCS#11 URIs are accepted.
	Set *key_password_file* to supply the decryption passphrase.
	Default: *false*.

*key_password_file* = _path_
	Path to a file containing the passphrase for the encrypted PEM CA
	private key.  The file is read once at startup; trailing newlines are
	stripped.  Required when *require_encrypted_key* is *true* and
	*key_file* is a filesystem path (not a PKCS#11 URI).

## [admin] — session locking and operator lockout

*session_lock_secs* = _seconds_
	Inactivity threshold before a session is locked (FTA_SSL_EXT.1).
	After this many idle seconds, the session token returns *423 Locked*
	rather than *401 Unauthorized*.  The operator must re-authenticate
	to obtain a new token.  Must be less than *session_ttl_secs*.
	Default: *900* (15 min).

*max_failed_auth* = _count_
	Maximum failed authentication attempts per operator before lockout
	(FIA_AFL.1).  Once exceeded, further attempts return *423 Locked*
	until the lockout expires or an administrator unlocks the operator.
	Default: *5*.

*lockout_duration_secs* = _seconds_
	How long the operator account remains locked after exceeding
	*max_failed_auth* (FIA_AFL.1).  Default: *1800* (30 min).

## [admin] — bootstrap operator fields

*bootstrap_operator_cert_file* = _path_
	Path where the bootstrap Administrator client certificate is written on
	first run.  When this file and *bootstrap_operator_key_file* are absent
	and the operators table is empty, a client certificate is generated and
	the operator is registered automatically.  Both fields must be set
	together.  Mutually exclusive with *bootstrap_operator_gssapi_principal*.

*bootstrap_operator_key_file* = _path_
	Path where the bootstrap Administrator client private key is written on
	first run.  Must be set alongside *bootstrap_operator_cert_file*.
	Mutually exclusive with *bootstrap_operator_gssapi_principal*.

*bootstrap_operator_gssapi_principal* = _principal_
	Kerberos principal for the GSSAPI bootstrap Administrator operator
	(e.g. _admin@EXAMPLE.COM_).  When set and the operators table is empty
	at startup, the principal is registered as Administrator so the first
	*akamuctl login --gssapi* succeeds without manual operator registration.
	Mutually exclusive with *bootstrap_operator_cert_file* /
	*bootstrap_operator_key_file*.

# SEE ALSO

*akamu-cosigner*(8), *akamuctl*(1), *akamu-cli*(1),
*systemd*(1), *systemd.service*(5)

RFC 8555 — Automatic Certificate Management Environment (ACME)++
RFC 8739 — Support for Short-Term, Automatically Renewed (STAR) Certificates++
RFC 9773 — ACME Renewal Information (ARI)

# AUTHORS

The akamu project contributors.
