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

# CONFIGURATION FILE

The configuration file is a TOML document.  An annotated example is
installed at */etc/akamu/config.toml.example*.

## [database]

The server supports three database backends selected by the *url* key:

| Backend    | URL prefix                          |
|------------|-------------------------------------|
| SQLite     | *sqlite://path* or *sqlite::memory:* |
| PostgreSQL | *postgres://user:pass@host/db*       |
| MariaDB    | *mariadb://user:pass@host/db*        |

PostgreSQL is a fully supported production backend.  State-transition
write transactions (*new-order*, *new-authz*, challenge validation) issue
*SET LOCAL synchronous_commit = off* automatically, reducing per-commit
WAL flush overhead by ~1–4 ms on SSD.  The certificate issuance
transaction retains full durability.

*require_tls* = _bool_
	When *true*, the server refuses to start unless the database URL
	explicitly enables SSL/TLS (FPT_ITT.1).  PostgreSQL requires
	_sslmode=require_ (or stronger); MariaDB/MySQL requires
	_ssl-mode=REQUIRED_ (or stronger).  Ignored for SQLite.
	Default: *false*.

## [[ca]] / [ca] — CA configuration

The server supports one or more CA instances.  Use *[[ca]]* (array-of-tables)
to define multiple CAs; the legacy single *[ca]* table remains accepted and
receives *id="default"* and *is_default=true* automatically.

*id* = _string_
	Unique identifier for this CA.  Must be lowercase alphanumeric, *_*,
	or *-*, at most 64 characters.  Reserved ACME path segments
	(*directory*, *new-nonce*, *new-account*, *new-order*, etc.) are
	rejected.  Required when multiple *[[ca]]* entries are configured.

*is_default* = _bool_
	When multiple *[[ca]]* entries are configured, exactly one must have
	*is_default = true*.  The default CA is served at the backward-
	compatible */acme/directory* alias.  Default: *false* (except when
	using the legacy single *[ca]* table, where it is implicit).

*caa_identities* = _[string, ...]_
	Per-CA CAA identity list.  When non-empty, overrides
	*[server].caa_identities* for orders processed through this CA's
	ACME endpoint.  When empty (the default), falls back to
	*[server].caa_identities*.  Default: *[]* (inherit from server).

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

## URL structure

When multiple CAs are configured, the server exposes per-CA ACME and
revocation endpoints alongside backward-compatible aliases:

	*/acme/{ca_id}/directory*, */acme/directory*
		Per-CA ACME directory (and default-CA alias).

	*/acme/{ca_id}/new-nonce*, */acme/{ca_id}/new-account*, ...
		All standard ACME endpoints are available under each CA prefix.

	*/ca/{ca_id}/crl*, */ca/crl*
		Per-CA CRL endpoint (and default-CA alias).

	*/ca/{ca_id}/ocsp*, */ca/ocsp*
		Per-CA OCSP responder (and default-CA alias).

	*/ca/{ca_id}/cross-certs*
		Public list of cross-certificates where *{ca_id}* is the subject.

## [server] — account_scope

*account_scope* = _string_
	Controls whether ACME accounts are shared across CAs or isolated
	per CA.  Accepted values:

	*"server"* (default)
		One account works with all configured CAs.  This matches the
		behavior of single-CA deployments and is the default.

	*"ca"*
		Accounts are isolated per CA.  An account registered via one
		CA's *new-account* endpoint cannot create orders via another CA.

## Builtin profile — ca_ids restriction

*ca_ids* = _[string, ...]_
	List of CA IDs for which this profile is available.  When set,
	ACME clients that request this profile via a CA not in the list
	receive an *invalidProfile* error at finalize time.  When empty
	(the default) the profile is available via all configured CAs.
	Config validation rejects *ca_ids* entries that do not match any
	configured CA *id*.

## Admin API — multi-CA endpoints

The admin API exposes additional endpoints for multi-CA management:

	*GET /admin/cas*
		List all configured CAs.

	*GET /admin/cas/{id}*
		Show details of a single CA including the CA certificate PEM.

	*POST /admin/ca/{id}/crl/force*
		Force immediate CRL regeneration for a specific CA.
		Requires *ca_operations* or *administrator* role.

	*POST /admin/ca/{id}/cross-sign*
		Issue a cross-certificate: CA *{id}* signs the public key of
		another CA.  Body: *{ "subject_ca_id": "other", "validity_years": 5 }*
		or *{ "subject_cert_pem": "-----...", "validity_years": 5 }*.
		Requires *administrator* or *ca_operations* role.

	*GET /admin/cross-certs*
		List stored cross-certificates.  Filters: *issuer_ca_id*,
		*subject_ca_id*, *limit*, *offset*.

	*GET /admin/cross-certs/{id}*
		Show a single cross-certificate including its PEM.

The existing *GET /admin/certs*, *GET /admin/orders*, and
*GET /admin/accounts* endpoints accept an optional *?ca_id=* query
parameter to limit results to a specific CA.

The *ca_ra* operator role now accepts a *ca_id* field (set via
*PATCH /admin/operators/{id}*).  A *ca_ra* operator with a *ca_id*
may only revoke and view certificates issued by that CA.  An unscoped
*ca_ra* (empty *ca_id*) is rejected with *403 Forbidden* at all
restricted endpoints.

# SEE ALSO

*akamu-cosigner*(8), *akamuctl*(1), *akamu-cli*(1),
*systemd*(1), *systemd.service*(5)

RFC 8555 — Automatic Certificate Management Environment (ACME)++
RFC 8739 — Support for Short-Term, Automatically Renewed (STAR) Certificates++
RFC 9773 — ACME Renewal Information (ARI)

# AUTHORS

The akamu project contributors.
