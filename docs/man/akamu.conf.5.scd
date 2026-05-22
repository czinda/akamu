AKAMU.CONF(5) "akamu" "File Formats"

# NAME

akamu.conf - configuration file for the akamu ACME server

# SYNOPSIS

*/etc/akamu/config.toml*

# DESCRIPTION

*akamu*(8) reads its configuration from a TOML file.  The default path
when running under systemd is */etc/akamu/config.toml*.  An annotated
example covering every option is installed at
*/etc/akamu/config.toml.example*.

All section headers shown below correspond directly to TOML table names.
Subsections (e.g. *[tls.client_auth]*) are nested tables.  Array-of-tables
entries (e.g. *[[ca]]*) may be repeated to define multiple instances.

# TOP-LEVEL FIELDS

*listen_addr* = _addr_
	Address the server binds to.  Two forms are accepted:

	_host:port_ (e.g. *0.0.0.0:8080*)
		TCP listener.  TLS may be enabled via *[tls]*.

	*unix:*_/path/to/socket_ (e.g. *unix:/run/akamu/akamu.sock*)
		Unix domain socket listener.  Mutually exclusive with *[tls]*;
		TLS termination must be handled by the reverse proxy.  The socket
		directory must exist with appropriate permissions.  When running
		under systemd with *akamu.socket*, the socket is inherited via
		*LISTEN_FDS* and this field selects the expected socket path for
		validation.

*base_url* = _url_
	Public base URL of the ACME server, used in all URLs returned to
	clients (e.g. directory, nonce, order, certificate, and CRL/OCSP
	links).  Must not have a trailing slash.  Example:
	*https://acme.example.com*.

# [database]

The server supports three database backends selected by the *url* key:

[[ Backend
:[ URL prefix
|  *SQLite*
:  *sqlite://path* or *sqlite::memory:*
|  *PostgreSQL*
:  *postgres://user:pass@host/db*
|  *MariaDB*
:  *mariadb://user:pass@host/db*

PostgreSQL is a fully supported production backend.  State-transition
write transactions (*new-order*, *new-authz*, challenge validation) issue
*SET LOCAL synchronous_commit = off* automatically, reducing per-commit
WAL flush overhead by ~1-4 ms on SSD.  The certificate issuance
transaction retains full durability.

*url* = _string_
	Database connection URL.  For SQLite, the file is created on first
	run.  Required.

*max_connections* = _integer_
	Maximum pooled connections.  Default: *1* for SQLite (avoids
	*SQLITE_BUSY_SNAPSHOT* deadlocks under concurrent writes), *10*
	for PostgreSQL and MariaDB.

*require_tls* = _bool_
	When *true*, the server refuses to start unless the database URL
	explicitly enables SSL/TLS (FPT_ITT.1).  PostgreSQL requires
	_sslmode=require_ (or stronger); MariaDB/MySQL requires
	_ssl-mode=REQUIRED_ (or stronger).  Ignored for SQLite.
	Default: *false*.

# [[ca]] / [ca] — CA configuration

The server supports one or more CA instances.  Use *[[ca]]* (array-of-tables)
to define multiple CAs; the legacy single *[ca]* table remains accepted and
receives *id="default"* and *is_default=true* automatically.

*id* = _string_
	Unique identifier for this CA.  Must be lowercase alphanumeric,
	underscore, or *-*, at most 64 characters.  Reserved ACME path segments
	(*directory*, *new-nonce*, *new-account*, *new-order*, etc.) are
	rejected.  Required when multiple *[[ca]]* entries are configured.

*is_default* = _bool_
	When multiple *[[ca]]* entries are configured, exactly one must have
	*is_default = true*.  The default CA is served at the backward-
	compatible */acme/directory* alias.  Default: *false* (except when
	using the legacy single *[ca]* table, where it is implicit).

*key_file* = _path_
	Path to the CA private key PEM file.  Auto-generated on first run
	if neither *key_file* nor *cert_file* exist on disk.  PKCS#11 URIs
	of the form *pkcs11:token=...;object=...;type=private* are also
	accepted for HSM-backed keys; the *pkcs11-provider* OpenSSL module
	must be loaded before the server starts.

*cert_file* = _path_
	Path to the CA certificate PEM file.  Auto-generated on first run
	alongside *key_file* when neither exists.

*key_type* = _string_
	Key algorithm for the auto-generated CA key.  Accepted values:

	- *ec:P-256*, *ec:P-384*, *ec:P-521*
	- *rsa:2048*, *rsa:3072*, *rsa:4096*
	- *ed25519*

	Has no effect when *key_file* already exists.  Default: *ec:P-256*.

*hash_alg* = _string_
	Hash algorithm used for certificate and CRL signatures.  Accepted
	values: *sha256*, *sha384*, *sha512*.  Default: *sha256*.

*validity_days* = _integer_
	Default validity of issued end-entity certificates in days.
	Individual profiles may override this.  Default: *90*.

*ca_validity_years* = _integer_
	Validity period of the CA certificate when auto-generated (years).
	Has no effect when *cert_file* already exists.  Default: *10*.

*common_name* = _string_
	Common Name (CN) for the auto-generated CA certificate distinguished
	name.  Has no effect when *cert_file* already exists.

*organization* = _string_
	Organization (O) for the auto-generated CA certificate distinguished
	name.  Has no effect when *cert_file* already exists.

*crl_url* = _url_
	URL placed in the CRL Distribution Points (CDP) X.509 extension of
	issued certificates.  Set to *{base_url}/ca/crl* (substituting the
	actual base URL) to use the built-in CRL endpoint.  Omit to suppress
	the CDP extension entirely.

*ocsp_url* = _url_
	URL placed in the Authority Information Access (AIA) OCSP extension
	of issued certificates.  Set to point to the built-in OCSP responder
	or an external OCSP service.  Omit to suppress the AIA OCSP extension.

*crl_next_update_secs* = _integer_
	nextUpdate validity window for the built-in CRL endpoint, in seconds.
	Default: *86400* (1 day).

*enforce_validity_cap* = _bool_
	When *true*, the server enforces the CA/B Forum Baseline Requirements
	§6.3.2 maximum 200-day validity cap at certificate issuance time.
	Certificates requested with a validity exceeding 200 days are
	rejected.  Public WebPKI CAs should set this to *true*.
	Default: *false*.

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

# [mtc] — Merkle Tree Certificate log

When this section is present and *enabled = true*, akamu appends issued
certificates to a Merkle Tree Certificate transparency log (MTC §5).
Checkpoints are signed by the key configured in *[mtc.signing_key]* and
optionally co-signed by external cosigners.

*log_path* = _path_
	Filesystem path for the MTC transparency log file.  The file is
	created on first run.  Multiple processes must not share the same
	log; the server acquires an exclusive *flock* on a sidecar lock file
	at *{log_path}.lock* to enforce this.
	Default: */var/lib/akamu/mtc.log*.

*enabled* = _bool_
	Set to *true* to enable MTC logging.  When *false* (the default),
	the *[mtc]* section is parsed but no log entries are written and no
	checkpoints are produced.  Default: *false*.

*checkpoint_interval_secs* = _integer_
	How often the checkpoint background task fires, in seconds.
	Default: *3600* (1 hour).

*landmark_interval_secs* = _integer_
	How often a new landmark tree size is frozen, in seconds.  A
	landmark records a stable tree size that cosigners and auditors
	can reference.  Default: *86400* (1 day).

*max_active_landmarks* = _integer_
	Maximum number of active (non-expired) landmarks to retain in the
	database.  Older landmarks beyond this count are pruned.
	Default: *100*.

*checkpoint_retention_count* = _integer_
	Maximum number of checkpoints to retain in the database.  Older
	checkpoints beyond this count are pruned.  Default: *1000*.

## [mtc.signing_key]

Signing key configuration for MTC checkpoint production.  When this
subsection is absent, checkpoints are disabled even if *enabled = true*.
The MTC signing key must be distinct from the X.509 CA key (MTC §5.5).

*key_file* = _path_
	Path to the MTC signing key PEM file.  Auto-generated if the file
	does not exist.

*key_type* = _string_
	Key algorithm for auto-generation.  Same accepted values as
	*[[ca]].key_type*.  Default: *ec:P-256*.

*hash_alg* = _string_
	Hash algorithm for checkpoint signatures.  Accepted values:
	*sha256*, *sha384*, *sha512*.  Default: *sha256*.

## [[mtc.cosigners]]

Repeat this block for each external cosigner.  Akāmu POSTs the
DER-encoded Checkpoint to the cosigner URL and expects a DER
SubtreeSignature in return.

*url* = _url_
	HTTP(S) endpoint of the cosigner signing service.  Required.

*cosigner_id_cert_pem* = _path_
	Optional path to the cosigner identity certificate PEM.  When
	present, the returned SubtreeSignature is verified against this
	certificate before being included in the checkpoint.

# [server] — ACME server behaviour

*terms_of_service_url* = _url_
	Optional Terms of Service URL advertised in the *meta* field of
	*/acme/directory*.  When absent, no *termsOfService* field is
	included.

*website_url* = _url_
	Optional website URL advertised in the *meta* field of
	*/acme/directory*.  When absent, no *website* field is included.

*caa_identities* = _[string, ...]_
	List of CAA identity strings checked against CAA DNS records for
	all orders.  Per-CA *caa_identities* overrides this value for that
	CA.  Example: *["acme.example.com"]*.

*external_account_required* = _bool_
	When *true*, new ACME account registrations must include a valid
	External Account Binding (EAB) MAC.  Existing accounts are
	unaffected.  Default: *false*.

*account_scope* = _string_
	Controls whether ACME accounts are shared across CAs or isolated
	per CA.  Accepted values:

	*"server"* (default)
		One account works with all configured CAs.  This matches the
		behavior of single-CA deployments and is the default.

	*"ca"*
		Accounts are isolated per CA.  An account registered via one
		CA's *new-account* endpoint cannot create orders via another CA.

*order_expiry_secs* = _integer_
	Order expiry time in seconds.  Orders not finalized within this
	window expire and must be recreated.  Default: *86400* (1 day).

*authz_expiry_secs* = _integer_
	Authorization expiry time in seconds.  Pending authorizations not
	completed within this window are invalidated.
	Default: *86400* (1 day).

*max_body_bytes* = _integer_
	Maximum JOSE+JSON request body size in bytes.  Requests with a
	larger body are rejected with HTTP 413.  Default: *65536*.

*http_validation_port* = _integer_
	TCP port used when fetching *http-01* challenge responses from
	clients.  RFC 8555 §8.3 requires port *80* in production.  Override
	only for testing environments.  Default: *80*.

*http_validation_allow_private_ips* = _bool_
	When *true*, *http-01* redirect targets that resolve to private or
	loopback IP addresses are followed.  Default: *false*.  Enable only
	in isolated test environments; following redirects to private
	addresses is an SSRF risk in production.

*dns_persist_issuer_domains* = _string_ or _[string, ...]_
	Issuer domain(s) placed in *dns-persist-01* issuer-domain-names and
	matched against TXT records.  Accepts a single string or an array of
	strings.  Defaults to the host portion of *base_url* when absent.

*dns_resolver_addr* = _addr_
	DNS resolver address for challenge validation (*dns-01*,
	*dns-persist-01*, and CAA lookups).  Format: *ip:port*.  Defaults
	to the system resolver from */etc/resolv.conf*.  Useful for
	split-horizon DNS or isolated test environments.

*dns_persist01_resolver_addr* = _addr_
	Separate DNS resolver address used only for *dns-persist-01*
	validation.  Falls back to *dns_resolver_addr* when absent.

*dns_dot_server_name* = _hostname_
	DNS-over-TLS (DoT, RFC 7858) TLS SNI hostname of the resolver.
	When set, all DNS challenge queries are sent over TLS on port 853.
	*dns_resolver_addr* must point to the DoT server (e.g.
	*1.1.1.1:853*) when this option is used.

*validate_dnssec* = _bool_
	Enable DNSSEC validation for *dns-01*, *dns-persist-01*, and CAA
	lookups.  Required by CA/B Forum BR §3.2.2.4 since 2026-03-15.
	Set to *false* only for testing or in DNSSEC-unsigned environments.
	Default: *true*.

*ari_retry_after_secs* = _integer_
	Retry-After interval in seconds included in
	*GET /acme/renewal-info* responses (RFC 9773 §4.3).
	Default: *21600* (6 hours).

*ari_explanation_url* = _url_
	URL included in *GET /acme/renewal-info* responses as
	*explanationURL* (RFC 9773 §4.1).  When absent, no *explanationURL*
	field is included.

*allow_subdomain_auth* = _bool_
	When *true*, advertises RFC 9444 subdomain authorization support in
	the directory meta.  Default: *false*.

*star_min_lifetime_secs* = _integer_
	Minimum lifetime of a STAR certificate in seconds (RFC 8739).
	STAR orders with a requested lifetime shorter than this value are
	rejected.  Default: *86400* (1 day).

*star_max_duration_secs* = _integer_
	Maximum duration of a STAR order in seconds (RFC 8739).  Orders
	requesting renewal beyond this total duration are rejected.
	Default: *31536000* (1 year).

*star_allow_certificate_get* = _bool_
	When *true*, unauthenticated HTTP GET requests to the STAR
	certificate URL are permitted.  Default: *true*.

*tor_connectivity_enabled* = _bool_
	When *true*, enables validation of *.onion* identifiers (RFC 9799
	§4).  Requires that the server can reach the Tor network outbound.
	Default: *false*.

*trusted_proxies* = _[cidr, ...]_
	CIDR blocks trusted to supply the *X-Remote-User* header (set by a
	Kerberos/SPNEGO reverse proxy).  Requests from source IPs not in
	this list never have *X-Remote-User* honoured.  Example:
	*["127.0.0.1/32", "::1/128"]*.

*eab_master_secret* = _string_
	Base64url-encoded master secret for HKDF-SHA-256 EAB key derivation
	(RFC 5869).  Must be at least 32 bytes when decoded.  When set, ACME
	clients can derive their own EAB HMAC keys without administrator
	provisioning.  Generate with:

	```
	openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
	```

## [server.eab_keys]

Static EAB pre-shared keys seeded into the database at startup
(RFC 8555 §7.3.4).  Each entry maps a key identifier string to a
base64url-encoded HMAC key.  Keys are inserted with *INSERT OR IGNORE*;
runtime-provisioned keys are never overwritten by this section.

Example:

```
[server.eab_keys]
"my-kid" = "base64url-encoded-hmac-key"
```

## [server.gssapi]

Standalone GSSAPI/SPNEGO authentication for the ACME server (as an
alternative to a Kerberos reverse proxy).  When this subsection is
present, akamu handles *Authorization: Negotiate* directly.

*keytab_file* = _path_
	Path to the HTTP service keytab file.  The akamu process must have
	read access.  Required when using standalone GSSAPI.

*service_name* = _string_
	Kerberos service name.  MIT Kerberos appends *@*_hostname_
	automatically.  Default: *HTTP*.

# [email_challenge] — RFC 8823 S/MIME email validation

When this section is absent or *enabled = false*, the *email-reply-00*
challenge type is not advertised and orders for email identifiers are
rejected.

The email validation flow works as follows: when an ACME client requests
an authorization for an email identifier, the server invokes *send_script*
to deliver a challenge email containing *token-part2* to the identifier
address.  The recipient replies to the email or submits *token-part2*
via the webhook endpoint.  The server then validates the submission and
marks the authorization as complete.

*enabled* = _bool_
	Set to *true* to enable the *email-reply-00* challenge type.
	Default: *false*.

*from_address* = _address_
	Envelope From address used in challenge emails.  Must be a valid
	RFC 5321 address that recipients can reply to.  Required when
	*enabled = true*.

*send_script* = _path_
	Absolute path to an executable that delivers the challenge email.
	The server invokes it with a cleared environment (*env_clear()*),
	injecting only the following variables:

	*ACME_TO*
		Recipient address (the identifier being validated).

	*ACME_FROM*
		Value of *from_address*.

	*ACME_SUBJECT*
		Email subject line: *ACME: <token-part1-base64url>*.

	*ACME_MESSAGE_ID*
		RFC 5322 Message-ID in angle-bracket form.

	*ACME_AUTO_SUBMITTED*
		Value *auto-generated; type=acme*.  Set this as a header.

	*ACME_TOKEN_PART2*
		Base64url token-part2.  Include verbatim in the message body.

	Exit code *0* signals success.  Any other exit code marks the
	challenge delivery as failed and the challenge is set to invalid.

*send_script_timeout_secs* = _integer_
	Timeout for the *send_script* invocation in seconds.  Minimum: *1*.
	Default: *30*.

*webhook_hmac_secret* = _string_
	HMAC-SHA256 secret authenticating inbound webhook requests.  The
	webhook caller must supply *X-Akamu-Signature: sha256=*_hex_ where
	_hex_ is the HMAC-SHA256 of the raw request body computed with this
	secret.  Must be at least 32 characters.  Generate with:

	```
	openssl rand -hex 32
	```

# [tls] — server-side TLS

When this section is absent or *enabled = false*, the server speaks
plain HTTP.  In typical production deployments, TLS termination is
handled upstream by nginx, haproxy, or another reverse proxy, and this
section is omitted.

*enabled* = _bool_
	Set to *true* to enable TLS on the main listener.  Default: *false*.

*cert_file* = _path_
	Path to the server TLS certificate PEM file.  The file should
	contain the leaf certificate followed by any intermediate
	certificates (chain order).  Required when *enabled = true* and
	*server_name* is not set.

*key_file* = _path_
	Path to the server TLS private key PEM file.  Required when
	*enabled = true* and *server_name* is not set.

*protocols* = _[string, ...]_
	TLS protocol versions to accept.  Accepted values: *TLSv1.2*,
	*TLSv1.3*.  Default: *["TLSv1.2", "TLSv1.3"]*.  For strict
	configurations drop *TLSv1.2*.

*server_name* = _hostname_
	When set (and *cert_file* / *key_file* are absent), the server
	auto-generates a self-signed TLS certificate for this hostname on
	first run.  For testing only.

*bootstrap_key_type* = _string_
	Key algorithm for the auto-generated self-signed TLS certificate.
	Same accepted values as *[[ca]].key_type*.  Default: *ec:P-256*.
	Only used when *server_name* is set.

## [tls.client_auth]

Mutual TLS (mTLS) client certificate authentication.  When this
subsection is present, the server requests a client certificate from
all connecting TLS clients.

*required* = _bool_
	When *true*, TLS handshakes without a valid client certificate are
	rejected.  When *false*, client certificates are verified if
	presented but not required.  Default: *false*.

*ca_files* = _[path, ...]_
	List of PEM files containing the CA certificates trusted for client
	certificate verification.  At least one file is required when this
	subsection is present.

*profile* = _string_
	Certificate path validation profile.  Accepted values:

	*"webpki"*
		Web PKI path validation (RFC 5280 with Web PKI constraints).

	*"rfc5280"*
		Standard RFC 5280 path validation.

	Default: *"webpki"*.

*allow_post_quantum* = _bool_
	When *true*, client certificates using ML-DSA or hybrid composite
	post-quantum keys are accepted.  Default: *false*.

*max_chain_depth* = _integer_
	Maximum certificate chain depth for client certificates.
	Default: *8*.

*minimum_rsa_modulus* = _integer_
	Minimum RSA key size in bits for client certificates.
	Default: *2048*.

# [admin]

Admin endpoints (*/admin/*) are served on a dedicated TLS listener
configured in this section.  When this section is absent, all admin
endpoints return 404.

Operator authentication uses one or both of:

- *mTLS client certificates* — configure *ca_certs* with the operator
  CA(s).
- *GSSAPI/Kerberos* — configure *[admin.gssapi]*.

At least one of *ca_certs* or *[admin.gssapi]* must be configured;
the server exits at startup if neither is set.

*listen_addr* = _addr_
	Address and port for the dedicated admin TLS listener.  Follows the
	same format as the top-level *listen_addr*.  Example:
	*127.0.0.1:9443*.

*cert_file* = _path_
	Path to the admin listener TLS certificate PEM file (leaf then
	chain).  Required when *listen_addr* is set and *server_name* is
	not set.

*key_file* = _path_
	Path to the admin listener TLS private key PEM file.  Required when
	*listen_addr* is set and *server_name* is not set.

*ca_certs* = _[path, ...]_
	List of PEM files containing CA certificates trusted for operator
	mTLS client certificate verification.  Omit when using GSSAPI-only
	authentication.

*session_ttl_secs* = _integer_
	Inactive session expiry.  Sessions with no activity for this
	duration are invalidated and require re-authentication.
	Default: *3600* (1 h).

*session_lock_secs* = _integer_
	Inactivity threshold before a session is locked (FTA_SSL_EXT.1).
	After this many idle seconds, the session token returns *423 Locked*
	rather than *401 Unauthorized*.  The operator must re-authenticate
	to obtain a new token.  Must be less than *session_ttl_secs*.
	Default: *900* (15 min).

*auth_rate_limit* = _integer_
	Maximum credential presentations (session token, mTLS cert, or
	GSSAPI token) from a single source IP in a rolling 5-minute window
	before that source receives *429 Too Many Requests*.  Default: *20*.

*max_failed_auth* = _integer_
	Maximum failed authentication attempts per operator before lockout
	(FIA_AFL.1).  Once exceeded, further attempts return *423 Locked*
	until the lockout expires or an administrator unlocks the operator.
	Default: *5*.

*lockout_duration_secs* = _integer_
	How long the operator account remains locked after exceeding
	*max_failed_auth* (FIA_AFL.1).  Default: *1800* (30 min).

*audit_max_rows* = _integer_
	Maximum number of rows retained in the audit log (FAU_STG.4).  When
	absent, the audit log is unlimited.

*audit_overflow* = _string_
	Policy when *audit_max_rows* is reached (FAU_STG.4).  Accepted
	values:

	*"drop_oldest"*
		Delete the oldest audit rows to make room for new events.

	*"halt"*
		Halt the server rather than drop audit rows.

*audit_alarm_threshold* = _integer_
	Number of *SecurityViolation* events within a rolling 5-minute
	window that triggers a security alarm (FAU_ARP.1).

*audit_alarm_action* = _string_
	Action taken when *audit_alarm_threshold* is reached (FAU_ARP.1).
	Accepted values: *"syslog"* (log a syslog ALERT message),
	*"halt"* (halt the server).

*server_name* = _hostname_
	When set (and *cert_file* / *key_file* are absent), auto-generates
	a self-signed TLS certificate for the admin listener on first run.
	For testing only.  Default: *localhost*.

*bootstrap_key_type* = _string_
	Key algorithm for the auto-generated admin TLS certificate.  Same
	accepted values as *[[ca]].key_type*.  Default: *ec:P-256*.

*bootstrap_operator_cert_file* = _path_
	Path where the bootstrap Administrator client certificate is written
	on first run.  When this file and *bootstrap_operator_key_file* are
	absent and the operators table is empty, a client certificate is
	generated and the operator is registered automatically.  Both fields
	must be set together.  Mutually exclusive with
	*bootstrap_operator_gssapi_principal*.

*bootstrap_operator_key_file* = _path_
	Path where the bootstrap Administrator client private key is written
	on first run.  Must be set alongside *bootstrap_operator_cert_file*.
	Mutually exclusive with *bootstrap_operator_gssapi_principal*.

*bootstrap_operator_name* = _string_
	Display name for the bootstrap Administrator operator.  Used when
	registering the initial operator on first run.  Default: *admin*.

*bootstrap_operator_gssapi_principal* = _principal_
	Kerberos principal for the GSSAPI bootstrap Administrator operator
	(e.g. _admin@EXAMPLE.COM_).  When set and the operators table is
	empty at startup, the principal is registered as Administrator so
	the first *akamuctl login --gssapi* succeeds without manual operator
	registration.  Mutually exclusive with *bootstrap_operator_cert_file*
	and *bootstrap_operator_key_file*.

## [admin.gssapi]

GSSAPI/Kerberos authentication for admin operators.

*keytab_file* = _path_
	Path to the HTTP service keytab file.  Required when using
	GSSAPI authentication for the admin API.

*service_name* = _string_
	Kerberos service name.  MIT Kerberos appends *@*_hostname_
	automatically.  Default: *HTTP*.

# [profiles] — certificate profiles

When this section is absent, the deprecated *[server].profiles* map
governs directory advertisement and the local CA applies its defaults to
all orders.

*refresh_interval_secs* = _integer_
	How often profile providers are re-read, in seconds.
	Default: *3600* (1 hour).

When a *default* profile is configured, the server automatically applies it
to *newOrder* requests that omit the *profile* field (RECOMMENDED by
draft-ietf-acme-profiles-01 §4).  The echoed profile name in the order
object allows clients to record which profile was applied.  Profiles named
anything other than *default* are never auto-applied; the client must
request them explicitly.

Profile providers are defined under *[profiles.providers.*_name_*]*.
Each provider has a *type* field that determines its kind.

## Builtin profile provider

```
[profiles.providers.local]
type = "builtin"
```

Individual profiles are defined as
*[profiles.providers.*_name_*.profiles.*_profile-id_*]*.

*description* = _string_
	Human-readable description of the certificate profile.  Advertised
	in the ACME directory.

*validity_days* = _integer_
	Validity period of certificates issued under this profile, in days.
	Overrides *[[ca]].validity_days* for this profile.

*hash_alg* = _string_
	Hash algorithm for certificates issued under this profile.  Inherits
	from *[[ca]].hash_alg* when absent.  Accepted values: *sha256*,
	*sha384*, *sha512*.

*key_usage* = _[string, ...]_
	X.509 KeyUsage bits to assert.  Common values:
	*digital_signature*, *key_encipherment*, *content_commitment*,
	*key_agreement*, *key_cert_sign*, *crl_sign*.

*eku* = _[string, ...]_
	Extended Key Usage OID names.  Common values: *server_auth*,
	*client_auth*, *email_protection*, *code_signing*.

*allowed_key_types* = _[string, ...]_
	Key types accepted in CSRs for this profile.  Same syntax as
	*[[ca]].key_type*.  When empty, any key type is accepted.

*certificate_policies* = _[{oid = string}, ...]_
	Certificate policy OIDs to include in the Certificate Policies
	extension.  Example: *[{oid = "2.23.140.1.2.1"}]* for the CA/B
	Forum BR DV-SSL OID.

*crl_url* = _url_
	Overrides *[[ca]].crl_url* for certificates issued under this
	profile.  Set to *""* (empty string) to suppress the CDP extension
	even when the CA has a *crl_url* configured.

*ocsp_url* = _url_
	Overrides *[[ca]].ocsp_url* for certificates issued under this
	profile.  Set to *""* (empty string) to suppress the AIA OCSP
	extension even when the CA has an *ocsp_url* configured.

*allowed_identifiers* = _[string, ...]_
	List of allowed identifier patterns.  Each entry is a regular
	expression prefixed with the identifier type and a colon separator
	(e.g. a DNS pattern like *dns:* followed by a regular expression).
	When non-empty, ACME orders whose identifiers do not match at least
	one pattern are rejected.

*identifier_match* = _string_
	How *allowed_identifiers* are applied.  Accepted values:

	*"all"*
		Every identifier in the order must match at least one pattern.

	*"any"*
		At least one identifier in the order must match a pattern.

	Default: *"all"*.

*require_account_grant* = _bool_
	When *true*, the ACME account must have been granted this profile
	via *POST /admin/accounts/{id}/grants* before orders using this
	profile are accepted.  Default: *false*.

*auth_hook* = _path_
	Absolute path to an executable invoked at authorization time to
	perform additional policy checks.  The hook receives order details
	on stdin as JSON and must exit *0* to permit issuance.

*auth_hook_timeout_secs* = _integer_
	Timeout for the *auth_hook* invocation in seconds.  Default: *30*.

*issue_as* = _string_
	Certificate format for issuance.  Accepted values: *x509* (standard
	X.509 DER/PEM), *mtc* (Merkle Tree Certificate).  Default: *x509*.

	When set to *mtc*, the ACME certificate download endpoint
	(*GET /acme/cert/{id}*) returns a binary DER-encoded
	*StandaloneCertificate* with *Content-Type: application/pkix-cert*
	instead of a PEM chain.  *akamu-cli*(1) saves the binary directly to
	the file given by *--out*; the ARI renewal check (*akamu-cli renew*)
	extracts the embedded *TBSCertificate* — present as the first SEQUENCE
	field in *StandaloneCertificate* — for cert-id construction, so ARI
	works identically for MTC and X.509 certificates.

*ca_ids* = _[string, ...]_
	List of CA IDs for which this profile is available.  When set,
	ACME clients that request this profile via a CA not in the list
	receive an *invalidProfile* error at finalize time.  When empty
	(the default) the profile is available via all configured CAs.
	Config validation rejects *ca_ids* entries that do not match any
	configured CA *id*.

## Dogtag profile provider

```
[profiles.providers.dogtag]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = []
```

*profile_dir* = _path_
	Directory containing Dogtag PKI profile *.cfg* files.  Required.

*profiles* = _[string, ...]_
	List of profile IDs to load from *profile_dir*.  When empty, all
	*.cfg* files in the directory are loaded.

## IPA profile provider

```
[profiles.providers.ipa]
type     = "ipa"
profiles = ["caIPAserviceCert"]
```

*profiles* = _[string, ...]_
	List of FreeIPA profile IDs to load via GSSAPI LDAP.  Required.

## [profiles.providers._name_.ldap] — IPA LDAP connection

*uri* = _url_
	LDAP server URI.  Example: *ldap://ipa.example.com:7389*.  Required.

*base_dn* = _dn_
	LDAP base DN for profile searches.  Example: *o=ipaca*.  Required.

*gssapi* = _bool_
	When *true*, authenticate to LDAP using GSSAPI/Kerberos.
	Default: *true*.

*keytab_file* = _path_
	Path to the Kerberos keytab file.  Required when *gssapi = true*.

*principal* = _principal_
	Kerberos principal used for LDAP authentication.  Example:
	_akamu/akamu.example.com@EXAMPLE.COM_.

*timeout_secs* = _integer_
	LDAP operation timeout in seconds.  Default: *10*.

*starttls* = _bool_
	When *true*, upgrade the LDAP connection to TLS using STARTTLS.
	Default: *false*.

*tls_ca_cert_file* = _path_
	Path to a PEM file containing the CA certificate used to verify the
	LDAP server TLS certificate.  Omit to use system trust anchors.

*srv_domain* = _domain_
	Domain name for _ldap._tcp SRV record discovery.  When set,
	overrides *uri* with the SRV-discovered server addresses.

*srv_scheme* = _string_
	URI scheme for SRV-discovered servers.  Accepted values: *ldap*,
	*ldaps*.  Default: *ldap*.

# URL STRUCTURE

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

# ADMIN API — MULTI-CA ENDPOINTS

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
		another CA.  Requires *administrator* or *ca_operations* role.

	*GET /admin/cross-certs*
		List stored cross-certificates.  Filters: *issuer_ca_id*,
		*subject_ca_id*, *limit*, *offset*.

	*GET /admin/cross-certs/{id}*
		Show a single cross-certificate including its PEM.

The *GET /admin/certs*, *GET /admin/orders*, and *GET /admin/accounts*
endpoints accept an optional *?ca_id=* query parameter to limit results
to a specific CA.

The *ca_ra* operator role accepts a *ca_id* field (set via
*PATCH /admin/operators/{id}*).  A *ca_ra* operator with a *ca_id*
may only revoke and view certificates issued by that CA.  An unscoped
*ca_ra* (empty *ca_id*) is rejected with *403 Forbidden* at all
restricted endpoints.

# SEE ALSO

*akamu*(8), *akamuctl*(1), *akamu-cosigner.conf*(5)

# AUTHORS

The akamu project contributors.
