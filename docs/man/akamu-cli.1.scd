AKAMU-CLI(1) "akamu" "User Commands"

# NAME

akamu-cli - ACME client with post-quantum account key support

# SYNOPSIS

*akamu-cli* _command_ [_subcommand_] [_args_]

# DESCRIPTION

*akamu-cli* is the end-user ACME client for the *akamu*(8) project.  It
implements RFC 8555 (ACME) and several extensions:

- *ARI* (RFC 9773) — Automatic Renewal Information, checked before every
  renewal to avoid unnecessary issuance.
- *ML-DSA* account keys (FIPS 204) — post-quantum key types *ml-dsa-44*,
  *ml-dsa-65*, and *ml-dsa-87* are supported alongside classical EC and RSA
  keys, for servers that support PQC account authentication.
- *External Account Binding* (EAB, RFC 8555 §7.3.4) — via explicit HMAC
  credentials or GSSAPI/Kerberos-authenticated EAB fetch (akamu extension).
- *dns-persist-01* challenge — long-lived DNS TXT records per
  draft-ietf-acme-dns-persist, avoiding per-renewal DNS writes.
- *onion-csr-01* challenge — certificate issuance for Tor hidden services.
- *tkauth-01* (RFC 9447 / RFC 9448) — token-based authorisation for DNS
  identifiers; fetches a *JWTClaimConstraints* authority token from a Token
  Authority via SPNEGO/Kerberos and submits it as the challenge response.
  Enables the server to embed KRB5PrincipalName OtherName SANs derived from
  the token's *permittedValues* claims.

The tool is stateless except for two sidecar files it maintains alongside
the account key (see *SIDECAR FILES* below).  No daemon, no database.

# GLOBAL OPTIONS

*-v*, *--verbose*
	Enable debug-level logging for the ACME client library.  Prints the
	subject, issuer, validity dates, and signature algorithm of any CA
	certificate supplied via *--server-ca* and of the server TLS certificate
	during the connection handshake.  Has no visible effect without
	*--server-ca*.  Pass twice (*-vv*) to additionally enable *hyper_util*
	and *rustls* debug output for full TLS-level tracing.

# COMMANDS

## Account management

*account register* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_ [_OPTIONS_]
	Register a new ACME account with the server.  If the key file _FILE_ does
	not exist, a new key is generated using *--key-type* and saved.  The
	resulting account URL is stored in an account URL sidecar next to _FILE_
	(see *SIDECAR FILES*).

	*--server* _URL_
		ACME directory URL.
		Default: *https://acme-v02.api.letsencrypt.org/directory*

	*--ca* _CA_ID_
		CA identifier for akamu multi-CA servers.  When set, the directory
		URL is constructed as _{server}/acme/{ca}/directory_, overriding
		*--server* if it does not already end in */directory*.

	*--account-key* _FILE_
		PEM file for the account key.  Generated and saved if the file does
		not exist.

	*--key-type* _TYPE_
		Key type to generate when _FILE_ does not exist.
		Default: *ec:P-256*.  See *KEY TYPES* below.

	*--contact* _URI_
		Contact URI (e.g. *mailto:admin@example.com*).  May be repeated.
		Stored by the server; used for expiry warnings and abuse contact.

	*--agree-tos*
		Agree to the server's terms of service.  Required by most public
		CA servers.  Without this flag the server may reject the request.

	EAB flags — see *EXTERNAL ACCOUNT BINDING* below.

*account deregister* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_
	Deactivate an existing ACME account (RFC 8555 §7.3.7).  Reads the account
	URL from the sidecar file.  Sends a deactivation request to the server.
	Removes the sidecar file on success.  A deactivated account cannot be
	reactivated; all pending orders and authorizations are abandoned.

	*--server* _URL_
		ACME directory URL.

	*--ca* _CA_ID_
		CA identifier for multi-CA servers.

	*--account-key* _FILE_
		PEM file for the account key.  The account URL sidecar must exist
		next to this file.

*account show* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_
	Print the URL, status, and contact addresses of the registered account.
	Does not modify any local files.

*account update* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_ [*--contact* _URI_ ...]
	Replace the contact list on the server.  Pass *--contact* once per address;
	omit *--contact* entirely to clear all contacts.

*account key-change* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_ *--new-key* _FILE_ [*--new-key-type* _TYPE_]
	Roll the ACME account key to a new key (RFC 8555 §7.3.5).  The server
	atomically replaces the old public key with the new one; no certificates
	are affected.

	*--account-key* _FILE_
		Current account key PEM file.

	*--new-key* _FILE_
		New key PEM file.  Generated using *--new-key-type* if the file does
		not exist.

	*--new-key-type* _TYPE_
		Key type to generate when *--new-key* does not exist.
		Default: *ec:P-256*.

	On success, _FILE_ given by *--account-key* is overwritten with the new
	key.  The account URL sidecar is not changed (the account URL is stable
	across key rolls).

## Certificate issuance

*issue* [*--server* _URL_] [*--ca* _CA_ID_] *-d* _DOMAIN_ [...] *--account-key* _FILE_ *--out* _FILE_ [_OPTIONS_]
	Obtain a certificate for one or more domain names.  Places an order,
	satisfies all authorizations using the chosen challenge type, submits a
	CSR, and downloads the issued certificate chain.

	If the account key file does not exist, a new key is generated and an
	account is registered inline (EAB flags apply to the inline registration).
	If the account URL sidecar already exists, the stored account is reused.

	After a successful issuance, a TOML renewal sidecar is written to
	_<out>.renewal.toml_ capturing all parameters needed to renew with
	*akamu-cli renew --renewal-config* (see *SIDECAR FILES*).

	*--server* _URL_
		ACME directory URL.
		Default: *https://acme-v02.api.letsencrypt.org/directory*

	*--ca* _CA_ID_
		CA identifier for multi-CA servers.  Constructs the directory URL as
		_{server}/acme/{ca}/directory_.

	*-d* _DOMAIN_, *--domain* _DOMAIN_
		Domain name to include in the certificate.  May be repeated.  The
		first domain becomes the Common Name; all become Subject Alternative
		Names.  Prefix with *\*.* for wildcards (requires a DNS challenge).

	*--account-key* _FILE_
		PEM file for the account key.

	*--key-type* _TYPE_
		Account key type used when generating a new key.
		Default: *ec:P-256*.

	*--cert-key* _FILE_
		Reuse an existing certificate private key.  When absent, a new key
		is generated and saved as _<out>.key.pem_.

	*--cert-key-type* _TYPE_
		Key type for a newly generated certificate key.
		Default: *ec:P-256*.

	*--profile* _ID_
		Request a named certificate profile (draft-ietf-acme-profiles-01).
		The profile controls validity period, key usage, EKU, and other
		certificate parameters on servers that support profiles.  Omit to
		let the server apply its default (servers with a *default* profile
		configured will apply it automatically).  The echoed profile name
		is saved in the renewal TOML sidecar.

	*--out* _FILE_
		Write the issued certificate to this file.  For standard X.509
		profiles the content is a PEM certificate chain
		(*application/pem-certificate-chain*).  For MTC profiles
		(*issue_as = "mtc"* in *akamu.conf*(5)) the server delivers a
		binary DER-encoded *StandaloneCertificate*
		(*application/pkix-cert*); the file is written as-is and is *not*
		a PEM file.  *akamu-cli renew* handles both formats transparently:
		the ARI cert-id is derived from the embedded *TBSCertificate*,
		which is the first field of both *Certificate* and
		*StandaloneCertificate*.

	*--challenge* _TYPE_
		Challenge type.  Default: *http-01*.  See *CHALLENGE TYPES* below.

	*--server-ca* _FILE_
		Trust the CA certificate in _FILE_ (PEM) when connecting to the
		ACME server over HTTPS.  Use this when the server uses a private or
		self-signed CA that is not in the system trust store.  The path is
		saved in the renewal TOML sidecar so subsequent *renew* runs do not
		need to repeat this flag.  Enables *-v* cert logging (see *GLOBAL
		OPTIONS*).

	*--tkauth-url* _URL_
		Token Authority endpoint for the *tkauth-01* challenge.  The client
		POSTs an *EnhancedJWTClaimConstraints* request (RFC 9447 §3) with
		SPNEGO *Authorization: Negotiate* to this URL and extracts the
		returned JWT.  Accepts *http://*, *https://*, and *http+unix://*
		URLs.  See *UNIX DOMAIN SOCKET URLS* below.

	*--tkauth-keytab* _FILE_
		Kerberos keytab for SPNEGO authentication to the Token Authority.
		Required when *--challenge tkauth-01* is used.  The principal in
		the keytab is used to acquire a service ticket for the Token
		Authority.

	*--http-port* _PORT_
		Port to serve *http-01* challenges on.  Default: *80*.
		Serving on port 80 typically requires root or *CAP_NET_BIND_SERVICE*.

	*--tls-port* _PORT_
		Port to serve *tls-alpn-01* challenges on.  Default: *443*.

	*--onion-key* _FILE_
		Ed25519 hidden-service key PEM file.  Required for *onion-csr-01*.

	*--dns-hook* _CMD_
		Hook script for automated DNS TXT record management.
		Required for unattended *dns-01* and *dns-persist-01* issuance.
		See *DNS HOOK INTERFACE* below.

	*--poll-timeout* _SECS_
		Maximum seconds to wait for challenge validation and order
		completion.  Default: *120*.

	EAB flags — see *EXTERNAL ACCOUNT BINDING* below.

*renew* [*--renewal-config* _FILE_] [*--cert* _FILE_] [*--force*] [_issue-flags_]
	ARI-aware certificate renewal.  Before issuing, *renew* queries the
	server's Renewal Information endpoint (RFC 9773) and prints the suggested
	renewal window.  Issuance is skipped when the window has not yet opened.

	*--renewal-config* _FILE_
		Load all parameters from a TOML sidecar written by *akamu-cli issue*
		or *akamu-cli import certbot*.  All issue flags are taken from the
		file; command-line flags other than *--cert* and *--force* are
		ignored.  This is the recommended way to automate renewal from cron
		or a systemd timer.

	*--cert* _FILE_
		Existing certificate PEM to check the ARI renewal window against.
		Overrides the certificate path from *--renewal-config*.  Ignored
		when *--force* is set.

	*--force*
		Renew unconditionally, skipping the ARI window check.

	*--cert-key* _FILE_
		Reuse an existing certificate private key instead of generating a
		new one.  Use this when the key is pinned via DANE TLSA records or
		similar mechanisms.  Overrides the *cert_key_path* in
		*--renewal-config* when both are given.

	*--profile* _ID_
		Override the certificate profile for this renewal.  When
		*--renewal-config* is used, the profile stored in the TOML is sent
		by default; this flag overrides it.

	When *--renewal-config* is not given, all the *issue* flags must be
	provided explicitly (or via a combination with *--cert* for the ARI check).
	The *issue* flags are described under *issue* above.

## Certificate revocation

*revoke* [*--server* _URL_] [*--ca* _CA_ID_] *--account-key* _FILE_ *--cert* _FILE_ [_OPTIONS_]
	Revoke an issued certificate (RFC 8555 §7.6).  The certificate is
	identified by its DER content, which the server matches against its
	database.

	*--account-key* _FILE_
		PEM file for the account key that owns the certificate.
		Mutually exclusive with *--cert-key*.

	*--cert* _FILE_
		PEM file containing the certificate to revoke (full chain or leaf).

	*--cert-key* _FILE_
		PEM file for the certificate's own private key.  Use this for
		self-revocation when the account key is no longer available.
		Mutually exclusive with *--account-key*.

	*--reason* _N_
		RFC 5280 CRL reason code.  Accepted values: 0–6 and 8–10.  Omit
		for unspecified (code 0).

		. 0 — unspecified
		. 1 — keyCompromise
		. 2 — cACompromise
		. 3 — affiliationChanged
		. 4 — superseded
		. 5 — cessationOfOperation
		. 6 — certificateHold
		. 8 — removeFromCRL
		. 9 — privilegeWithdrawn
		. 10 — aACompromise

## CA discovery

*ca list* [*--server* _URL_] [*--admin-url* _URL_]
	List CAs available on an akamu server.  Without *--admin-url*, fetches the
	default ACME directory and reports a single *default* CA entry.  For a
	full list of configured CAs on multi-CA deployments, use the admin API via
	*akamuctl ca list*.

	*--server* _URL_
		ACME server base URL or full directory URL.

	*--admin-url* _URL_
		Admin API base URL.  When provided, the tool notes that full CA
		listing requires *akamuctl*(1) and falls back to the default CA.

*ca show* *--ca* _CA_ID_ [*--server* _URL_]
	Show the directory URL for a specific CA.  Attempts a connection to verify
	reachability.

	*--ca* _CA_ID_
		CA identifier to look up.

## Import

*import certbot* [_OPTIONS_]
	Import accounts and certificates from an existing *certbot*(1)
	installation.  Reads certbot's private key files, account metadata, and
	renewal configuration and converts them to the format used by *akamu-cli*.

	*--certbot-dir* _DIR_
		Certbot configuration directory.  Default: */etc/letsencrypt*.
		Reading this directory usually requires *root* access; consider
		using *--dry-run* first.

	*--account-key* _FILE_
		Output path for the imported account key PEM.  Required unless
		*--list* is given.  The account URL sidecar is written alongside.

	*--server* _URL_
		Import only the account registered with this CA URL.  When
		multiple CA directories exist under *<certbot-dir>/accounts/*,
		this flag selects one.

	*-d* _DOMAIN_, *--domain* _DOMAIN_
		Limit certificate import to this domain.  May be repeated.
		Default: import all domains found in renewal configurations.

	*--cert-dir* _DIR_
		Directory to write imported certificate chains and private keys.
		A *<domain>.renewal.toml* sidecar is written for each certificate,
		ready for use with *akamu-cli renew --renewal-config*.

	*--dns-challenge* _TYPE_
		Challenge type to record in renewal configuration for DNS-based
		certbot configurations.  Default: *dns-01*.

	*--dns-hook* _CMD_
		Hook script to store in generated renewal configurations.  Not
		invoked during import; stored so subsequent *renew* calls can use
		it.  If the certbot configuration used a DNS authenticator but no
		*--dns-hook* is provided, a warning is printed for each affected
		domain — the renewal config will require manual addition of
		*dns_hook* before unattended renewal is possible.

	*--dry-run*
		Show what would be done without writing any files.

	*--list*
		List discoverable accounts and certificates from the certbot
		directory, then exit without writing files.

	Wildcard domains stored by certbot with a leading underscore prefix
	are re-encoded as *\*.example.com* in the renewal configuration.

	Account key type and certificate key type are auto-detected from the
	imported key files (EC curve or RSA modulus size); the generated
	renewal TOML will reflect the detected type rather than a hardcoded
	*ec:P-256* default.

	Domains whose certificate chain or private key file is not accessible
	(e.g. requires root and the command is run without elevated privileges)
	are skipped with a warning rather than writing an incomplete renewal
	configuration.  Re-run with *sudo* (or check *--dry-run* first) to
	include them.

	All written files (account key, renewal TOML) are created with mode
	*0600*; copied certificate keys are set to *0600* at the destination.

Certbot authenticator names are mapped to akamu challenge types as follows:

[[ *Certbot authenticator*
:< *akamu challenge type*
|  standalone, webroot, nginx, apache
:  http-01
|  Any *dns-\** plugin; manual with preferred_challenges = dns
:  value of *--dns-challenge* (default: dns-01)
|  tls-sni-01
:  tls-alpn-01 (with a deprecation notice)

## System integration

*install timer* *--renewal-config* _FILE_ [_OPTIONS_]
	Generate a systemd *.service* and *.timer* unit pair that runs
	*akamu-cli renew --renewal-config* _FILE_ on a daily schedule.
	The units are written to */etc/systemd/system/* when the command
	runs as root, or *~/.config/systemd/user/* otherwise.  Use
	*--system* or *--user* to override the auto-detected location.

	*--renewal-config* _FILE_
		TOML renewal configuration written by *akamu-cli issue* or
		*akamu-cli import certbot*.  Required.

	*--unit-name* _NAME_
		Override the generated unit base name.  Default: derived from
		the first domain in the renewal config (e.g.
		*akamu-renew-example.com* for *example.com*; wildcard domains
		produce *akamu-renew-wildcard-example.com*).

	*--system*
		Write units to */etc/systemd/system/* even when running as
		non-root.  Mutually exclusive with *--user*.

	*--user*
		Write units to *~/.config/systemd/user/* even when running as
		root.  Mutually exclusive with *--system*.

	*--on-calendar* _SPEC_
		systemd *OnCalendar* expression for the timer.
		Default: *daily*.  Example: *"Mon *-*-* 04:00:00"*.

	*--enable*
		Run *systemctl [--user] enable* on the timer after writing the
		unit files.

	*--now*
		Start the timer immediately after enabling.  Implies *--enable*.

	*--print-only*
		Print the generated unit file contents to standard output
		without writing any files or calling *systemctl*.  Useful for
		review before committing to installation.

	*--force*
		Overwrite existing unit files without prompting.

	The generated timer uses *RandomizedDelaySec=1h* and
	*Persistent=true* so that a missed run (e.g. the machine was off
	at midnight) is executed on the next startup.  The *ExecStart*
	path is set to the absolute path of the running *akamu-cli*
	binary.

	By default the command writes the unit files and prints a
	ready-to-paste *systemctl enable* command; it does not enable or
	start the timer automatically.

## MTC transparency log

All *mtc* subcommands share these common options:

*--server* _URL_
	ACME server base URL or full directory URL.  Required.

*--ca* _CA_ID_
	CA identifier for multi-CA servers.

*--server-ca* _FILE_
	PEM file of an extra CA certificate to trust for the server's TLS
	connection.

*--max-response-bytes* _BYTES_
	Maximum response body size in bytes.  Default: 10485760 (10 MiB).

*--request-timeout* _SECS_
	HTTP request timeout in seconds.  Default: 30.

*mtc tree-size* *--server* _URL_ [_OPTIONS_]
	Print the current Merkle tree size as JSON.

*mtc root* *--server* _URL_ [_OPTIONS_]
	Print the current tree size and root hash as JSON.

*mtc inclusion-proof* *--server* _URL_ *--cert-id* _ID_ [_OPTIONS_]
	Print the inclusion proof for a certificate as JSON.

	*--cert-id* _ID_
		Certificate ID (UUID from the ACME certificate URL).  Required.

*mtc standalone* *--server* _URL_ *--cert-id* _ID_ [*--out* _FILE_] [_OPTIONS_]
	Download the standalone DER certificate.

	*--cert-id* _ID_
		Certificate ID.  Required.

	*--out* _FILE_
		Write DER bytes to _FILE_.  If omitted, prints hex to stdout.

*mtc landmark-cert* *--server* _URL_ *--cert-id* _ID_ [*--out* _FILE_] [_OPTIONS_]
	Download the landmark certificate for a given certificate.  Returns
	an error with a retry-after duration if the landmark is not yet
	available.

	*--cert-id* _ID_
		Certificate ID.  Required.

	*--out* _FILE_
		Write DER bytes to _FILE_.  If omitted, prints hex to stdout.

*mtc landmarks* *--server* _URL_ [_OPTIONS_]
	List all landmarks as JSON.

*mtc landmark-list* *--server* _URL_ [_OPTIONS_]
	Print the landmark list in text/plain format.

*mtc consistency-proof* *--server* _URL_ *--from* _N_ *--to* _N_ [_OPTIONS_]
	Print a consistency proof between two tree sizes as JSON.

	*--from* _N_
		Starting tree size.  Required.

	*--to* _N_
		Ending tree size.  Required.

*mtc subtree-root* *--server* _URL_ *--start* _N_ *--end* _N_ [_OPTIONS_]
	Print the root hash of a subtree range as JSON.

	*--start* _N_
		Start index (inclusive).  Required.

	*--end* _N_
		End index (exclusive).  Required.

*mtc revoked-ranges* *--server* _URL_ [_OPTIONS_]
	Print revoked entry ranges as JSON.

*mtc verify* *--server* _URL_ *--cert-id* _ID_ [*--cert-file* _FILE_] [_OPTIONS_]
	Verify a standalone certificate's inclusion proof against the
	server's Merkle tree.  Displays certificate details including
	subject, issuer, validity, serial number (with log/leaf
	decomposition), SANs (DNS, IP, email, Kerberos, URI), X.509
	extensions, leaf hash, proof details, root hash, and the
	verification result.

	*--cert-id* _ID_
		Certificate ID.  Required.

	*--cert-file* _FILE_
		Read the standalone DER certificate from a local file instead
		of fetching it from the server.

*mtc checkpoint* *--server* _URL_ [_OPTIONS_]
	Print the signed transparency log checkpoint text.

# KEY TYPES

The following values are accepted by *--key-type*, *--cert-key-type*, and
*--new-key-type*:

[[ *Value*
:< *Algorithm*
|  ec:P-256
:  ECDSA with NIST P-256 (default for all key arguments)
|  ec:P-384
:  ECDSA with NIST P-384
|  ec:P-521
:  ECDSA with NIST P-521
|  rsa:2048
:  RSA 2048-bit
|  rsa:3072
:  RSA 3072-bit
|  rsa:4096
:  RSA 4096-bit
|  ed25519
:  Ed25519 (EdDSA over Curve25519)
|  ed448
:  Ed448 (EdDSA over Curve448)
|  ml-dsa-44
:  ML-DSA Level 2 (FIPS 204) — post-quantum
|  ml-dsa-65
:  ML-DSA Level 3 (FIPS 204) — post-quantum
|  ml-dsa-87
:  ML-DSA Level 5 (FIPS 204) — post-quantum

ML-DSA account keys are only usable with servers that support post-quantum
JWS algorithms.  *akamu*(8) does; most public CA servers do not.

# CHALLENGE TYPES

*http-01*
	The server fetches a token from
	*http://<domain>/.well-known/acme-challenge/<token>*.
	*akamu-cli* binds to *--http-port* (default 80) and serves the token
	directly.  Wildcard domains (*\*.example.com*) cannot be validated with
	http-01 (RFC 8555 §8.3).

*tls-alpn-01*
	The server connects to port *--tls-port* (default 443) and negotiates
	the *acme-tls/1* ALPN protocol (RFC 8737).  *akamu-cli* serves a
	self-signed certificate containing the key authorization in a
	*acmeValidation-v1* extension.  Wildcard domains cannot be validated
	with tls-alpn-01.

*dns-01*
	The server queries _acme-challenge.<domain>. IN TXT_ for the SHA-256
	key authorization digest.  Without *--dns-hook*, *akamu-cli* prompts
	for manual record creation and waits for Enter before triggering
	validation.  The record is removed after validation.  Supports wildcard
	domains.

*dns-persist-01*
	A variant of dns-01 defined in draft-ietf-acme-dns-persist.  The server
	provides long-lived issuer domain names; the client writes a static TXT
	record at _validation-persist.<domain>._ encoding the account URL.  The
	record only needs to be set once and survives across renewals, making it
	suitable for automated wildcard renewal without per-renewal DNS writes.
	Without *--dns-hook*, *akamu-cli* prompts for manual creation of the
	long-lived record.

*onion-csr-01*
	Challenge type for Tor hidden service domains (*\*.onion*).  Requires
	*--onion-key* pointing to an Ed25519 hidden-service key PEM.  The client
	builds and submits a CSR signed with the onion service key, proving
	ownership without any network challenge.

*tkauth-01*
	Token-based authorisation challenge (RFC 9447 / RFC 9448) for DNS
	identifiers.  Requires *--tkauth-url* and *--tkauth-keytab*.

	The client first fetches a preliminary authority token from the Token
	Authority, extracts the *tkvalue* claim, constructs a JWK thumbprint
	fingerprint of the account key, and fetches the final token bound to
	that fingerprint.  The resulting JWT is submitted to the server as the
	challenge response.

	The server validates the JWT signature (via *x5c* certificate chain,
	*x5u* certificate URL, or *kid* key identifier resolved against a
	configured JWKS endpoint), checks the *JWTClaimConstraints*
	*permittedValues*, and embeds the token's allowed Kerberos principals as
	*KRB5PrincipalName* OtherName SANs in the issued certificate.

	Only DNS identifiers are supported; wildcards are not permitted.

# UNIX DOMAIN SOCKET URLS

The *--server* and *--tkauth-url* flags accept *http+unix://* URLs in addition
to *https://* URLs.  This scheme routes the request over a Unix domain socket
instead of a TCP connection.

URL format:

```
http+unix://SOCKET_PATH_ENCODED/REQUEST_PATH
```

where _SOCKET_PATH_ENCODED_ is the socket file path with */* percent-encoded
as *%2F* (all other characters may appear literally or percent-encoded), and
_REQUEST_PATH_ is the normal HTTP path starting with */*.

Examples:

- *http+unix://%2Frun%2Fakamu%2Fakamu.sock/acme/default/directory*
- *http+unix://%2Frun%2Fekishib%2Fekishib.sock/at/account/1/token*

The local machine's hostname (from *gethostname*(2)) is used as the GSSAPI
service host component when authenticating to a Token Authority over a Unix
domain socket.

# EXTERNAL ACCOUNT BINDING

Some CA servers require an External Account Binding (EAB) credential to
associate the new ACME account with a pre-provisioned identity (RFC 8555
§7.3.4).

The following flags are available on *account register*, *issue*, and *renew*:

*--eab-kid* _KID_
	EAB key identifier provided by the CA.  Must be combined with
	*--eab-key*.  Mutually exclusive with *--gssapi-keytab*.

*--eab-key* _KEY_
	EAB HMAC key, base64url-encoded without padding.  Must be combined with
	*--eab-kid*.

*--eab-alg* _ALG_
	HMAC algorithm: *HS256* (default), *HS384*, or *HS512*.

*--gssapi-keytab* _PATH_
	Path to a Kerberos keytab.  *akamu-cli* sends *GET /acme/eab* with a
	*Authorization: Negotiate* token derived from the keytab, retrieves the
	EAB kid and HMAC key from the server's JSON response, and proceeds with
	registration.  The authenticated Kerberos principal is printed to standard
	error.  Mutually exclusive with *--eab-kid* / *--eab-key*.

	The GSSAPI EAB flow is an akamu server extension; it is not available on
	public CA servers.  When the server has no *eab_master_secret* configured,
	the EAB endpoint returns no credentials and *akamu-cli* proceeds without
	EAB and prints a note to standard error.

On *issue* and *renew*, EAB flags are used only when no account URL sidecar
exists (i.e. when inline account registration is required).

The *--eab-key* HMAC secret is intentionally *not* saved in the renewal TOML
sidecar written after a successful *issue*.  Re-supply *--eab-key* on each
renewal that requires a fresh inline registration, or register the account
separately with *account register* first.

# DNS HOOK INTERFACE

When *--dns-hook* _CMD_ is combined with *--challenge dns-01* or
*--challenge dns-persist-01*, *akamu-cli* calls _CMD_ to add and remove
DNS TXT records instead of waiting for manual input.

The hook is invoked as:

```
<CMD> add
<CMD> remove
```

Values are passed via environment variables (not as command-line arguments,
which would be visible in */proc/<pid>/cmdline*):

[[ *Variable*
:< *Value*
|  AKAMU_DOMAIN
:  DNS name being validated (wildcard prefix *\*.* stripped)
|  AKAMU_TOKEN
:  ACME challenge token
|  AKAMU_TXT
:  TXT record value (*base64url(SHA-256(key_auth))*)
|  AKAMU_KEY_AUTH
:  Full key authorization string

Exit code 0 indicates success.  A non-zero exit code is treated as failure;
stderr output from the hook is captured and included in the error message.

For *dns-01*, the hook is called with *add* before challenge validation and
with *remove* after it completes (success or failure).

For *dns-persist-01*, only *add* is called on success.  The TXT record is
long-lived and must not be removed between renewals.

# SIDECAR FILES

*akamu-cli* maintains two categories of sidecar files alongside the account
key and certificate chain.  These files are plain text and can be inspected
or edited if needed.

## Account URL sidecar

After a successful *account register* or inline registration during *issue*
or *import certbot*, the ACME account URL is written to a file next to the
account key:

[[ *Scenario*
:< *Sidecar filename*
|  Single CA or default CA (no *--ca*)
:  _<account-key>.account-url_
|  Named CA (*--ca* _ID_ where _ID_ ≠ *default*)
:  _<account-key>.<ca_id>.account-url_

For example, with *--account-key /etc/akamu/acme.pem* and *--ca rsa*, the
sidecar is */etc/akamu/acme.pem.rsa.account-url*.

The CA ID is sanitized before use in filenames: any character that is not
alphanumeric, a hyphen, or an underscore is replaced with an underscore.

*account deregister* reads the sidecar to find the account URL and removes it
after deactivation.  *issue* and *renew* read it to skip re-registration
when the file already exists.

## Renewal sidecar

After every successful *issue*, a TOML file named _<out>.renewal.toml_ is
written alongside the certificate chain.  It records the full set of
parameters needed to renew the certificate with
*akamu-cli renew --renewal-config*.

Key fields in the renewal TOML:

```
server           = "https://acme.example.com"
ca               = "rsa"        # absent when using the default CA
account_key      = "/etc/akamu/account.pem"
account_key_type = "ec:P-256"
cert_path        = "/etc/ssl/example.com/fullchain.pem"
cert_key_path    = "/etc/ssl/example.com/fullchain.pem.key.pem"
cert_key_type    = "ec:P-256"
challenge_type   = "dns-01"
http_port        = 80
tls_port         = 443
poll_timeout     = 120
eab_alg          = "HS256"
dns_hook         = "/etc/akamu/hooks/dns-update.sh"
profile          = "dv-tls"    # omitted when no profile was requested
server_ca        = "/etc/akamu/ca.pem"      # omitted when not set
tkauth_url       = "https://idp.example.com/at/account/1/token"  # omitted when not set
tkauth_keytab    = "/etc/akamu/client.keytab"                    # omitted when not set

[[domains]]
type  = "dns"
value = "example.com"

[[domains]]
type  = "dns"
value = "*.example.com"
```

The *profile* key is omitted when neither the client nor the server selected
a profile during issuance.  The *eab_key* field is never written; supply
*--eab-key* explicitly on renewals that require inline account registration.
The *server_ca*, *tkauth_url*, and *tkauth_keytab* fields are omitted when
the corresponding flags were not set during issuance.

All private files written by *akamu-cli* (*account_key*, *cert_key_path*,
the renewal TOML itself) are created with mode *0600*, readable only by the
owning user.

# EXAMPLES

Register a new account with Let's Encrypt:

```
akamu-cli account register \
  --account-key /etc/akamu/acme.pem \
  --key-type ec:P-256 \
  --contact mailto:admin@example.com \
  --agree-tos
```

Issue a certificate via http-01 (requires port 80):

```
akamu-cli issue \
  --account-key /etc/akamu/acme.pem \
  --domain example.com \
  --domain www.example.com \
  --out /etc/ssl/example.com/fullchain.pem
```

Issue a wildcard certificate via dns-01 with a hook script:

```
akamu-cli issue \
  --account-key /etc/akamu/acme.pem \
  --domain example.com \
  --domain '*.example.com' \
  --challenge dns-01 \
  --dns-hook /etc/akamu/hooks/dns-update.sh \
  --out /etc/ssl/example.com/wildcard.pem
```

Renew using the generated renewal config (suitable for cron):

```
akamu-cli renew \
  --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml
```

Register on an akamu multi-CA server using GSSAPI EAB:

```
akamu-cli account register \
  --server https://acme.corp.example.com \
  --ca rsa \
  --account-key /etc/akamu/acme.pem \
  --agree-tos \
  --gssapi-keytab /etc/akamu/client.keytab
```

Import from certbot and renew:

```
sudo akamu-cli import certbot \
  --account-key /etc/akamu/acme.pem \
  --cert-dir /etc/akamu/certs \
  --dns-hook /etc/akamu/hooks/dns-update.sh

akamu-cli renew \
  --renewal-config /etc/akamu/certs/example.com.pem.renewal.toml
```

Roll the account key to an ML-DSA key:

```
akamu-cli account key-change \
  --server https://acme.corp.example.com \
  --account-key /etc/akamu/acme.pem \
  --new-key /etc/akamu/acme-pq.pem \
  --new-key-type ml-dsa-65
```

Revoke a certificate using the certificate's own private key:

```
akamu-cli revoke \
  --server https://acme.corp.example.com \
  --account-key /etc/akamu/acme.pem \
  --cert /etc/ssl/example.com/fullchain.pem \
  --cert-key /etc/ssl/example.com/fullchain.pem.key.pem \
  --reason 1
```

Issue a certificate using tkauth-01 with GSSAPI authentication to a Token
Authority (Ekishib) via Unix socket:

```
akamu-cli issue \
  --server https://acme.corp.example.com \
  --ca kerberos-svc \
  --account-key /etc/akamu/acme.pem \
  --domain host.example.com \
  --challenge tkauth-01 \
  --tkauth-url 'http+unix://%2Frun%2Fekishib%2Fekishib.sock/at/account/1/token' \
  --tkauth-keytab /etc/akamu/client.keytab \
  --out /etc/ssl/host.example.com/fullchain.pem
```

Preview the generated unit files without writing anything:

```
akamu-cli install timer \
  --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml \
  --print-only
```

Install a system-wide timer and enable it immediately (requires root):

```
sudo akamu-cli install timer \
  --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml \
  --enable --now
```

Install a user-level timer for non-root certificate management:

```
akamu-cli install timer \
  --renewal-config ~/certs/example.com.pem.renewal.toml
# then:
systemctl --user enable --now akamu-renew-example.com.timer
```

Query the MTC transparency log tree size and root hash:

```
akamu-cli mtc tree-size --server https://acme.example.com
akamu-cli mtc root --server https://acme.example.com
```

Verify an MTC standalone certificate by ID (fetches from server):

```
akamu-cli mtc verify \
  --server https://acme.example.com \
  --cert-id ddaf3c89-1da0-4bc0-b2aa-abe634e88dc0
```

Verify a locally saved standalone certificate:

```
akamu-cli mtc verify \
  --server https://acme.example.com \
  --cert-id ddaf3c89-1da0-4bc0-b2aa-abe634e88dc0 \
  --cert-file /tmp/cert.der
```

Download a standalone certificate and verify it with a custom timeout:

```
akamu-cli mtc standalone \
  --server https://acme.example.com \
  --cert-id ddaf3c89-1da0-4bc0-b2aa-abe634e88dc0 \
  --out /tmp/cert.der

akamu-cli mtc verify \
  --server https://acme.example.com \
  --cert-id ddaf3c89-1da0-4bc0-b2aa-abe634e88dc0 \
  --cert-file /tmp/cert.der \
  --request-timeout 60
```

# ENVIRONMENT

*RUST_LOG*
	Controls log output level and filtering.  The default filter enables
	*INFO*-level messages from the *akamu_client* library.  Set to *debug*
	for verbose protocol-level tracing:

	```
	RUST_LOG=debug akamu-cli issue ...
	```

# EXIT STATUS

*0*	Command succeeded.

*1*	Command failed.  An error message is written to standard error.

# SEE ALSO

*akamu*(8), *akamu-cosigner*(8), *akamuctl*(1),
*akamu.conf*(5)

RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile++
RFC 8555 - Automatic Certificate Management Environment (ACME)++
RFC 8737 - ACME TLS-ALPN-01 Challenge Extension++
RFC 9447 - Automated Certificate Management Environment (ACME) Token Binding for Path Validation (tkauth-01)++
RFC 9448 - TNAuthList Profile of Automated Certificate Management Environment (ACME) Authority Token++
RFC 9773 - ACME Renewal Information (ARI)++
RFC 9799 - ACME Extensions for .onion Special-Use Domain Names++
draft-ietf-acme-dns-persist - Persistent DNS-01 Challenge for ACME++
RFC 9964 - ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)++
draft-ietf-plants-merkle-tree-certs-05 - Merkle Tree Certificates (MTC)

# AUTHORS

The akamu project contributors.
