AKAMUCTL(1) "akamu" "User Commands"

# NAME

akamuctl - administration CLI for the akamu ACME server

# SYNOPSIS

*akamuctl* [OPTIONS] _command_ [_subcommand_] [_args_]

# DESCRIPTION

*akamuctl* is the command-line administration tool for *akamu*(8).  It
communicates with the akamu administration REST API over HTTPS, using
mTLS client certificate authentication and/or GSSAPI/Kerberos.

The tool reads connection parameters from a TOML configuration file
(see *CONFIGURATION FILE* below).  All parameters can also be supplied
on the command line; command-line values override the config file.

Session tokens obtained after *login* are cached in
*~/.config/akamu/session.json* and reused until they expire.

# OPTIONS

*-c*, *--config* _FILE_
	Path to the configuration file.
	Default: *~/.config/akamu/akamuctl.toml*

*--server-url* _URL_
	Admin API base URL (overrides *[server].url* in the config).

*--ca-cert* _FILE_
	CA certificate file for TLS server verification
	(overrides *[server].ca_cert*).

*--cert* _FILE_
	mTLS client certificate file (overrides *[server].cert_file*).

*--key* _FILE_
	mTLS client private key file (overrides *[server].key_file*).

*-o*, *--output* _FORMAT_
	Output format.  *table* (default) or *json*.

# COMMANDS

## Authentication

*login* [*--gssapi*]
	Authenticate with the admin API and cache the session token.
	The cached token is used by all subsequent commands until it
	expires.  Re-run *login* to refresh the token.

	*--gssapi*
		Use GSSAPI/Kerberos (HTTP Negotiate) instead of mTLS client
		certificates.  A valid Kerberos TGT must be present in the
		default ccache (run _kinit_ first).

		The GSSAPI service principal name (SPN) is resolved as follows:

		. If *gssapi_service* is set in *[server]* config, it is used
		  as-is.
		. Otherwise the SPN is derived from the server URL as
		  *HTTP@*_hostname_, where _hostname_ is determined by:
		  - Loopback names (_localhost_, _ip6-localhost_,
		    _localhost.localdomain_, _ip6-loopback_) and loopback IP
		    addresses (127.x.x.x, ::1) → replaced with the machine's
		    own FQDN via *gethostname*(2) and forward/reverse DNS.
		  - Non-loopback IP addresses → resolved to a hostname via a
		    DNS PTR lookup using *hickory-resolver*; a warning is
		    printed and the IP is used as a fallback if reverse DNS
		    fails.
		  - DNS hostnames → used directly.

*logout*
	Invalidate the current session token.

## Statistics and audit

*stats*
	Print server and cosigner statistics (certificate counts,
	account counts, audit row count, etc.).

*audit* [OPTIONS]
	Query the audit event log.

	*--type* _TYPE_
		Filter by event type (e.g. *cert.issue*, *auth.login*).

	*--subject* _SUBJECT_
		Filter by subject (JWK thumbprint, certificate serial,
		or account UUID).

	*--from* _RFC3339_
		Include only events at or after this timestamp.

	*--until* _RFC3339_
		Include only events at or before this timestamp.

	*--outcome* _OUTCOME_
		Filter by outcome: *success* or *failure*.

	*--limit* _N_
		Maximum number of results (default: 100).

	*--offset* _N_
		Pagination offset (default: 0).

## Operator management

*operator list*
	List all registered operators with their ID, name, role,
	and active status.

*operator show* _ID_
	Show the details of a single operator by numeric ID, including
	certificate fingerprint, GSSAPI principal, creation time, and
	last-seen timestamp.

*operator add* --name _NAME_ --role _ROLE_ [OPTIONS]
	Register a new operator.

	*--name* _NAME_
		Display name for the operator.

	*--role* _ROLE_
		Role: *administrator*, *ca_operations*, *ca_ra*, or *auditor*.

	*--cert-file* _FILE_
		Path to the operator's client certificate.  The SHA-256
		fingerprint of the leaf DER is extracted and stored.

	*--gssapi-principal* _PRINCIPAL_
		Kerberos principal (e.g. *alice@REALM*) for GSSAPI auth.

*operator update* _ID_ [OPTIONS]
	Update fields of an existing operator.  Only provided fields are
	changed; omitted fields remain unchanged.

	*--name* _NAME_
		New display name.

	*--role* _ROLE_
		New role: *administrator*, *ca_operations*, *ca_ra*, or *auditor*.

	*--ca-id* _CA_ID_
		Assign a CA scope to a *ca_ra* operator.  The operator may
		then only revoke and view certificates issued by that CA.
		Setting *--role ca_ra* without *--ca-id* is rejected.  Pass
		an empty string to clear the CA scope (only valid when
		changing the role away from *ca_ra*).

	*--cert-file* _FILE_
		Path to a new client certificate.  The SHA-256 fingerprint
		is extracted and replaces the stored fingerprint.

	*--gssapi-principal* _PRINCIPAL_
		New Kerberos principal.

*operator remove* _ID_
	Deactivate the operator with the given numeric ID.
	The record is retained for audit purposes.

*operator activate* _ID_
	Re-activate a previously deactivated operator.

*operator unlock* _ID_
	Reset the failed-authentication counter for a locked operator
	and clear the lockout timestamp (FIA_AFL.1).  Use this after an
	operator has been locked out by exceeding *max_failed_auth*.

## EAB key management

*eab list* [--used] [--unused]
	List External Account Binding (EAB) keys.
	*--used* shows only consumed keys; *--unused* shows only
	available keys.  Without flags, shows all keys.

*eab show* _KID_
	Show details of a single EAB key by its key identifier,
	including creation time, usage status, and profile grants.

*eab add* [OPTIONS]
	Provision a new EAB key.

	*--kid* _KID_
		Key identifier.  Auto-generated if absent.

	*--hmac-key* _KEY_
		Base64url HMAC key.  Auto-generated if absent.

	*--profile* _PROFILE_
		Restrict this key to a certificate profile.
		May be repeated for multiple profiles.

*eab remove* _KID_
	Deactivate the EAB key with identifier _KID_.

## Certificate management

*cert list* [OPTIONS]
	List issued certificates.

	*--ca* _CA_ID_
		Filter by CA ID.  Only certificates issued by the named CA
		are returned.

	*--serial* _HEX_
		Filter by certificate serial number.

	*--subject* _DN_
		Filter by subject distinguished name (substring match).

	*--after* _RFC3339_
		Issued at or after this timestamp.

	*--before* _RFC3339_
		Issued at or before this timestamp.

	*--status* _STATUS_
		Filter by status: *active* or *revoked*.

	*--limit* _N_
		Maximum results (default: 20).

	*--offset* _N_
		Pagination offset (default: 0).

*cert show* _CERT_ID_
	Show a certificate's metadata by its UUID, including order ID,
	account ID, serial number, validity window, revocation status,
	MTC log index, and ARI renewal window.

*cert download* _CERT_ID_ [OPTIONS]
	Download a certificate's content.

	*--format* _FORMAT_
		Output format: *pem* (default) or *der*.

	*-o*, *--output* _FILE_
		Write to file instead of standard output.

*revoke* _CERT_ID_ [--reason _CODE_]
	Revoke a certificate by its database ID.
	_CODE_ is an RFC 5280 CRL reason code (default: 0 = unspecified).

*crl-force*
	Force immediate CRL regeneration for the default CA.  To force
	regeneration for a specific CA use *ca crl-force* _CA_ID_ instead.

## Account management

*account list* [OPTIONS]
	List ACME accounts.

	*--ca* _CA_ID_
		Filter by CA ID.  Only accounts registered through the named
		CA's *new-account* endpoint are returned.

	*--status* _STATUS_
		Filter by status: *valid* or *deactivated*.

	*--limit* _N_
		Maximum results (default: 100).

	*--offset* _N_
		Pagination offset (default: 0).

*account show* _ACCOUNT_ID_
	Show details of a single ACME account by its UUID, including
	status, contact information, JWK thumbprint, creation and
	update times, and profile grants.

*account deactivate* _ACCOUNT_ID_
	Admin-initiated account deactivation.  The account is set to
	*deactivated* status and can no longer issue certificates.

*account grants get* _ACCOUNT_ID_
	Show the certificate profile grants for an ACME account.

*account grants set* _ACCOUNT_ID_ --profile _PROFILE_ [...]
	Set profile grants for an account.  Replaces the existing grant
	list.  Repeat *--profile* for multiple profiles.

*account grants clear* _ACCOUNT_ID_
	Remove all profile grants from an account (unrestricted access).

## Profile management

*profile list*
	List all loaded certificate profiles with their parameters,
	including validity period, hash algorithm, extended key usages,
	and MTC issuance settings.

*profile add* _ID_ --params-file _FILE_
	Add a new certificate profile to the runtime cache (FPT_NPE_EXT.1).
	_FILE_ must be a JSON file whose fields match the profile payload
	accepted by *POST /admin/profiles*.  Requires the *administrator* role.

	*--params-file* _FILE_
		Path to the JSON file with profile parameters.

*profile update* _ID_ --params-file _FILE_
	Replace an existing certificate profile in the runtime cache.
	Requires the *administrator* role.

	*--params-file* _FILE_
		Path to the JSON file with updated profile parameters.

*profile remove* _ID_
	Remove a certificate profile from the runtime cache.
	Requires the *administrator* role.

## Order management

*order list* [OPTIONS]
	List certificate orders.

	*--ca* _CA_ID_
		Filter by CA ID.  Only orders placed against the named CA
		are returned.

	*--account-id* _ACCOUNT_ID_
		Filter by account UUID.

	*--status* _STATUS_
		Filter by order status (e.g. *pending*, *ready*, *valid*,
		*invalid*).

	*--limit* _N_
		Maximum results (default: 100).

	*--offset* _N_
		Pagination offset (default: 0).

*order show* _ORDER_ID_
	Show a single order's details by its UUID, including identifiers,
	associated authorization IDs, certificate ID, profile, and
	timing fields.

## CA management

*ca list*
	List all configured CAs with their ID, default flag, key type,
	hash algorithm, CRL URL, and OCSP URL.

*ca show* _CA_ID_
	Show details of a single CA by ID.

*ca cert* _CA_ID_
	Print the CA certificate PEM for the specified CA.

*ca crl-force* _CA_ID_
	Force immediate CRL regeneration for the specified CA.
	Requires the *ca_operations* or *administrator* role.

*ca cross-sign* _ISSUER_ID_ [OPTIONS]
	Issue a cross-certificate: CA _ISSUER_ID_ signs the public key
	of another CA or an externally provided certificate.

	*--subject-ca* _CA_ID_
		ID of the subject CA whose public key will be cross-signed.
		Mutually exclusive with *--subject-cert*.

	*--subject-cert* _FILE_
		PEM file containing the subject CA certificate to cross-sign.
		Mutually exclusive with *--subject-ca*.

	*--validity-years* _N_
		Validity period in years for the cross-certificate.
		Default: 5.

	Requires the *administrator* or *ca_operations* role.

## Cross-certificate management

*cross-cert list* [OPTIONS]
	List stored cross-certificates.

	*--issuer-ca* _CA_ID_
		Filter by issuing CA ID.

	*--subject-ca* _CA_ID_
		Filter by subject CA ID.

	*--limit* _N_
		Maximum results (default: 100).

	*--offset* _N_
		Pagination offset (default: 0).

*cross-cert download* _CROSS_CERT_ID_ [OPTIONS]
	Download a cross-certificate by its UUID.

	*--format* _FORMAT_
		Output format: *pem* (default) or *der*.

	*-o*, *--output* _FILE_
		Write to file instead of standard output.

## Server configuration

*server-config*
	Show the server's redacted runtime configuration.  Sensitive
	fields such as the database URL are masked.

## Session inspection

*whoami*
	Show information about the locally cached session tokens for
	both server and cosigner.  Displays the server URL and token
	expiry time.  Does not contact the server.

## Cosigner administration

*cosigner login*
	Authenticate with the cosigner admin API and cache the session
	token.

*cosigner logout*
	Invalidate the cosigner session token.

*cosigner status*
	Print cosigner connectivity and identity information.

*cosigner stats*
	Print cosigner statistics (signing counts, uptime, etc.).

*cosigner config*
	Show the cosigner's redacted runtime configuration.

## Configuration utilities

*config generate*
	Print an annotated example *akamuctl.toml* to standard output.
	Redirect to a file as a starting point for your configuration:

		akamuctl config generate > ~/.config/akamu/akamuctl.toml

*config validate*
	Validate the configuration file.  Checks that referenced files
	(certificates, keys) exist on disk and that the server URL is
	well-formed.

## Shell completions

*completions* _SHELL_
	Generate shell completion scripts for the given shell.
	Supported values: *bash*, *zsh*, *fish*, *elvish*, *powershell*.

	Example:

		akamuctl completions bash > /etc/bash_completion.d/akamuctl

# CONFIGURATION FILE

The default configuration file is *~/.config/akamu/akamuctl.toml*.
Use *akamuctl config generate* to produce an annotated template.

```
[server]
# Base URL of the akamu admin API.
url      = "https://akamu.example.com:9443"

# CA certificate used to verify the admin TLS endpoint.
# Omit to use system trust anchors.
# ca_cert = "/etc/akamu/certs/ca.cert.pem"

# mTLS client credentials (required when the admin API uses cert auth).
# cert_file = "/etc/akamu/operator.cert.pem"
# key_file  = "/etc/akamu/operator.key.pem"

# GSSAPI service principal name used by 'akamuctl login --gssapi'.
# Overrides the automatic HTTP@<hostname> derivation from the server URL.
# gssapi_service = "HTTP@akamu.example.com"

# Cosigner admin URL and TLS settings (optional; required for
# 'akamuctl cosigner' commands).
[cosigner]
# url           = "https://cosigner.example.com:9444"
# ca_cert       = "/etc/akamu/cosigner-ca.cert.pem"
# gssapi_service = "HTTP@cosigner.example.com"
```

# FILES

*~/.config/akamu/akamuctl.toml*
	Per-user configuration file.

*~/.config/akamu/session.json*
	Cached session token (mode 0600).

# EXIT STATUS

*0*	Command succeeded.

*1*	Command failed.  An error message is written to standard error.

# SEE ALSO

*akamu*(8), *akamu-cosigner*(8)

# AUTHORS

The akamu project contributors.
