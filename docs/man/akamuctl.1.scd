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

*login*
	Authenticate with the admin API and cache the session token.
	The cached token is used by all subsequent commands until it
	expires.  Re-run *login* to refresh the token.

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

*operator add* --name _NAME_ --role _ROLE_ [OPTIONS]
	Register a new operator.

	*--name* _NAME_
		Display name for the operator.

	*--role* _ROLE_
		Role: *administrator* or *auditor*.

	*--cert-file* _FILE_
		Path to the operator's client certificate.  The SHA-256
		fingerprint of the leaf DER is extracted and stored.

	*--gssapi-principal* _PRINCIPAL_
		Kerberos principal (e.g. *alice@REALM*) for GSSAPI auth.

*operator remove* _ID_
	Deactivate the operator with the given numeric ID.
	The record is retained for audit purposes.

*operator activate* _ID_
	Re-activate a previously deactivated operator.

## EAB key management

*eab list* [--used] [--unused]
	List External Account Binding (EAB) keys.
	*--used* shows only consumed keys; *--unused* shows only
	available keys.  Without flags, shows all keys.

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

*revoke* _CERT_ID_ [--reason _CODE_]
	Revoke a certificate by its database ID.
	_CODE_ is an RFC 5280 CRL reason code (default: 0 = unspecified).

*crl-force*
	Force immediate regeneration of the CRL.

## Account management

*account grants get* _ACCOUNT_ID_
	Show the certificate profile grants for an ACME account.

*account grants set* _ACCOUNT_ID_ --profile _PROFILE_ [...]
	Set profile grants for an account.  Replaces the existing grant
	list.  Repeat *--profile* for multiple profiles.

*account grants clear* _ACCOUNT_ID_
	Remove all profile grants from an account (unrestricted access).

## Cosigner administration

*cosigner status*
	Print cosigner connectivity and identity information.

*cosigner stats*
	Print cosigner statistics (signing counts, uptime, etc.).

## Configuration

*config generate*
	Print an annotated example *akamuctl.toml* to standard output.
	Redirect to a file as a starting point for your configuration:

		akamuctl config generate > ~/.config/akamu/akamuctl.toml

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

# Cosigner admin URL and TLS settings (optional; required for
# 'akamuctl cosigner' commands).
[cosigner]
# url     = "https://cosigner.example.com:9444"
# ca_cert = "/etc/akamu/cosigner-ca.cert.pem"
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
