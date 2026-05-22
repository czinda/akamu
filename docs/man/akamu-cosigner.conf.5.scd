AKAMU-COSIGNER.CONF(5) "akamu" "File Formats"

# NAME

akamu-cosigner.conf - configuration file for the akamu-cosigner MTC daemon

# SYNOPSIS

*/etc/akamu-cosigner/cosigner.toml*

# DESCRIPTION

*akamu-cosigner*(8) reads its configuration from a TOML file.  The default
path when running under systemd is */etc/akamu-cosigner/cosigner.toml*.

All section headers shown below correspond directly to TOML table names.
Fields marked *Required* must be present; all others have defaults or are
optional.

# [server]

*listen_addr* = _addr_
	Address the cosigner daemon binds to.  Two forms are accepted:

	_host:port_ (e.g. *"0.0.0.0:8444"*)
		TCP listener.

	*"unix:"*_/path/to/socket_ (e.g. *"unix:/run/akamu-cosigner/cosigner.sock"*)
		Unix domain socket listener.  Use this when akamu and
		akamu-cosigner run on the same host and you want to avoid an
		exposed TCP port.  When running under systemd with
		*akamu-cosigner.socket*, the socket is inherited via *LISTEN_FDS*.

	Default: *"0.0.0.0:8080"*.  Overridden by the
	*AKAMU_COSIGNER_LISTEN* environment variable.  Unix domain socket
	listeners cannot be combined with *[tls]*.

*base_url* = _url_
	The public URL of this cosigner instance (e.g.
	*"https://cosigner.example.com:8444"*).  This value is used when
	constructing the *SubtreeSignature* and when generating the dNSName
	SAN in the auto-generated self-signed cosigner-id certificate.
	Required.

# [tls]

Optional.  When this section is present, the HTTP server enables TLS on
*listen_addr*.  TLS is mutually exclusive with Unix domain socket
listeners.

When *[tls]* is absent and *[acme_bootstrap]* is configured, the
certificate produced by ACME bootstrap is used for TLS automatically.
When neither is configured, the server runs on plain HTTP.

*cert_file* = _path_
	Path to the server TLS certificate PEM (leaf + intermediates).

*key_file* = _path_
	Path to the server TLS private key PEM.

# [signing_key]

Configuration for the key used to produce *SubtreeSignature* responses.
This key is distinct from any TLS key.  Its public half MUST match the
public key embedded in the cosigner-id certificate.

*key_file* = _path_
	Path to the signing key PEM.  If the file does not exist at startup,
	it is generated automatically using *key_type* and written here.
	Required (the field must be present even if the file will be
	auto-generated).

*key_type* = _type_
	Key algorithm.  Accepted values use the same format as the akamu
	server *[ca].key_type*:

	*"ec:P-256"* (default)
		ECDSA with NIST P-256.

	*"ec:P-384"*
		ECDSA with NIST P-384.

	*"ed25519"*
		Ed25519 (*hash_alg* is ignored).

	*"rsa:2048"*, *"rsa:3072"*, *"rsa:4096"*
		RSA with the specified bit length.

*hash_alg* = _alg_
	Hash algorithm for ECDSA/RSA signatures.  Ignored for EdDSA and
	ML-DSA key types.  Default: *"sha256"*.  Other accepted values:
	*"sha384"*, *"sha512"*.

# [cosigner_id]

The cosigner identity certificate.  The issuer and serial from this
certificate are embedded in every *SubtreeSignature.cosigner* field so
that relying parties can match the signature back to a trusted cosigner.

*cert_file* = _path_
	Path to the cosigner identity certificate PEM.  If the file is absent
	at startup and *[acme_bootstrap]* is not configured, a self-signed
	certificate is generated using the signing key and written here.  It
	has 10-year validity, a CN of *akamu-cosigner*, and a dNSName SAN
	derived from *[server].base_url*.

	When *[acme_bootstrap]* is configured and the path named here does
	not exist on disk, the certificate issued by ACME bootstrap is used
	as the cosigner-id source automatically.

	Required (the field must be present even if the file will be
	auto-generated or superseded by ACME bootstrap).

# [acme_bootstrap]

Optional.  When present, *akamu-cosigner* uses *akamu-client* to obtain
a certificate from the configured ACME server on startup if the
certificate file is absent or expiring within 30 days.

The issued certificate is stored at *cert_file* / *key_file* and is then
used automatically as the TLS server certificate (unless *[tls]* is also
configured, in which case *[tls].cert_file* / *[tls].key_file* take
priority) and as the cosigner-id source (unless *[cosigner_id].cert_file*
already exists on disk).

*server_url* = _url_
	ACME server directory URL
	(e.g. *"https://acme.example.com/directory"*).  Required.

*account_email* = _email_
	Contact e-mail for the ACME account.  The *mailto:* prefix is added
	automatically.  Optional.

*eab_kid* = _kid_
	External Account Binding (EAB) key identifier as provisioned by the
	CA.  Required when the ACME server mandates EAB.

*eab_hmac* = _key_
	EAB HMAC key, base64url-encoded (no padding).  Required when the
	ACME server mandates EAB.

*domain* = _fqdn_
	DNS name to certify.  Must be publicly resolvable for the chosen
	challenge type.  Required.

*challenge_type* = _type_
	ACME challenge type.  One of:

	*"http-01"* (default)
		HTTP challenge.  The cosigner serves challenge responses on
		*GET /.well-known/acme-challenge/:token* using its own HTTP
		listener.

	*"dns-01"*
		DNS TXT challenge.  If *dns_hook* is set it is invoked to
		provision the record; otherwise the TXT value is logged and
		an operator must set it manually.

	*"dns-persist-01"*
		Persistent DNS challenge (draft-ietf-acme-dns-persist).  If
		*dns_persist_hook* is set it is invoked; otherwise the record
		details are logged for manual provisioning.

	*"tls-alpn-01"*
		TLS-ALPN challenge.

*dns_hook* = _command_
	Shell command invoked for *dns-01* DNS record provisioning.
	The command is executed with the following environment variables set:

	*ACME_DOMAIN*
		The domain being validated.

	*ACME_TXT_VALUE*
		The TXT record value to publish.

	Exit 0 indicates the record was provisioned successfully.  If absent,
	the TXT value is written to the log and an operator must set the
	record manually.

*dns_persist_hook* = _command_
	Shell command invoked for *dns-persist-01* DNS record provisioning.
	The command is executed with the following environment variables set:

	*ACME_DOMAIN*
		The domain being validated.

	*ACME_TXT_NAME*
		The full DNS TXT record name to publish
		(the validation-persist label prepended to the domain).

	*ACME_TXT_VALUE*
		The TXT record value (e.g. "<issuer>; accounturi=<uri>").

	*ACME_ACCOUNT_URI*
		The ACME account URI.

	*ACME_ISSUER_DOMAIN*
		The ACME issuer domain.

	Exit 0 indicates success.

*cert_file* = _path_
	Output path for the issued certificate PEM chain.  Required.

*key_file* = _path_
	Output path for the private key PEM for the issued certificate.
	Required.

*csr_key_type* = _type_
	Key type for the ACME CSR key.  Same values as *[signing_key].key_type*.
	Default: *"ec:P-256"*.

# [admin]

Optional.  When present, the cosigner exposes a REST administration API
that *akamuctl cosigner* commands use.

*listen_addr* = _addr_
	Separate listener address for the admin API (e.g.
	*"127.0.0.1:9444"*).  Required within this section.

*cert_file* = _path_
	TLS certificate PEM for the admin listener.  Required within this
	section.

*key_file* = _path_
	TLS private key PEM for the admin listener.  Required within this
	section.

*ca_certs* = [_path_, ...]
	List of CA certificate file paths trusted for operator mTLS client
	certificates.  Used to verify client certificates presented by
	*akamuctl cosigner login*.

*session_ttl_secs* = _seconds_
	Session token lifetime in seconds.  After this period the session
	expires and the operator must re-authenticate.  Default: *3600*.

## [[admin.operators]]

Zero or more inline operator entries.  At least one of *cert_fingerprint*
or *gssapi_principal* must be supplied per entry.

*name* = _string_
	Display name for this operator.

*role* = _role_
	Access role.  One of:

	*"administrator"*
		Full read/write access to the admin API.

	*"auditor"*
		Read-only access to status and statistics endpoints.

*cert_fingerprint* = _hex_
	SHA-256 fingerprint of the operator's client certificate DER leaf,
	hex-encoded without separators.  Used for mTLS client certificate
	authentication.

*gssapi_principal* = _principal_
	Kerberos principal (e.g. *"alice@REALM"*) for GSSAPI/Negotiate
	authentication.

# EXAMPLES

Minimal configuration with a pre-provisioned certificate:

```
[server]
listen_addr = "0.0.0.0:8444"
base_url    = "https://cosigner.example.com:8444"

[tls]
cert_file = "/etc/akamu-cosigner/tls.pem"
key_file  = "/etc/akamu-cosigner/tls.key"

[signing_key]
key_file = "/var/lib/akamu-cosigner/signing.key"
key_type = "ec:P-256"

[cosigner_id]
cert_file = "/etc/akamu-cosigner/cosigner-id.pem"
```

Configuration with ACME bootstrap and an admin API:

```
[server]
listen_addr = "0.0.0.0:8444"
base_url    = "https://cosigner.example.com:8444"

[signing_key]
key_file = "/var/lib/akamu-cosigner/signing.key"
key_type = "ec:P-256"

[cosigner_id]
cert_file = "/var/lib/akamu-cosigner/cosigner-id.pem"

[acme_bootstrap]
server_url    = "https://acme.example.com/directory"
domain        = "cosigner.example.com"
challenge_type = "http-01"
eab_kid       = "my-kid"
eab_hmac      = "base64url-hmac-key"
cert_file     = "/var/lib/akamu-cosigner/acme.pem"
key_file      = "/var/lib/akamu-cosigner/acme.key"

[admin]
listen_addr = "127.0.0.1:9444"
cert_file   = "/etc/akamu-cosigner/admin-tls.pem"
key_file    = "/etc/akamu-cosigner/admin-tls.key"
ca_certs    = ["/etc/akamu-cosigner/operator-ca.pem"]

[[admin.operators]]
name             = "alice"
role             = "administrator"
gssapi_principal = "alice@EXAMPLE.COM"
```

# SEE ALSO

*akamu-cosigner*(8), *akamu*(8), *akamu.conf*(5), *akamuctl*(1)

RFC 8555 - Automatic Certificate Management Environment (ACME)++
RFC 9162 - Certificate Transparency Version 2.0++
draft-ietf-plants-merkle-tree-certs - Merkle Tree Certificates for TLS++
RFC 9964 - ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)

# AUTHORS

The akamu project contributors.
