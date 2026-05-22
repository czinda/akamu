AKAMU-COSIGNER(8) "akamu" "System Administration"

# NAME

akamu-cosigner - MTC cosigner daemon for akamu Merkle Tree Certificates

# SYNOPSIS

*akamu-cosigner* [_config-file_]

# DESCRIPTION

*akamu-cosigner* is a standalone daemon that co-signs Merkle Tree
Certificate (MTC) checkpoints produced by an *akamu*(8) server.
Co-signing allows independent parties to attest to the correctness of
an MTC transparency log, following the MTC draft specification.

The cosigner accepts HTTP *POST /sign* requests carrying a DER-encoded
*Checkpoint* from the akamu server, verifies its structure, and returns
a DER-encoded *SubtreeSignature* covering the full checkpoint range
*[0, tree_size)*.  The signature is computed over a TLS-encoded
*CosignedMessage* (MTC spec §5.4.1) using the configured signing key.

The akamu server refers to cosigners through the *[[mtc.cosigners]]*
array in its own server configuration.  Each entry supplies the cosigner
URL and the trust anchor used to verify that cosigner's TLS certificate.
Multiple cosigners can be configured on a single akamu server.

*akamu-cosigner* can obtain its identity certificate from an ACME server
automatically at startup using *akamu-client* (configured via the
*[acme_bootstrap]* section), or it can be pointed at a pre-provisioned
certificate via *[cosigner_id]*.  When neither ACME bootstrap nor a
pre-existing file is found, a self-signed certificate is generated
automatically and written to *[cosigner_id].cert_file*.

An administration REST API (when configured via *[admin]*) lets
operators query status and statistics using *akamuctl cosigner*.

# ARGUMENTS

_config-file_
	Path to the TOML configuration file.  Defaults to *cosigner.toml*
	in the current working directory.  When running under systemd the
	unit file passes */etc/akamu-cosigner/cosigner.toml*.

# CONFIGURATION FILE

The configuration file is a TOML document.  See *akamu-cosigner.conf*(5)
for the complete reference.

# SIGNING ENDPOINT

*POST /sign*

The primary cosigner endpoint called by the *akamu*(8) server at each
batch issuance cycle.

*Request body*
	DER-encoded *Checkpoint* (Content-Type: *application/octet-stream*).
	The *tree_size* field must be greater than zero.

*Response (200 OK)*
	DER-encoded *SubtreeSignature* (Content-Type: *application/octet-stream*).
	The signature covers the full checkpoint range *[0, tree_size)*.

*Error responses*
	*400 Bad Request* — malformed or zero-size Checkpoint.
	*500 Internal Server Error* — signing failure; details in server log.

The cosigner signs a TLS-encoded *CosignedMessage* structure (MTC spec
§5.4.1) using the key from *[signing_key]* and returns the resulting
*SubtreeSignature* whose *cosigner* field is populated from the identity
certificate at *[cosigner_id].cert_file*.

# ADMIN API

When *[admin]* is configured the following endpoints are available on
the admin listener.  All admin endpoints require a valid session token
obtained via *POST /admin/session* (equivalent to *akamuctl cosigner login*).

*POST /admin/session*
	Authenticate and obtain a session token.  Accepts mTLS client
	certificate or GSSAPI/Negotiate credentials.

*DELETE /admin/session*
	Invalidate the current session token.

*GET /admin/status*
	Liveness and identity information.

*GET /admin/stats*
	Signing statistics: total signatures issued, timestamp of the most
	recent signature, and daemon uptime.

*GET /admin/config*
	Redacted runtime configuration.  Requires the *administrator* role.

# ENVIRONMENT

*RUST_LOG*
	Log filter directive (tracing-subscriber format).  Default: *info*.
	Example: *RUST_LOG=akamu_cosigner=debug,info*.

*AKAMU_COSIGNER_LISTEN*
	Overrides *[server].listen_addr* in the configuration file.  Accepts
	the same syntax: *host:port* for TCP or *unix:/path* for a Unix
	domain socket.

# FILES

*/etc/akamu-cosigner/cosigner.toml*
	Main configuration file read by the systemd unit.

*/var/lib/akamu-cosigner/*
	State directory for the cosigner daemon (mode 0750,
	owner akamu-cosigner:akamu-cosigner).

*/var/lib/akamu-cosigner/signing.key.pem*
	Default path for the auto-generated signing key when
	*[signing_key].key_file* points here.

*/var/lib/akamu-cosigner/cosigner-id.cert.pem*
	Default path for the auto-generated or ACME-issued cosigner identity
	certificate when *[cosigner_id].cert_file* points here.

*/var/lib/akamu-cosigner/acme.cert.pem*, */var/lib/akamu-cosigner/acme.key.pem*
	Default output paths for the ACME-issued certificate and key when
	*[acme_bootstrap].cert_file* / *[acme_bootstrap].key_file* point here.

# SIGNALS

*SIGTERM*, *SIGINT*
	Graceful shutdown.

# EXIT STATUS

*0*	Clean shutdown.

*1*	Fatal startup error.  Details are written to the log.

# EXAMPLES

Start the cosigner with a non-default configuration file:

```
akamu-cosigner /etc/akamu-cosigner/my-cosigner.toml
```

Minimal configuration with a pre-provisioned certificate and key:

```
[server]
listen_addr = "0.0.0.0:8444"
base_url    = "https://cosigner.example.com:8444"

[tls]
cert_file = "/etc/akamu-cosigner/tls.cert.pem"
key_file  = "/etc/akamu-cosigner/tls.key.pem"

[signing_key]
key_file = "/var/lib/akamu-cosigner/signing.key.pem"
key_type = "ec:P-256"
hash_alg = "sha256"

[cosigner_id]
cert_file = "/etc/akamu-cosigner/cosigner-id.cert.pem"
```

Configuration using ACME bootstrap (certificate auto-provisioned on
first start; TLS and cosigner-id are both taken from the ACME cert):

```
[server]
listen_addr = "0.0.0.0:8444"
base_url    = "https://cosigner.example.com:8444"

[signing_key]
key_file = "/var/lib/akamu-cosigner/signing.key.pem"

[cosigner_id]
cert_file = "/var/lib/akamu-cosigner/cosigner-id.cert.pem"

[acme_bootstrap]
server_url    = "https://acme.example.com/directory"
account_email = "admin@example.com"
eab_kid       = "xxxxxxxxxxxxxxxx"
eab_hmac      = "base64url-encoded-hmac-key"
domain        = "cosigner.example.com"
challenge_type = "http-01"
cert_file     = "/var/lib/akamu-cosigner/acme.cert.pem"
key_file      = "/var/lib/akamu-cosigner/acme.key.pem"

[admin]
listen_addr = "127.0.0.1:9444"
cert_file   = "/etc/akamu-cosigner/admin-tls.cert.pem"
key_file    = "/etc/akamu-cosigner/admin-tls.key.pem"
ca_certs    = ["/etc/akamu-cosigner/operator-ca.cert.pem"]

[[admin.operators]]
name             = "alice"
role             = "administrator"
cert_fingerprint = "aabbcc..."

[[admin.operators]]
name              = "bob"
role              = "auditor"
gssapi_principal  = "bob@EXAMPLE.COM"
```

# SEE ALSO

*akamu*(8), *akamuctl*(1), *akamu-cli*(1),
*akamu-cosigner.conf*(5)

RFC 8555 - Automatic Certificate Management Environment (ACME)++
RFC 9162 - Certificate Transparency Version 2.0++
draft-ietf-plants-merkle-tree-certs - Merkle Tree Certificates for TLS++
RFC 9964 - ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)

# AUTHORS

The akamu project contributors.
