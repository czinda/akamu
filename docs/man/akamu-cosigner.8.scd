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

The cosigner receives a DER-encoded *Checkpoint* via HTTP POST from the
akamu server, verifies it, and returns a DER-encoded *SubtreeSignature*.
Multiple cosigners can be configured on a single akamu server.

The cosigner can obtain its identity certificate from an ACME server
automatically at startup using *akamu-client* (the *[acme_bootstrap]*
configuration section), or it can be pointed at a pre-provisioned
certificate.

An administration REST API (when configured via *[admin]*) lets
operators query status and statistics using *akamuctl cosigner*.

# ARGUMENTS

_config-file_
	Path to the TOML configuration file.  Defaults to *cosigner.toml*
	in the current working directory.  When running under systemd the
	unit file passes */etc/akamu-cosigner/cosigner.toml*.

# ENVIRONMENT

*RUST_LOG*
	Log filter directive (tracing-subscriber format).
	Default: *info*.

# FILES

*/etc/akamu-cosigner/cosigner.toml*
	Main configuration file read by the systemd unit.

*/var/lib/akamu-cosigner/*
	State directory for the cosigner daemon (mode 0750,
	owner akamu-cosigner:akamu-cosigner).

# SIGNALS

*SIGTERM*, *SIGINT*
	Graceful shutdown.

# EXIT STATUS

*0*	Clean shutdown.

*1*	Fatal startup error.  Details are written to the log.

# EXAMPLES

Start the cosigner with a non-default configuration file:

	akamu-cosigner /etc/akamu-cosigner/my-cosigner.toml

# CONFIGURATION FILE

The configuration file is a TOML document.  The unit file passes
*/etc/akamu-cosigner/cosigner.toml*.

## listen_addr

*listen_addr* = _addr_
	Address the cosigner daemon binds to.  Two forms are accepted:

	_host:port_ (e.g. *127.0.0.1:8444*)
		TCP listener.

	*unix:*_/path/to/socket_ (e.g. *unix:/run/akamu-cosigner/cosigner.sock*)
		Unix domain socket listener.  Use this when akamu and
		akamu-cosigner run on the same host and you want to avoid an
		exposed TCP port.  When running under systemd with
		*akamu-cosigner.socket*, the socket is inherited via *LISTEN_FDS*.

# SEE ALSO

*akamu*(8), *akamuctl*(1)

MTC draft — Merkle Tree Certificates for TLS

# AUTHORS

The akamu project contributors.
