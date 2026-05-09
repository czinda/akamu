# Akāmu sample configurations

Each file in this directory is a self-contained, focused configuration example
for a specific deployment scenario.  Every file includes the four required
sections (`listen_addr`, `base_url`, `[database]`, `[ca]`) plus only the
options relevant to its scenario.

Start with the file closest to your use case and merge sections as needed.
The full reference with every option and its default is `config.toml.example`
at the repository root.

## Index

| File | Scenario | Key options |
|------|----------|-------------|
| [minimal.toml](minimal.toml) | Quick-start, bare minimum | SQLite, auto-generated CA |
| [development.toml](development.toml) | Local integration testing | Private IPs allowed, DNSSEC off, short validity |
| [production-postgres.toml](production-postgres.toml) | Hardened public CA | PostgreSQL, encrypted key, validity cap, CAA |
| [tls-native.toml](tls-native.toml) | Akāmu terminates TLS | `[tls]` with external cert/key |
| [tls-mutual.toml](tls-mutual.toml) | ACME clients need a client cert | `[tls.client_auth]` required |
| [eab-static.toml](eab-static.toml) | Fixed set of pre-provisioned EAB keys | `[server.eab_keys]` table |
| [eab-hkdf.toml](eab-hkdf.toml) | Dynamic EAB keys derived at runtime | `eab_master_secret` |
| [kerberos-standalone.toml](kerberos-standalone.toml) | Akāmu handles SPNEGO directly | `[server.gssapi]` |
| [kerberos-proxy.toml](kerberos-proxy.toml) | Kerberos via reverse proxy | `trusted_proxies` |
| [admin-mtls.toml](admin-mtls.toml) | Admin API with operator client certs | `[tls.client_auth]` + `ca_files` |
| [admin-kerberos.toml](admin-kerberos.toml) | Admin API with Kerberos auth | `[admin.gssapi]` |
| [admin-audit.toml](admin-audit.toml) | Strict audit logging and alarms | `audit_overflow`, `audit_alarm_*` |
| [profiles-builtin.toml](profiles-builtin.toml) | Inline certificate profiles | `[profiles.providers.local]` |
| [profiles-ipa.toml](profiles-ipa.toml) | FreeIPA / IPAThinCA profiles | `[profiles.providers.ipa]` + GSSAPI LDAP |
| [profiles-dogtag.toml](profiles-dogtag.toml) | Dogtag PKI profiles from filesystem | `[profiles.providers.dogtag]` |
| [revocation.toml](revocation.toml) | Built-in CRL and OCSP endpoints | `crl_url`, `ocsp_url` |
| [star.toml](star.toml) | Short-Term Automatic Renewal (RFC 8739) | `star_*` options |
| [ari.toml](ari.toml) | Renewal Information hints (RFC 9773) | `ari_retry_after_secs`, `ari_explanation_url` |
| [hsm.toml](hsm.toml) | CA key in hardware security module | PKCS#11 URI as `key_file` |
| [mtc.toml](mtc.toml) | Merkle Tree Certificate transparency log | `[mtc]` + `[mtc.signing_key]` |
| [mtc-cosigner.toml](mtc-cosigner.toml) | MTC with external cosigners | `[[mtc.cosigners]]` |
| [dns-dot.toml](dns-dot.toml) | DNS-over-TLS for validation queries | `dns_dot_server_name` |
| [dns-persist.toml](dns-persist.toml) | dns-persist-01 challenge | `dns_persist_issuer_domains` |
| [subdomain-auth.toml](subdomain-auth.toml) | RFC 9444 subdomain authorization | `allow_subdomain_auth` |
| [tor-onion.toml](tor-onion.toml) | Certificates for .onion identifiers (RFC 9799) | `tor_connectivity_enabled` |
| [smime-email.toml](smime-email.toml) | S/MIME email certificates (RFC 8823) | `[email_challenge]`, `email-reply-00` |
| [delegation.toml](delegation.toml) | RFC 9115 delegated certificates (IdO + upstream CA) | `delegation_enabled`, `[delegation_upstream]` |
| [post-quantum.toml](post-quantum.toml) | ML-DSA post-quantum CA and profiles | `key_type = "ml-dsa-65"` |
| [multi-ca.toml](multi-ca.toml) | Multiple CA instances (RSA + EC) | `[[ca]]`, `account_scope`, `ca_ids` |

## Further reading

- Full configuration reference: `docs/src/user/configuration.md`
- Challenge types: `docs/src/user/challenges.md`
- TLS deployment modes: `docs/src/user/tls.md`
- Certificate profiles: `docs/src/user/profiles.md`
- GSSAPI / Kerberos: `docs/src/user/eab-kerberos.md`
- CRL and OCSP: `docs/src/user/crl-ocsp.md`
- Merkle Tree Certificates: `docs/src/user/mtc.md`
- Admin API: `docs/src/user/admin-api.md`
