# Client Library Internals

This page documents the internal design of `akamu-client` and the `akamu-cli`
command-line tool: the `DnsHookSolver`, the `RenewalConfig` type contract,
`AccountKey::from_jwk_private`, and the certbot migration internals.

For the user-facing command reference, see [akamu-cli — Command Reference](../client/cli.md).

## Source layout

| File | Contents |
|------|----------|
| `crates/akamu-client/src/account.rs` | `AccountKey`, `Account`, key generation, `alg_for_key`, `jwk_private_to_backend_key` |
| `crates/akamu-client/src/challenge.rs` | `ChallengeSolver` trait, `Http01Solver`, `TlsAlpn01Solver`, `Dns01Helper`, `DnsPersist01Helper`, `DnsHookSolver` |
| `crates/akamu-client/src/client.rs` | `AcmeClient` — directory-aware async HTTP client with nonce management |
| `crates/akamu-client/src/csr.rs` | `build_csr` — DER-encoded CSR construction |
| `crates/akamu-client/src/eab.rs` | `create_eab_jws` — client-side EAB JWS construction (RFC 8555 §7.3.4) |
| `crates/akamu-client/src/error.rs` | `ClientError` — unified error type |
| `crates/akamu-client/src/gssapi_eab.rs` | `fetch_eab_via_gssapi`, `GssapiEabResult` — GSSAPI-authenticated EAB credential fetch |
| `crates/akamu-client/src/mtc_client.rs` | `MtcClient` — async HTTP client for querying an MTC transparency log server |
| `crates/akamu-client/src/mtc_verify.rs` | MTC standalone certificate verification: parsing, leaf hashing, inclusion proof checks (`CertDetails`, `ExtensionDetail`) |
| `crates/akamu-client/src/mtc_types.rs` | MTC response types: `TreeSizeResponse`, `RootResponse`, `InclusionProofResponse`, `CertFetchResult`, etc. |
| `crates/akamu-client/src/onion.rs` | `build_onion_csr` — DER-encoded CSR for onion-csr-01 challenges (RFC 9799) |
| `crates/akamu-client/src/types.rs` | `Identifier`, `Order`, `Authorization`, `Challenge`, `RenewalConfig`, `AccountOptions`, `EabOptions`, `StarOrderParams`, `StarOrder`, `RenewalInfo` |
| `crates/akamu-cli/src/import/certbot.rs` | `discover_accounts`, `discover_renewals`, `jwk_to_account_key`, `map_challenge_type`, `build_renewal_config`, `live_cert_paths` |

---

## AccountKey

`AccountKey` is the central type that owns an account's private key and its
pre-computed derivative values.  The struct holds four fields:

```rust
pub struct AccountKey {
    priv_key:   BackendPrivateKey,   // synta-certificate private key handle
    pub_jwk:    JwkPublic,           // pre-computed public JWK (from akamu-jose)
    thumbprint: String,              // pre-computed RFC 7638 thumbprint (base64url)
    alg:        &'static str,        // JWS alg string ("ES256", "EdDSA", "ML-DSA-65", …)
}
```

All four values are computed once inside `AccountKey::from_backend_key` and
then stored.  All subsequent callers (sign requests, key-authorization
computation, EAB payload) read from cache without re-deriving.

### Key generation

`AccountKey::generate(key_type)` dispatches to `generate_backend_key`, which
calls the corresponding `BackendPrivateKey::generate_*` function:

| `key_type` string | Function called |
|---|---|
| `"ec:P-256"` (or `"P-256"`) | `BackendPrivateKey::generate_ec("P-256")` |
| `"ec:P-384"` (or `"P-384"`) | `BackendPrivateKey::generate_ec("P-384")` |
| `"ec:P-521"` (or `"P-521"`) | `BackendPrivateKey::generate_ec("P-521")` |
| `"rsa:2048"` (or `"rsa2048"`) | `BackendPrivateKey::generate_rsa(2048, 65537)` |
| `"rsa:3072"` (or `"rsa3072"`) | `BackendPrivateKey::generate_rsa(3072, 65537)` |
| `"rsa:4096"` (or `"rsa4096"`) | `BackendPrivateKey::generate_rsa(4096, 65537)` |
| `"ed25519"` | `BackendPrivateKey::generate_ed25519()` |
| `"ed448"` | `BackendPrivateKey::generate_ed448()` |
| `"ml-dsa-44"` (or `"ML-DSA-44"`) | `BackendPrivateKey::generate_ml_dsa("ML-DSA-44")` |
| `"ml-dsa-65"` (or `"ML-DSA-65"`) | `BackendPrivateKey::generate_ml_dsa("ML-DSA-65")` |
| `"ml-dsa-87"` (or `"ML-DSA-87"`) | `BackendPrivateKey::generate_ml_dsa("ML-DSA-87")` |

Any other string returns `ClientError::Crypto`.

### `alg_for_key` — JWS algorithm detection

`alg_for_key` derives the JWS `alg` string from the key material.  It queries
the public key's `key_type()` string and branches:

- `"ec"` — calls `pub_key.ec_curve_name()` to get the curve name and maps
  `"P-256"` / `"prime256v1"` → `"ES256"`, `"P-384"` / `"secp384r1"` → `"ES384"`,
  `"P-521"` / `"secp521r1"` → `"ES512"`.
- `"rsa"` — always returns `"PS256"` (RSA-PSS with SHA-256).
- `"ed25519"` or `"ed448"` — returns `"EdDSA"`.
- Anything else — inspects the raw SPKI DER to detect ML-DSA.

**ML-DSA SPKI OID detection.**  The FIPS 204 OIDs share a common prefix of
eight bytes at offset 8 of the DER-encoded SPKI:

```
60 86 48 01 65 03 04 03
```

The byte at offset 16 distinguishes the parameter set:

| Byte at offset 16 | Algorithm |
|---|---|
| `0x11` | ML-DSA-44 |
| `0x12` | ML-DSA-65 |
| `0x13` | ML-DSA-87 |

Any other value returns `ClientError::Crypto`.

---

## `AccountKey::from_jwk_private`

Builds an `AccountKey` from a raw private JWK JSON string — the format used
by certbot's `accounts/…/private_key.json`.  Supports EC (P-256, P-384,
P-521) and RSA.  The entry point is:

```rust
pub fn from_jwk_private(json: &str) -> Result<Self, ClientError>
```

The implementation calls `jwk_private_to_backend_key(json)`, which:

1. Parses `json` as `serde_json::Value`.
2. Reads `kty` (case-insensitive, uppercased for matching).
3. **EC path** (`"EC"`):
   - Reads `crv` → maps `"P-256"` / `"P-384"` / `"P-521"` to the curve string.
   - Decodes `d`, `x`, `y` from base64url-no-padding.
   - Calls `BackendPrivateKey::from_ec_private_scalar(&d, &x, &y, curve)`.
4. **RSA path** (`"RSA"`):
   - Decodes all eight CRT components from base64url-no-padding:
     `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`.
   - Constructs `synta_certificate::RsaPrivateComponents { n, e, d, p, q, dp, dq, qi }`.
   - Calls `BackendPrivateKey::from_rsa_private_components(&components)`.
5. Any other `kty` returns `Err("unsupported JWK kty: …")`.

After constructing the `BackendPrivateKey`, `from_backend_key` runs the same
path as `generate`: derives the public JWK, computes the thumbprint, and
determines the JWS `alg` string.

---

## ChallengeSolver trait

```rust
pub trait ChallengeSolver: Send + Sync {
    fn present(
        &self,
        token: &str,
        key_auth: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + '_>>;

    fn cleanup(
        &self,
        token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + '_>>;
}
```

`present` is called before the ACME client triggers the challenge.
`cleanup` is called after the challenge completes (success or failure).
Both methods return boxed futures to allow `dyn` dispatch across the async
boundary without requiring `async_trait`.

---

## Http01Solver

`Http01Solver` binds a minimal HTTP/1.1 server and serves
`/.well-known/acme-challenge/<token>` responses.

**Internal design:**

- Token storage is `Arc<RwLock<HashMap<String, String>>>` (token → key_auth).
- `start()` binds `0.0.0.0:<port>` with `TcpListener`, then spawns a
  background accept loop with `tokio::spawn`.  Each accepted connection
  gets its own `tokio::spawn` running `hyper::server::conn::http1::Builder`.
- `present(token, key_auth)` writes to the `RwLock` under a write guard.
- `cleanup(token)` removes the entry under a write guard.
- `handle_challenge` strips the `/.well-known/acme-challenge/` prefix and
  returns the stored value with HTTP 200, or HTTP 404 for any other path.
- All responses use `http_body_util::Full<Bytes>`.

---

## TlsAlpn01Solver

`TlsAlpn01Solver` serves ephemeral ACME challenge certificates for
tls-alpn-01 (RFC 8737).

**Internal design:**

- Certificate storage is `Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>` (domain → certified key).
- `start()` creates a `rustls::ServerConfig` using the `rustls-native-ossl` provider,
  sets `alpn_protocols = vec![b"acme-tls/1"]`, and spawns a
  `tokio_rustls::TlsAcceptor` accept loop.  The `JoinHandle` is stored in
  `self.handle`.
- `present(domain, id_type, key_auth)` performs all certificate construction:
  1. Computes `SHA-256(key_auth)` to get a 32-byte hash.
  2. Encodes the `id-pe-acmeIdentifier` extension as an `OCTET STRING` containing
     the hash, then wraps it in `synta_certificate::acme_types::Authorization`
     to produce the DER extension value.
  3. Generates an ephemeral EC P-256 key with `BackendPrivateKey::generate_ec`.
  4. Builds a self-signed certificate using `synta_certificate::CertificateBuilder`
     with a 7-day validity window, the domain as CN, and the `id-pe-acmeIdentifier`
     extension marked critical.  For `id_type == "ip"` the SAN is `iPAddress`;
     otherwise `dNSName`.
  5. Loads the key into rustls via `rustls_native_ossl::default_provider().key_provider.load_private_key`.
  6. Inserts the `rustls::sign::CertifiedKey` into the SNI store under the domain name.
- `SniResolver` implements `rustls::server::ResolvesServerCert` by looking up
  `client_hello.server_name()` in the store.
- `cleanup()` aborts the background `JoinHandle`.

---

## Dns01Helper and DnsPersist01Helper

`Dns01Helper` exposes one static method:

```rust
pub fn txt_value(key_auth: &str) -> Result<String, ClientError>
```

This returns `base64url(SHA-256(key_auth))`.  The computation is done by
`dns_txt_value` in `account.rs`, which calls
`synta_certificate::default_data_hasher().hash_data("sha256",
key_auth.as_bytes())` and base64url-encodes the result.

`DnsPersist01Helper` is a different design — it does **not** hash the key
authorization.  Instead, it builds the structured TXT record content
specified by `draft-ietf-acme-dns-persist`.  It exposes two static methods:

```rust
// Non-wildcard: placed at _validation-persist.<domain>
pub fn txt_record(issuer_domain: &str, account_url: &str) -> String
// Returns: "<issuer_domain>; accounturi=<account_url>"

// Wildcard / subdomain coverage:
pub fn txt_record_wildcard(issuer_domain: &str, account_url: &str) -> String
// Returns: "<issuer_domain>; accounturi=<account_url>; policy=wildcard"
```

`issuer_domain` is taken from the `issuer-domain-names` array in the
server's challenge object.  `account_url` is the ACME account URL returned
at registration time.

Unlike dns-01, the dns-persist-01 record is long-lived; it is provisioned
once and left in place — there is no cleanup call.

---

## DnsHookSolver

`DnsHookSolver` implements DNS-01 and dns-persist-01 TXT record management
by delegating to an external hook script.  The hook is never used for
http-01 or tls-alpn-01.

**Struct:**

```rust
pub struct DnsHookSolver {
    hook: String,   // path or shell command
}
```

**Hook invocation — `run_hook`:**

```rust
let output = tokio::process::Command::new(&self.hook)
    .arg(operation)               // "add" or "remove"
    .env("AKAMU_DOMAIN",   domain)
    .env("AKAMU_TOKEN",    token)
    .env("AKAMU_TXT",      &txt)  // base64url(SHA-256(key_auth))
    .env("AKAMU_KEY_AUTH", key_auth)
    .output()
    .await?;
```

Values are passed exclusively via environment variables, not command-line
arguments, to avoid leaking secrets through `/proc/<pid>/cmdline`.

**Environment variables:**

| Variable | Value |
|---|---|
| `AKAMU_DOMAIN` | DNS name being validated |
| `AKAMU_TOKEN` | ACME challenge token |
| `AKAMU_TXT` | `base64url(SHA-256(key_authorization))` |
| `AKAMU_KEY_AUTH` | Full key authorization string (`{token}.{thumbprint}`) |

**Exit code semantics:**  exit code 0 is success.  Any non-zero exit code
produces `ClientError::Crypto` with the captured stderr included in the
message.

**Public API:**

- `deploy(domain, token, key_auth)` — calls `run_hook("add", …)` for dns-01.
- `clean(domain, token, key_auth)` — calls `run_hook("remove", …)` for dns-01.
- `deploy_persist(domain, txt_record)` — for dns-persist-01: invokes the hook
  with `add` and passes only `AKAMU_DOMAIN` and `AKAMU_TXT` (the full
  structured record content built by `DnsPersist01Helper`).  There is no
  corresponding `clean` for dns-persist-01 because the record is long-lived.

**Environment variables for dns-persist-01 (`deploy_persist`):**

| Variable | Value |
|---|---|
| `AKAMU_DOMAIN` | DNS name being validated |
| `AKAMU_TXT` | Full TXT record content (`"issuer; accounturi=…[; policy=wildcard]"`) |

`DnsHookSolver` does not implement the `ChallengeSolver` trait directly
because the trait's `present`/`cleanup` signatures do not carry the domain
name.  Callers use `deploy`, `clean`, and `deploy_persist` explicitly.

---

## `fetch_eab_via_gssapi` (`gssapi_eab.rs`)

`fetch_eab_via_gssapi` performs a one-shot authenticated GET to the server's
`/acme/eab` endpoint using a Kerberos keytab and returns the EAB credentials
ready for use in a `newAccount` request.

### Public types

```rust
pub struct GssapiEabResult {
    pub principal: String,       // e.g. "host/client.example.com@REALM"
    pub kid:       Option<String>, // present when eab_master_secret is configured
    pub hmac_key:  Option<String>, // base64url-encoded HMAC key
    pub alg:       Option<String>, // e.g. "HS256"
}

pub async fn fetch_eab_via_gssapi(
    eab_url:      &str,
    keytab_file:  &str,
) -> Result<GssapiEabResult, ClientError>
```

### Internal steps

1. Calls `GssClientCred::from_keytab(keytab_file)` (from `akamu-gssapi`) to
   load the initiator credential from the keytab.
2. Calls `derive_service_name(eab_url)` to compute the target SPN as
   `HTTP@<hostname>` by stripping the URL scheme, port, and path.
3. Calls `akamu_gssapi::init_token(&cred, &target, None)` inside
   `tokio::task::spawn_blocking` to avoid blocking the async executor on the
   `gss_init_sec_context` FFI call.
4. Base64-encodes the resulting token and sends a single GET request with
   `Authorization: Negotiate <base64-token>`.
5. Parses the JSON response into `GssapiEabResult`.

Note: this function performs a **single** GSSAPI step (no multi-round-trip
loop).  Kerberos AP-REQ exchanges are typically single-round-trip, so one
step is sufficient.  Multi-round-trip SPNEGO is handled by
`AdminClient::session_token` in `akamuctl` for the admin API path.

### `derive_service_name`

A private helper that strips the URL scheme (`https://` or `http://`), path,
and port from `eab_url` to extract the bare hostname, then returns
`HTTP@<hostname>`.  Returns `ClientError::Http` when no non-empty host
component can be extracted.

---

## RenewalConfig

`RenewalConfig` is a `Serialize + Deserialize` struct that captures every
parameter needed to repeat a certificate issuance without user interaction.

**Fields and serde defaults:**

| Field | Type | Serde default | Notes |
|-------|------|---------------|-------|
| `server` | `String` | (required) | ACME directory URL (base URL or full per-CA directory URL) |
| `ca` | `Option<String>` | `None` | CA identifier for akamu multi-CA servers; derives directory URL as `{server}/acme/{ca}/directory`; ignored when `server` already ends in `/directory`; omitted from TOML when absent |
| `domains` | `Vec<Identifier>` | (required) | Identifiers to certify |
| `account_key` | `PathBuf` | (required) | Path to account private key PEM |
| `account_key_type` | `String` | `"ec:P-256"` | Key type string for account key |
| `cert_path` | `PathBuf` | (required) | Output path for certificate chain |
| `cert_key_path` | `PathBuf` | (required) | Output path for certificate private key |
| `cert_key_type` | `String` | `"ec:P-256"` | Key type string for certificate key |
| `challenge_type` | `String` | `"http-01"` | Challenge type |
| `http_port` | `u16` | `80` | Port for http-01 challenge server |
| `tls_port` | `u16` | `443` | Port for tls-alpn-01 challenge server |
| `onion_key` | `Option<PathBuf>` | `None` | Onion service private key path |
| `poll_timeout` | `u64` | `120` | Validation poll timeout in seconds |
| `contacts` | `Vec<String>` | `[]` | Contact URIs for account registration |
| `eab_kid` | `Option<String>` | `None` | EAB key identifier |
| `eab_key` | `Option<String>` | `None` | EAB HMAC key (base64url) |
| `eab_alg` | `String` | `"HS256"` | EAB HMAC algorithm |
| `gssapi_keytab` | `Option<PathBuf>` | `None` | Path to a Kerberos keytab for GSSAPI-authenticated EAB fetch; mutually exclusive with `eab_kid`/`eab_key` |
| `dns_hook` | `Option<String>` | `None` | DNS hook script path |

Fields with serde defaults use `#[serde(default = "defaults::…")]` pointing
to private free functions in the `defaults` module.  Fields without a default
must be present in the TOML file.

**TOML sidecar convention:**  `akamu-cli issue` writes the renewal config to
`<cert-path>.renewal.toml` (e.g. if `cert_path` is
`/etc/akamu/certs/example.com.pem`, the sidecar is
`/etc/akamu/certs/example.com.pem.renewal.toml`).  `akamu-cli renew
--renewal-config` reads this file.

**TOML round-trip:**  all field types must survive a `toml::to_string_pretty`
→ `toml::from_str` round-trip.  `Identifier` serializes as an inline table
`{ type = "dns", value = "example.com" }`.

---

## Certbot import internals

`crates/akamu-cli/src/import/certbot.rs` implements the `akamu-cli import
certbot` subcommand.

### Account directory structure

Certbot stores accounts under:

```
<certbot-dir>/accounts/<ca-hostname>/<account-id>/
    private_key.json   # raw private JWK
    regr.json          # registration response (contains uri and body.contact)
    meta.json          # metadata (contains creation_dt)
```

`discover_accounts` walks `accounts/` two levels deep.  For each account
directory it:

1. Reads `private_key.json` as a raw JWK JSON string.
2. Calls `parse_regr_json` to extract `uri` (the account URL) and
   `body.contact` (the contact list) from `regr.json`.
3. Calls `parse_meta_json` to extract `creation_dt` from `meta.json`.
4. Returns a `CertbotAccount` struct.

Any directory missing `private_key.json` is silently skipped.

### Renewal file structure

Certbot writes one `.conf` file per certificate to `<certbot-dir>/renewal/`.
The file name stem is the primary domain name (with wildcard encoding; see
below).

`discover_renewals` reads all `*.conf` files in the `renewal/` directory.
Each file is parsed by `parse_ini_flat`, which reads all `key = value` lines
from both the flat top section and the `[renewalparams]` section (section
headers and blank lines are skipped; `#` comments are stripped).  The
relevant keys are:

| Key | Meaning |
|-----|---------|
| `server` | ACME directory URL (default: Let's Encrypt v2) |
| `authenticator` | Challenge authenticator string |
| `preferred_challenges` | Optional override for `manual` authenticator |

### Challenge-type mapping

`map_challenge_type(authenticator, preferred_challenges, dns_challenge)`
maps certbot's authenticator string to an akamu challenge type:

| certbot `authenticator` | `preferred_challenges` | akamu challenge type | Warning? |
|---|---|---|---|
| `standalone` | any | `http-01` | No |
| `webroot` | any | `http-01` | No |
| `nginx` | any | `http-01` | No |
| `apache` | any | `http-01` | No |
| `manual` | contains `"dns"` | value of `--dns-challenge` arg | Yes — manual DNS |
| `manual` | anything else | `http-01` | No |
| `tls-sni-01` | any | `tls-alpn-01` | Yes — deprecated |
| `dns-*` (any prefix) | any | value of `--dns-challenge` arg | Yes — hook needed |
| anything else | any | `http-01` | No |

The `--dns-challenge` CLI argument controls whether DNS challenges map to
`"dns-01"` (default) or `"dns-persist-01"`.  The `canonical_dns_challenge`
helper performs this mapping.

### Wildcard encoding convention

Certbot stores wildcard certificates under directory names that replace the
leading `*.` with `_wildcard.`:

| Domain | Certbot directory name |
|--------|----------------------|
| `*.example.com` | `_wildcard.example.com` |
| `example.com` | `example.com` |

`build_renewal_config` decodes this by checking whether `renewal.domain`
starts with `"_wildcard."` and, if so, substituting `"*."` at the start to
reconstruct the original domain name.

`live_cert_paths` encodes the inverse: given a domain starting with `"*."`,
it substitutes `"_wildcard."` to locate the certbot `live/` subdirectory.

### `build_renewal_config`

Takes a `CertbotRenewal` plus caller-supplied paths and options and constructs
a `RenewalConfig`.  It does not attempt to detect the certificate key type
from the existing certbot certificate; it always writes `"ec:P-256"` for both
`account_key_type` and `cert_key_type`.  The caller must update these if the
imported account uses a different key type.

The function returns `(RenewalConfig, Option<&'static str>)` where the second
element is a human-readable warning when the mapping is ambiguous (deprecated
authenticator, manual DNS required, etc.).

### `jwk_to_account_key`

A thin wrapper around `AccountKey::from_jwk_private`.  Used by the import
subcommand after `discover_accounts` has read the raw JWK JSON string, to
verify that the key can be loaded before writing it to disk.

