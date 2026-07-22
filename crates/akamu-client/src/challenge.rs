//! Challenge solver trait and built-in implementations.
//!
//! Implement [`ChallengeSolver`] for custom challenge types.  Two built-in
//! helpers handle the common cases:
//!
//! - [`Http01Solver`] — serves `/.well-known/acme-challenge/<token>` on a
//!   local TCP port (default 80) using a minimal hyper HTTP/1.1 server.
//! - [`Dns01Helper`] — computes the TXT record value; DNS provisioning is the
//!   caller's responsibility.
//! - [`DnsPersist01Helper`] — builds the persistent TXT record content per
//!   draft-ietf-acme-dns-persist; DNS provisioning is the caller's
//!   responsibility.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{account::dns_txt_value, error::ClientError};

/// Async trait for challenge solvers.
///
/// `present` is called before the client triggers the challenge; `cleanup` is
/// called after the challenge completes (success or failure).
pub trait ChallengeSolver: Send + Sync {
    fn present(
        &self,
        token: &str,
        key_auth: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>;

    fn cleanup(
        &self,
        token: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>;
}

// ── http-01 solver ────────────────────────────────────────────────────────────

type TokenStore = Arc<RwLock<HashMap<String, String>>>;
type ValidationNotifiers = Arc<RwLock<HashMap<String, Arc<tokio::sync::Notify>>>>;

/// Serves `/.well-known/acme-challenge/<token>` via a minimal HTTP/1.1 server.
///
/// Binds to the given port on `127.0.0.1`.  In production, port 80 must be
/// used (or an upstream proxy must forward the ACME challenge path).
pub struct Http01Solver {
    port: u16,
    store: TokenStore,
    notifiers: ValidationNotifiers,
}

impl Http01Solver {
    pub fn new(port: u16) -> Self {
        Http01Solver {
            port,
            store: Arc::new(RwLock::new(HashMap::new())),
            notifiers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Bind the TCP listener and spawn the accept loop in the background.
    ///
    /// Call this once before issuing any orders.
    pub async fn start(&self) -> Result<(), ClientError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        let store = Arc::clone(&self.store);
        let notifiers = Arc::clone(&self.notifiers);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let io = TokioIo::new(stream);
                let store = Arc::clone(&store);
                let notifiers = Arc::clone(&notifiers);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| {
                                let store = Arc::clone(&store);
                                let notifiers = Arc::clone(&notifiers);
                                async move { handle_challenge(&store, &notifiers, req) }
                            }),
                        )
                        .await;
                });
            }
        });
        Ok(())
    }

    /// Wait until the ACME server has fetched the challenge token via HTTP.
    ///
    /// Per RFC 8555 §7.5.1, the client SHOULD NOT begin polling the
    /// authorization until it has seen the validation request from the server.
    /// Returns `Ok(())` when the token has been served, or `Err` on timeout.
    pub async fn wait_for_validation(
        &self,
        token: &str,
        timeout: Duration,
    ) -> Result<(), ClientError> {
        let notify = {
            let notifiers = self.notifiers.read().unwrap();
            notifiers.get(token).cloned()
        };
        let Some(notify) = notify else {
            return Ok(());
        };
        tokio::time::timeout(timeout, notify.notified())
            .await
            .map_err(|_| {
                ClientError::Http(format!(
                    "timed out waiting for http-01 validation request for token {token}"
                ))
            })
    }
}

fn handle_challenge(
    store: &TokenStore,
    notifiers: &ValidationNotifiers,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    let path = req.uri().path();
    if let Some(token) = path.strip_prefix(PREFIX) {
        let body = store
            .read()
            .unwrap()
            .get(token)
            .cloned()
            .unwrap_or_default();
        if !body.is_empty() {
            if let Ok(notifiers) = notifiers.read() {
                if let Some(n) = notifiers.get(token) {
                    n.notify_one();
                }
            }
        }
        Ok(Response::new(Full::new(Bytes::from(body))))
    } else {
        Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::new()))
            .unwrap())
    }
}

impl ChallengeSolver for Http01Solver {
    fn present(
        &self,
        token: &str,
        key_auth: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>
    {
        let token = token.to_owned();
        let key_auth = key_auth.to_owned();
        let store = Arc::clone(&self.store);
        let notifiers = Arc::clone(&self.notifiers);
        Box::pin(async move {
            notifiers
                .write()
                .unwrap()
                .insert(token.clone(), Arc::new(tokio::sync::Notify::new()));
            store.write().unwrap().insert(token, key_auth);
            Ok(())
        })
    }

    fn cleanup(
        &self,
        token: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>
    {
        let token = token.to_owned();
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            store.write().unwrap().remove(&token);
            Ok(())
        })
    }
}

// ── dns-01 helper ─────────────────────────────────────────────────────────────

/// Computes the `_acme-challenge.<domain>` TXT record value for dns-01.
///
/// The caller is responsible for provisioning and removing the DNS record.
pub struct Dns01Helper;

impl Dns01Helper {
    /// Returns `base64url(SHA-256(key_authorization))`.
    pub fn txt_value(key_auth: &str) -> Result<String, ClientError> {
        dns_txt_value(key_auth)
    }
}

// ── dns-persist-01 helper ─────────────────────────────────────────────────────

/// Builds the persistent TXT record content for dns-persist-01
/// (draft-ietf-acme-dns-persist).
///
/// The record is provisioned once at `_validation-persist.<domain>` and left
/// in place; it does not need to be reprovisioned for each renewal.  Unlike
/// dns-01, there is no token or key-authorization hash — the record encodes
/// the CA's issuer domain and the client's ACME account URI directly.
///
/// # Example
///
/// ```
/// use akamu_client::challenge::DnsPersist01Helper;
/// let record = DnsPersist01Helper::txt_record(
///     "acme.example.com",
///     "https://acme.example.com/acme/account/42",
/// );
/// assert_eq!(record, "acme.example.com; accounturi=https://acme.example.com/acme/account/42");
/// ```
pub struct DnsPersist01Helper;

impl DnsPersist01Helper {
    /// Returns the TXT record content for a non-wildcard domain:
    ///
    /// ```text
    /// <issuer_domain>; accounturi=<account_url>
    /// ```
    ///
    /// `issuer_domain` must be one of the values from the `issuer-domain-names`
    /// array in the server's challenge object.  `account_url` is the ACME
    /// account URL returned by the server at registration time.
    pub fn txt_record(issuer_domain: &str, account_url: &str) -> String {
        format!("{}; accounturi={}", issuer_domain, account_url)
    }

    /// Returns the TXT record content when `policy=wildcard` authorisation is
    /// needed (wildcard identifiers or subdomain coverage):
    ///
    /// ```text
    /// <issuer_domain>; accounturi=<account_url>; policy=wildcard
    /// ```
    pub fn txt_record_wildcard(issuer_domain: &str, account_url: &str) -> String {
        format!(
            "{}; accounturi={}; policy=wildcard",
            issuer_domain, account_url
        )
    }
}

// ── dns-hook solver ───────────────────────────────────────────────────────────

/// Delegates DNS-01 / dns-persist-01 TXT record management to an external hook
/// script.
///
/// The hook is invoked as:
///
/// ```text
/// <hook_script> add
/// <hook_script> remove
/// ```
///
/// All values are passed exclusively as **environment variables** (never as
/// command-line arguments, which would be visible via `/proc/<pid>/cmdline`):
///
/// **dns-01** (`deploy` / `clean`):
///
/// | Variable           | Value                                             |
/// |--------------------|---------------------------------------------------|
/// | `AKAMU_DOMAIN`     | Base DNS name being validated                     |
/// | `AKAMU_TOKEN`      | ACME challenge token                              |
/// | `AKAMU_TXT`        | `base64url(SHA-256(key_auth))`                    |
/// | `AKAMU_KEY_AUTH`   | Full key authorization string                     |
///
/// **dns-persist-01** (`deploy_persist`):
///
/// | Variable           | Value                                             |
/// |--------------------|---------------------------------------------------|
/// | `AKAMU_DOMAIN`     | Base DNS name being validated                     |
/// | `AKAMU_TXT`        | Full TXT record content (`issuer; accounturi=…`)  |
///
/// Exit code 0 is success; non-zero is failure.  stderr is captured and
/// included in the returned [`ClientError`].
pub struct DnsHookSolver {
    hook: String,
}

impl DnsHookSolver {
    /// Create a new solver that will delegate to `hook` (a path or shell
    /// command).
    pub fn new(hook: String) -> Self {
        Self { hook }
    }

    /// Compute the TXT record value and invoke the hook with `add`.
    pub async fn deploy(
        &self,
        domain: &str,
        token: &str,
        key_auth: &str,
    ) -> Result<(), ClientError> {
        self.run_hook("add", domain, token, key_auth).await
    }

    /// Invoke the hook with `remove` to clean up the TXT record.
    pub async fn clean(
        &self,
        domain: &str,
        token: &str,
        key_auth: &str,
    ) -> Result<(), ClientError> {
        self.run_hook("remove", domain, token, key_auth).await
    }

    /// Provision a dns-persist-01 TXT record by invoking the hook with `add`.
    ///
    /// Unlike [`deploy`](Self::deploy), the `txt_record` is the full structured
    /// record content (`"issuer; accounturi=<url>[; policy=wildcard]"`) built by
    /// [`DnsPersist01Helper`] — there is no token or key-authorization hash.
    /// The hook receives `AKAMU_DOMAIN` and `AKAMU_TXT` only.
    pub async fn deploy_persist(&self, domain: &str, txt_record: &str) -> Result<(), ClientError> {
        let output = tokio::process::Command::new(&self.hook)
            .arg("add")
            .env("AKAMU_DOMAIN", domain)
            .env("AKAMU_TXT", txt_record)
            .output()
            .await?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ClientError::Crypto(format!(
            "dns hook '{}' add exited with {}: {stderr}",
            self.hook, output.status,
        )))
    }

    async fn run_hook(
        &self,
        operation: &str,
        domain: &str,
        token: &str,
        key_auth: &str,
    ) -> Result<(), ClientError> {
        let txt = dns_txt_value(key_auth)?;
        let output = tokio::process::Command::new(&self.hook)
            .arg(operation)
            .env("AKAMU_DOMAIN", domain)
            .env("AKAMU_TOKEN", token)
            .env("AKAMU_TXT", &txt)
            .env("AKAMU_KEY_AUTH", key_auth)
            .output()
            .await?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ClientError::Crypto(format!(
            "dns hook '{}' {operation} exited with {}: {stderr}",
            self.hook, output.status,
        )))
    }
}

// ── tls-alpn-01 solver ────────────────────────────────────────────────────────

/// SNI-based certificate resolver: looks up the per-domain certified key in the
/// shared store.
#[derive(Debug)]
struct SniResolver {
    certs: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    notifiers: ValidationNotifiers,
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        if let Ok(notifiers) = self.notifiers.read() {
            if let Some(n) = notifiers.get(sni) {
                n.notify_one();
            }
        }
        let certs = self.certs.read().ok()?;
        certs.get(sni).cloned()
    }
}

/// Serves ephemeral ACME challenge certificates for tls-alpn-01 (RFC 8737).
///
/// Call [`start`](TlsAlpn01Solver::start) once to bind the port, then call
/// [`present`](TlsAlpn01Solver::present) for each domain/challenge pair before
/// triggering the challenge at the ACME server.  When finished, call
/// [`cleanup`](TlsAlpn01Solver::cleanup) to abort the background listener.
pub struct TlsAlpn01Solver {
    port: u16,
    certs: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    notifiers: ValidationNotifiers,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TlsAlpn01Solver {
    /// Create a new solver that will listen on `port` (typically 443).
    pub fn new(port: u16) -> Self {
        TlsAlpn01Solver {
            port,
            certs: Arc::new(RwLock::new(HashMap::new())),
            notifiers: Arc::new(RwLock::new(HashMap::new())),
            handle: None,
        }
    }

    /// Bind the TCP port and start the TLS accept loop.
    ///
    /// The loop accepts connections and completes TLS handshakes (ALPN
    /// `acme-tls/1`) so that the ACME server can fetch the challenge cert via
    /// SNI.  Call this once before the first [`present`](Self::present).
    pub async fn start(&mut self) -> Result<(), ClientError> {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls_native_ossl::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Crypto(format!("rustls: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver {
            certs: Arc::clone(&self.certs),
            notifiers: Arc::clone(&self.notifiers),
        }));

        let mut config = config;
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", self.port)).await?;

        self.handle = Some(tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        let _ = acc.accept(stream).await;
                    });
                }
            }
        }));

        Ok(())
    }

    /// Generate and register the challenge certificate for `domain`.
    ///
    /// * `domain`   — the ACME identifier value (DNS name or IP string).
    /// * `id_type`  — `"dns"` or `"ip"`.
    /// * `key_auth` — `{token}.{jwk_thumbprint}`.
    pub async fn present(
        &self,
        domain: &str,
        id_type: &str,
        key_auth: &str,
    ) -> Result<(), ClientError> {
        use synta_certificate::{
            acme_types::Authorization, default_data_hasher, oids, parse_time, BackendPrivateKey,
            CertificateBuilder, DataHasher, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };

        // 1. Compute SHA-256(key_auth) → 32 bytes.
        let hash: [u8; 32] = default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .map_err(|e| ClientError::Crypto(format!("SHA-256: {e}")))?
            .try_into()
            .map_err(|_| ClientError::Crypto("SHA-256 did not return 32 bytes".into()))?;

        // 2. Build the id-pe-acmeIdentifier extension value:
        //    OCTET STRING { <32-byte hash> } encoded as DER → 04 20 <hash>.
        let auth = Authorization::new_unchecked(synta::OctetString::new(hash.to_vec()));
        let ext_value = auth
            .to_der()
            .map_err(|e| ClientError::Crypto(format!("encode acme ext: {e}")))?;

        // 3. Generate an ephemeral EC P-256 key pair.
        let key = BackendPrivateKey::generate_ec("P-256")
            .map_err(|e| ClientError::Crypto(format!("generate key: {e}")))?;

        // 4. Extract SPKI (for cert) and PKCS#8 DER (for rustls).
        let spki = key
            .public_key()
            .map_err(|e| ClientError::Crypto(format!("public key: {e}")))?
            .spki_der()
            .to_vec();
        let pkcs8_der = key
            .to_der()
            .map_err(|e| ClientError::Crypto(format!("key to DER: {e}")))?;

        // 5. Build validity timestamps (not_before = now, not_after = now + 7 days).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let nb = parse_time(&unix_to_generalized_time(now_secs))
            .map_err(|e| ClientError::Crypto(format!("notBefore: {e}")))?;
        let na = parse_time(&unix_to_generalized_time(now_secs + 86400 * 7))
            .map_err(|e| ClientError::Crypto(format!("notAfter: {e}")))?;

        // 6. Build subject / issuer name.
        let name_der = NameBuilder::new()
            .common_name(domain)
            .build()
            .map_err(|e| ClientError::Crypto(format!("name: {e}")))?;

        // 7. Build SAN: iPAddress for "ip", dNSName otherwise.
        let san_der = if id_type == "ip" {
            let ip_bytes = if let Ok(v4) = domain.parse::<std::net::Ipv4Addr>() {
                v4.octets().to_vec()
            } else if let Ok(v6) = domain.parse::<std::net::Ipv6Addr>() {
                v6.octets().to_vec()
            } else {
                return Err(ClientError::Crypto(format!("invalid IP address: {domain}")));
            };
            SubjectAlternativeNameBuilder::new()
                .ip_address(&ip_bytes)
                .build()
                .map_err(|e| ClientError::Crypto(format!("SAN ip: {e}")))?
        } else {
            SubjectAlternativeNameBuilder::new()
                .dns_name(domain)
                .build()
                .map_err(|e| ClientError::Crypto(format!("SAN dns: {e}")))?
        };

        // 8. Build and sign the challenge certificate.
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::PE_ACME_IDENTIFIER, true, &ext_value)
            .sign(&signer)
            .map_err(|e| ClientError::Crypto(format!("sign cert: {e}")))?;

        // 9. Load the key and cert into a rustls CertifiedKey.
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der),
        );
        let signing_key = rustls_native_ossl::default_provider()
            .key_provider
            .load_private_key(private_key)
            .map_err(|e| ClientError::Crypto(format!("load key: {e}")))?;
        let cert_der_type = rustls::pki_types::CertificateDer::from(cert_der);
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert_der_type],
            signing_key,
        ));

        // 10. Register in the SNI store and create a validation notifier.
        self.notifiers
            .write()
            .unwrap()
            .insert(domain.to_string(), Arc::new(tokio::sync::Notify::new()));
        self.certs
            .write()
            .unwrap()
            .insert(domain.to_string(), certified);

        Ok(())
    }

    /// Wait until the ACME server has connected via TLS to validate the domain.
    ///
    /// Per RFC 8555 §7.5.1, the client SHOULD NOT begin polling the
    /// authorization until it has seen the validation request from the server.
    /// Returns `Ok(())` when the TLS handshake with matching SNI has been
    /// observed, or `Err` on timeout.
    pub async fn wait_for_validation(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> Result<(), ClientError> {
        let notify = {
            let notifiers = self.notifiers.read().unwrap();
            notifiers.get(domain).cloned()
        };
        let Some(notify) = notify else {
            return Ok(());
        };
        tokio::time::timeout(timeout, notify.notified())
            .await
            .map_err(|_| {
                ClientError::Http(format!(
                    "timed out waiting for tls-alpn-01 validation request for {domain}"
                ))
            })
    }

    /// Abort the background TLS listener.
    pub fn cleanup(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Convert Unix seconds to a GeneralizedTime string (`YYYYMMDDHHmmssZ`).
///
/// Mirrors `crate::ca::init::unix_to_generalized_time` in the server crate.
fn unix_to_generalized_time(secs: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(secs)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

/// Fetch an RFC 9447 authority token from a Token Authority using SPNEGO.
///
/// Posts `{"atc": {"tktype": "EnhancedJWTClaimConstraints", "tkvalue": ...,
/// "fingerprint": ..., "ca": false}}` to `ta_url` with a `Negotiate` token
/// derived from `keytab_path`.  Drives the full multi-step SPNEGO exchange.
///
/// Returns the compact JWT string from `response["token"]`.
pub async fn fetch_authority_token(
    ta_url: &str,
    tkvalue: &str,
    fingerprint: &str,
    keytab_path: &str,
) -> Result<String, ClientError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, Request, StatusCode};

    let cred = akamu_gssapi::GssClientCred::from_keytab(keytab_path)
        .map_err(|e| ClientError::Gssapi(e.to_string()))?;
    let target = derive_ta_service_name(ta_url)?;
    let mut ctx = akamu_gssapi::GssClientContext::new(&target)
        .map_err(|e| ClientError::Gssapi(e.to_string()))?;

    // Build the TCP client only for non-unix URLs.
    let http_opt = if !ta_url.starts_with("http+unix://") {
        use hyper_rustls::HttpsConnectorBuilder;
        use hyper_util::{client::legacy::Client, rt::TokioExecutor};
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls_native_ossl::default_provider())
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        Some(Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https))
    } else {
        None
    };

    let body_json = serde_json::json!({
        "atc": {
            "tktype": "EnhancedJWTClaimConstraints",
            "tkvalue": tkvalue,
            "fingerprint": fingerprint,
            "ca": false,
        }
    });
    let body_bytes: Bytes = serde_json::to_vec(&body_json)
        .map_err(|e| ClientError::Http(format!("JSON body: {e}")))?
        .into();

    let mut server_token: Option<Vec<u8>> = None;
    loop {
        let (token_bytes, _complete) = ctx
            .step(&cred, server_token.as_deref(), None)
            .map_err(|e| ClientError::Gssapi(e.to_string()))?;

        let token_b64 = STANDARD.encode(&token_bytes);
        let req = Request::builder()
            .method("POST")
            .uri(ta_url)
            .header("Authorization", format!("Negotiate {token_b64}"))
            .header("Content-Type", "application/json")
            .body(Full::new(body_bytes.clone()))
            .map_err(|e| ClientError::Http(format!("request build: {e}")))?;

        let (status, resp_headers, resp_bytes) = if let Some(http) = &http_opt {
            let resp = http
                .request(req)
                .await
                .map_err(|e| ClientError::Http(format!("POST {ta_url}: {e}")))?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let raw = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| ClientError::Http(format!("read body: {e}")))?
                .to_bytes()
                .to_vec();
            (status, headers, raw)
        } else {
            crate::unix::unix_dispatch(req).await?
        };

        let cont_token: Option<Vec<u8>> = resp_headers
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split_once(' ')
                    .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("negotiate"))
                    .map(|(_, b64)| b64.trim())
            })
            .and_then(|b64| STANDARD.decode(b64).ok());

        if status == StatusCode::UNAUTHORIZED {
            if let Some(cont) = cont_token {
                server_token = Some(cont);
                continue;
            }
            return Err(ClientError::Http(format!(
                "POST {ta_url}: HTTP {status}: authentication required"
            )));
        }

        if !status.is_success() {
            let body = String::from_utf8_lossy(&resp_bytes);
            return Err(ClientError::Http(format!(
                "POST {ta_url}: HTTP {status}: {body}"
            )));
        }

        let json: serde_json::Value = serde_json::from_slice(&resp_bytes)
            .map_err(|e| ClientError::Http(format!("parse TA response: {e}")))?;
        return json["token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| ClientError::Http("TA response missing 'token' field".into()));
    }
}

fn derive_ta_service_name(url: &str) -> Result<String, ClientError> {
    if url.starts_with("http+unix://") {
        // Unix socket: the service runs on this machine.
        return Ok(format!("HTTP@{}", crate::unix::local_hostname()));
    }
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme
        .split('/')
        .next()
        .and_then(|h| h.split(':').next())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ClientError::Http(format!("cannot extract hostname from '{url}'")))?;
    Ok(format!("HTTP@{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns01_txt_value_is_base64url_sha256() {
        // key_auth = "token.thumbprint" — the TXT value is base64url(sha256(key_auth)).
        let key_auth = "sometoken.somethumbprint";
        let txt = Dns01Helper::txt_value(key_auth).unwrap();
        // Must be non-empty base64url.
        assert!(!txt.is_empty());
        assert!(!txt.contains('+'));
        assert!(!txt.contains('/'));
        assert!(!txt.contains('='));
    }

    #[test]
    fn dns_persist_01_txt_record_non_wildcard() {
        let record = DnsPersist01Helper::txt_record(
            "acme.example.com",
            "https://acme.example.com/acme/account/42",
        );
        assert_eq!(
            record,
            "acme.example.com; accounturi=https://acme.example.com/acme/account/42"
        );
    }

    #[test]
    fn dns_persist_01_txt_record_wildcard() {
        let record = DnsPersist01Helper::txt_record_wildcard(
            "acme.example.com",
            "https://acme.example.com/acme/account/42",
        );
        assert_eq!(
            record,
            "acme.example.com; accounturi=https://acme.example.com/acme/account/42; policy=wildcard"
        );
    }

    #[tokio::test]
    async fn http01_solver_present_and_cleanup() {
        let solver = Http01Solver::new(0); // port 0 = unused for this test (no server started)
        solver.present("tok1", "tok1.thumb").await.unwrap();
        {
            let guard = solver.store.read().unwrap();
            assert_eq!(guard.get("tok1").map(String::as_str), Some("tok1.thumb"));
        }
        solver.cleanup("tok1").await.unwrap();
        {
            let guard = solver.store.read().unwrap();
            assert!(guard.get("tok1").is_none());
        }
    }

    #[test]
    fn tls_alpn01_solver_new_and_cleanup() {
        // cleanup on a solver that has never been started must not panic.
        let mut solver = TlsAlpn01Solver::new(0);
        solver.cleanup(); // handle is None — must be a no-op
    }
}
