//! Management web UI listener.
//!
//! Starts a non-mTLS HTTPS (or HTTP) listener that:
//!  - Serves the compiled PatternFly React app from `static_dir` at `/ui/*`.
//!  - Reverse-proxies `/api/*` to the admin mTLS API, stripping the `/api` prefix.
//!  - Redirects `/` → `/ui/`.
//!
//! The listener is only started when `[server.webui]` is present in the config.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::{routing, Router};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use synta_certificate::pem_to_der;
use tower_http::services::ServeDir;

use crate::config::WebUiConfig;
use crate::error::AcmeError;
use crate::tls::loader::{load_server_cert_chain, load_server_private_key};

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// Build a `hyper` HTTPS client for proxying to the admin API.
///
/// Uses the native-ossl provider so algorithm support is consistent with the
/// rest of the server. Falls back to the system root store when `proxy_ca_cert`
/// is absent. Adds a client certificate when `proxy_client_cert` / `proxy_client_key`
/// are configured (required for mTLS admin API connections).
pub fn build_proxy_client(cfg: &WebUiConfig) -> Result<HttpsClient, AcmeError> {
    let tls = build_proxy_tls_config(cfg)?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https))
}

fn build_proxy_tls_config(cfg: &WebUiConfig) -> Result<ClientConfig, AcmeError> {
    let mut roots = RootCertStore::empty();

    // Load OS native root CAs (used when admin API cert chains up to a public CA).
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "some native root CA certs could not be loaded for webui proxy"
        );
    }

    // Add the Akamu CA cert (admin API cert won't be in the system root store).
    if let Some(ref ca_path) = cfg.proxy_ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|e| AcmeError::Tls(format!("read proxy CA cert '{ca_path}': {e}")))?;
        let ders = pem_to_der(&pem);
        if ders.is_empty() {
            return Err(AcmeError::Tls(format!(
                "proxy CA cert file '{ca_path}' contains no PEM certificate blocks"
            )));
        }
        for der in ders {
            roots
                .add(CertificateDer::from(der))
                .map_err(|e| AcmeError::Tls(format!("add proxy CA cert from '{ca_path}': {e}")))?;
        }
    }

    let provider = Arc::new(rustls_native_ossl::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| AcmeError::Tls(format!("proxy rustls protocol versions: {e}")))?
        .with_root_certificates(roots);

    let tls = match (&cfg.proxy_client_cert, &cfg.proxy_client_key) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_server_cert_chain(cert_path)
                .map_err(|e| AcmeError::Tls(format!("proxy client cert: {e}")))?;
            let key = load_server_private_key(key_path)
                .map_err(|e| AcmeError::Tls(format!("proxy client key: {e}")))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| AcmeError::Tls(format!("proxy mTLS client auth: {e}")))?
        }
        _ => builder.with_no_client_auth(),
    };

    Ok(tls)
}

/// Build the Axum router for the webui listener.
///
/// `static_dir` must be `Some` for the `/ui/*` routes to work; when `None`,
/// those routes return 501 (the `embed-webui` feature handles the embedded case).
pub fn build_router(cfg: &WebUiConfig, proxy_client: HttpsClient) -> Router {
    let admin_api_url = cfg.admin_api_url.trim_end_matches('/').to_owned();

    let proxy_router = Router::new().fallback(routing::any(move |req: Request| {
        proxy_handler(req, proxy_client.clone(), admin_api_url.clone())
    }));

    let ui_router = if let Some(ref dir) = cfg.static_dir {
        let serve = ServeDir::new(dir).append_index_html_on_directories(true);
        Router::new().nest_service("/ui", serve)
    } else {
        Router::new().route("/ui/{*path}", routing::get(static_not_configured))
    };

    ui_router.nest("/api", proxy_router).route(
        "/",
        routing::get(|| async { axum::response::Redirect::permanent("/ui/") }),
    )
}

async fn static_not_configured() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "webui static_dir is not configured and embed-webui feature is not compiled in",
    )
}

/// Proxy a request from `/api/<path>` to `<admin_api_url>/<path>`.
///
/// Strips the `/api` prefix (already done by the `.nest("/api", ...)` mount),
/// forwards headers and body verbatim, and returns the upstream response.
/// The `Authorization: Bearer <session-token>` header passes through unchanged,
/// so the browser-side session token works directly with the admin API.
async fn proxy_handler(req: Request, client: HttpsClient, admin_api_url: String) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri();

    // Reconstruct the upstream URL: admin_api_url + path_and_query.
    let upstream = format!(
        "{}{}",
        admin_api_url,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );

    let upstream_uri = match upstream.parse::<hyper::Uri>() {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("webui proxy: bad upstream URI '{upstream}': {e}");
            return (StatusCode::BAD_GATEWAY, "bad upstream URI").into_response();
        }
    };

    // Collect the request body.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("webui proxy: read request body: {e}");
            return (StatusCode::BAD_GATEWAY, "failed to read request body").into_response();
        }
    };

    // Forward all incoming headers except those that must not be forwarded.
    let mut upstream_req = hyper::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &parts.headers {
        // Skip hop-by-hop headers.
        if matches!(
            name.as_str(),
            "host" | "connection" | "te" | "trailers" | "transfer-encoding" | "upgrade"
        ) {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    let upstream_req = match upstream_req.body(Full::new(Bytes::copy_from_slice(&body_bytes))) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("webui proxy: build upstream request: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build upstream request",
            )
                .into_response();
        }
    };

    match client.request(upstream_req).await {
        Ok(resp) => {
            let (resp_parts, resp_body) = resp.into_parts();
            let body_bytes = match resp_body.collect().await {
                Ok(b) => b.to_bytes(),
                Err(e) => {
                    tracing::warn!("webui proxy: read upstream response body: {e}");
                    return (StatusCode::BAD_GATEWAY, "failed to read upstream response")
                        .into_response();
                }
            };
            let mut response = Response::builder().status(resp_parts.status);
            for (name, value) in &resp_parts.headers {
                if matches!(
                    name.as_str(),
                    "connection" | "transfer-encoding" | "te" | "trailers" | "upgrade"
                ) {
                    continue;
                }
                response = response.header(name, value);
            }
            response.body(Body::from(body_bytes)).unwrap_or_else(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build response",
                )
                    .into_response()
            })
        }
        Err(e) => {
            tracing::warn!("webui proxy: upstream request failed: {e}");
            (StatusCode::BAD_GATEWAY, "upstream request failed").into_response()
        }
    }
}

/// Start the webui listener and run until a Ctrl-C signal is received.
///
/// The listener is started in the foreground; call this on a background task
/// when running alongside the main ACME server.
pub async fn run(cfg: WebUiConfig) -> Result<(), String> {
    let proxy_client = build_proxy_client(&cfg).map_err(|e| format!("webui proxy client: {e}"))?;
    let router = build_router(&cfg, proxy_client);

    let addr: SocketAddr = cfg
        .listen_addr
        .parse()
        .map_err(|e| format!("webui listen_addr '{}': {e}", cfg.listen_addr))?;

    if let Some(ref tls_cfg) = cfg.tls {
        let mut server_cfg = crate::tls::build_rustls_server_config(tls_cfg)
            .map_err(|e| format!("webui TLS config: {e}"))?;
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("webui bind '{}': {e}", cfg.listen_addr))?;
        tracing::info!("webui listener on {} (TLS)", cfg.listen_addr);

        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("received shutdown signal; stopping webui TLS listener");
                    break;
                }
                result = listener.accept() => {
                    let Ok((stream, _peer_addr)) = result else {
                        tracing::warn!("webui listener accept error; retrying");
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let router = router.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("webui TLS handshake failed: {e}");
                                return;
                            }
                        };
                        let io = hyper_util::rt::TokioIo::new(tls);
                        use tower::ServiceExt as _;
                        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let router = router.clone();
                            async move {
                                let req = req.map(Body::new);
                                Ok::<_, std::convert::Infallible>(router.oneshot(req).await.unwrap())
                            }
                        });
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, svc)
                        .await
                        {
                            tracing::warn!("webui TLS connection error: {e}");
                        }
                    });
                }
            }
        }
    } else {
        tracing::warn!(
            "webui listener on {} without TLS — enable [server.webui.tls] for production use",
            cfg.listen_addr
        );
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("webui bind '{}': {e}", cfg.listen_addr))?;
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c().await.ok();
                tracing::info!("received shutdown signal; stopping webui listener");
            })
            .await
            .map_err(|e| format!("webui server error: {e}"))?;
    }

    Ok(())
}
