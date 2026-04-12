//! Challenge solver trait and built-in implementations.
//!
//! Implement [`ChallengeSolver`] for custom challenge types.  Two built-in
//! helpers handle the common cases:
//!
//! - [`Http01Solver`] — serves `/.well-known/acme-challenge/<token>` on a
//!   local TCP port (default 80) using a minimal hyper HTTP/1.1 server.
//! - [`Dns01Helper`] — computes the TXT record value; DNS provisioning is the
//!   caller's responsibility.
//! - [`DnsPersist01Helper`] — same math as `Dns01Helper`.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
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

/// Serves `/.well-known/acme-challenge/<token>` via a minimal HTTP/1.1 server.
///
/// Binds to the given port on `127.0.0.1`.  In production, port 80 must be
/// used (or an upstream proxy must forward the ACME challenge path).
pub struct Http01Solver {
    port: u16,
    store: TokenStore,
}

impl Http01Solver {
    pub fn new(port: u16) -> Self {
        Http01Solver {
            port,
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Bind the TCP listener and spawn the accept loop in the background.
    ///
    /// Call this once before issuing any orders.
    pub async fn start(&self) -> Result<(), ClientError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let io = TokioIo::new(stream);
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| {
                                let store = Arc::clone(&store);
                                async move { handle_challenge(&store, req) }
                            }),
                        )
                        .await;
                });
            }
        });
        Ok(())
    }
}

fn handle_challenge(
    store: &TokenStore,
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
        Box::pin(async move {
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

/// Computes the persistent TXT record value for dns-persist-01.
///
/// Uses the same SHA-256 digest as dns-01 (per the LE draft).  The caller is
/// responsible for provisioning the long-lived `_validation-persist.<domain>`
/// TXT record before placing the order.
pub struct DnsPersist01Helper;

impl DnsPersist01Helper {
    /// Returns `base64url(SHA-256(key_authorization))`.
    pub fn txt_value(key_auth: &str) -> Result<String, ClientError> {
        dns_txt_value(key_auth)
    }
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
    fn dns_persist_01_matches_dns01() {
        let key_auth = "sometoken.somethumbprint";
        let a = Dns01Helper::txt_value(key_auth).unwrap();
        let b = DnsPersist01Helper::txt_value(key_auth).unwrap();
        assert_eq!(a, b);
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
}
