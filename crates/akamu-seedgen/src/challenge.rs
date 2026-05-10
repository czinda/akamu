//! HTTP-01 challenge responder for the in-process ACME server.
//!
//! Starts an axum HTTP server on an OS-assigned port and returns a
//! `ChallengeResponder` handle that workers use to register and clean up
//! key authorisations.  Pattern mirrors `benches/acme_bench.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use tokio::sync::RwLock;

pub type TokenMap = Arc<RwLock<HashMap<String, String>>>;

/// Handle to the running HTTP-01 challenge responder.
pub struct ChallengeResponder {
    port: u16,
    store: TokenMap,
    _task: tokio::task::JoinHandle<()>,
}

impl ChallengeResponder {
    /// Start the responder and return its handle.
    pub async fn start() -> Self {
        let store: TokenMap = Arc::new(RwLock::new(HashMap::new()));
        let router = Router::new()
            .route(
                "/.well-known/acme-challenge/{token}",
                get(
                    |State(s): State<TokenMap>, Path(token): Path<String>| async move {
                        match s.read().await.get(&token).cloned() {
                            Some(key_auth) => (StatusCode::OK, key_auth),
                            None => (StatusCode::NOT_FOUND, String::new()),
                        }
                    },
                ),
            )
            .with_state(Arc::clone(&store));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP-01 challenge responder on loopback");
        let port = listener
            .local_addr()
            .expect("HTTP-01 challenge responder local address")
            .port();
        let _task = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP-01 challenge responder exited with error: {e}");
            }
        });
        ChallengeResponder { port, store, _task }
    }

    /// TCP port the responder is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Store `token → key_auth` so the ACME server can validate it.
    pub async fn present(&self, token: &str, key_auth: &str) {
        self.store
            .write()
            .await
            .insert(token.to_string(), key_auth.to_string());
    }

    /// Remove the token after the challenge is validated.
    pub async fn cleanup(&self, token: &str) {
        self.store.write().await.remove(token);
    }
}
