//! Shared helpers for integration tests.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::extract::Path;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

/// Bind an ephemeral TCP port and return the port number and listener.
pub fn bind_free_port() -> (u16, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    l.set_nonblocking(true).expect("set_nonblocking");
    let port = l.local_addr().expect("local_addr").port();
    (port, l)
}

pub type TokenStore = Arc<RwLock<HashMap<String, String>>>;

/// Start a minimal HTTP-01 challenge responder on `std_listener`.
///
/// Returns the token store: insert `(token, key_authorization)` pairs to
/// make them serveable at `GET /.well-known/acme-challenge/{token}`.
pub async fn start_http01_solver(std_listener: std::net::TcpListener) -> TokenStore {
    let store: TokenStore = Arc::new(RwLock::new(HashMap::new()));
    let store_clone = Arc::clone(&store);

    let app = Router::new().route(
        "/.well-known/acme-challenge/{token}",
        get(move |Path(token): Path<String>| {
            let s = Arc::clone(&store_clone);
            async move { s.read().unwrap().get(&token).cloned().unwrap_or_default() }
        }),
    );

    let listener = TcpListener::from_std(std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    store
}
