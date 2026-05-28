use serde::Deserialize;

/// Web UI configuration (`[server.webui]`).
///
/// The web UI is served at `/ui/*` on the main ACME/admin listener.
/// Admin API calls from the browser go to `/admin/*` directly — no proxy.
#[derive(Debug, Deserialize, Clone)]
pub struct WebUiConfig {
    /// Directory containing the built `webui/dist/` output to serve.
    /// When absent the server falls back to the binary-embedded UI (if
    /// compiled with the `embed-webui` feature).
    pub static_dir: Option<String>,
}
