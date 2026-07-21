#[cfg(feature = "embed-webui")]
use include_dir::{include_dir, Dir};

#[cfg(feature = "embed-webui")]
static WEBUI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/webui/dist");

/// Build a sub-router for the embedded UI (paths are relative — caller nests
/// at `/ui`).
#[cfg(feature = "embed-webui")]
pub fn webui_router() -> axum::Router<std::sync::Arc<crate::state::AppState>> {
    axum::Router::new()
        .route("/", serve_embedded())
        .route("/{*path}", serve_embedded())
}

#[cfg(feature = "embed-webui")]
fn serve_embedded() -> axum::routing::MethodRouter<std::sync::Arc<crate::state::AppState>> {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{header, StatusCode};
    use axum::response::{IntoResponse, Response};

    axum::routing::get(|req: Request| async move {
        let path = req.uri().path().trim_start_matches('/');
        let path = if path.is_empty() { "index.html" } else { path };

        if let Some(file) = WEBUI_DIR.get_file(path) {
            let mime = mime_from_path(path);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .body(Body::from(file.contents().to_vec()))
                .unwrap()
                .into_response()
        } else if path.contains('.') {
            StatusCode::NOT_FOUND.into_response()
        } else if let Some(index) = WEBUI_DIR.get_file("index.html") {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Body::from(index.contents().to_vec()))
                .unwrap()
                .into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    })
}

#[cfg(feature = "embed-webui")]
fn mime_from_path(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}
