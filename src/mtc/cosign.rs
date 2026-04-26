//! External cosignature gathering (§6.2 of draft-ietf-plants-merkle-tree-certs).
//!
//! After a checkpoint is produced, akamu POSTs the DER-encoded Checkpoint to
//! each configured cosigner URL.  The cosigner is expected to return a
//! DER-encoded `SubtreeSignature`.  Failures are logged and skipped — partial
//! success is acceptable; the standalone certificate is built with whatever
//! signatures arrive.

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::config::CosignerConfig;

/// POST `checkpoint_der` to each configured cosigner and return the DER-encoded
/// `SubtreeSignature` responses as `(cosigner_url, signature_der)` pairs.
///
/// Each HTTP call is issued sequentially.  If a cosigner is slow or unavailable,
/// the checkpoint task's `checkpoint_interval_secs` provides the implicit timeout;
/// a future enhancement could parallelize these with `tokio::join_all`.
pub async fn gather_cosignatures(
    checkpoint_der: &[u8],
    cosigners: &[CosignerConfig],
) -> Vec<(String, Vec<u8>)> {
    if cosigners.is_empty() {
        return Vec::new();
    }

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let body_bytes = Bytes::copy_from_slice(checkpoint_der);
    let mut results = Vec::new();

    for cosigner in cosigners {
        let url = cosigner.url.clone();
        let body = Full::new(body_bytes.clone());

        let req = match Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url = %url, "build cosigner request: {e}");
                continue;
            }
        };

        match client.request(req).await {
            Ok(resp) => {
                let status = resp.status();
                match resp.into_body().collect().await {
                    Ok(collected) => {
                        if status.is_success() {
                            let der = collected.to_bytes().to_vec();
                            if der.is_empty() {
                                tracing::warn!(url = %url, "cosigner returned empty body");
                            } else {
                                tracing::debug!(url = %url, bytes = der.len(), "cosignature received");
                                results.push((url, der));
                            }
                        } else {
                            tracing::warn!(
                                url = %url,
                                status = %status,
                                "cosigner returned non-2xx status"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(url = %url, "read cosigner response body: {e}"),
                }
            }
            Err(e) => tracing::warn!(url = %url, "cosigner request failed: {e}"),
        }
    }

    results
}
