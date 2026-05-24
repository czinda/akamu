//! Unix domain socket HTTP/1.1 transport.
//!
//! Used when the ACME server or Token Authority URL uses the `http+unix://`
//! scheme.  URL format:
//!
//! ```text
//! http+unix://SOCKET_PATH_ENCODED/REQUEST_PATH
//! ```
//!
//! where `SOCKET_PATH_ENCODED` is the socket file path with `/` percent-encoded
//! as `%2F` (e.g. `%2Frun%2Fakamu%2Fakamu.sock`), and `REQUEST_PATH` is the
//! normal HTTP path (e.g. `/acme/default/directory`).

use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;

use crate::error::ClientError;

/// Return the local machine's hostname via `gethostname(2)`.
/// Falls back to `"localhost"` on error.
pub fn local_hostname() -> String {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret != 0 {
        return "localhost".into();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

/// Send a single HTTP/1.1 request over a Unix domain socket.
///
/// The request URI must use the `http+unix` scheme; the host component is the
/// percent-encoded socket path.  The URI is rewritten to path-only before the
/// request is sent.
pub async fn unix_dispatch(
    req: Request<Full<Bytes>>,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
    use hyper::client::conn::http1;

    let uri = req.uri().clone();
    let encoded_host = uri
        .host()
        .ok_or_else(|| ClientError::Http("http+unix URL missing socket path in host".into()))?;

    let sock_path = percent_decode_str(encoded_host)
        .decode_utf8()
        .map_err(|_| ClientError::Http("http+unix socket path is not valid UTF-8".into()))?
        .into_owned();

    // HTTP/1.1 request line uses only path+query, not the full URI.
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let (mut parts, body) = req.into_parts();
    parts.uri = path_and_query
        .parse::<hyper::Uri>()
        .map_err(|e| ClientError::Http(format!("unix request path: {e}")))?;
    parts
        .headers
        .entry(hyper::header::HOST)
        .or_insert_with(|| hyper::header::HeaderValue::from_static("localhost"));
    let req = Request::from_parts(parts, body);

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::UnixStream::connect(&sock_path),
    )
    .await
    .map_err(|_| ClientError::Http(format!("unix connect to {sock_path}: timeout")))?
    .map_err(|e| ClientError::Http(format!("unix connect to {sock_path}: {e}")))?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| ClientError::Http(format!("unix HTTP/1.1 handshake: {e}")))?;
    tokio::spawn(conn);

    let resp = tokio::time::timeout(std::time::Duration::from_secs(30), sender.send_request(req))
        .await
        .map_err(|_| ClientError::Http("unix request timed out".into()))?
        .map_err(|e| ClientError::Http(format!("unix request: {e}")))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let raw = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ClientError::Http(format!("unix read body: {e}")))?
        .to_bytes()
        .to_vec();

    Ok((status, headers, raw))
}
