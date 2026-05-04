use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

#[allow(clippy::too_many_arguments)]
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    serial: Option<String>,
    subject: Option<String>,
    after: Option<String>,
    before: Option<String>,
    status: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/certs?limit={limit}&offset={offset}");
    if let Some(s) = &serial {
        path.push_str(&format!("&serial={}", urlenc(s)));
    }
    if let Some(s) = &subject {
        path.push_str(&format!("&subject={}", urlenc(s)));
    }
    if let Some(a) = &after {
        path.push_str(&format!("&after={}", urlenc(a)));
    }
    if let Some(b) = &before {
        path.push_str(&format!("&before={}", urlenc(b)));
    }
    if let Some(st) = &status {
        path.push_str(&format!("&status={}", urlenc(st)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}
