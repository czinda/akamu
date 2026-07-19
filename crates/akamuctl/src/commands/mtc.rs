//! MTC transparency log administration subcommands (akamuctl mtc …).

use std::path::PathBuf;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

fn ca_qs(ca: &Option<String>) -> String {
    match ca {
        Some(id) => format!("?ca_id={}", urlenc(id)),
        None => String::new(),
    }
}

/// Show MTC transparency log tree size.
pub async fn tree_size(
    client: &AdminClient,
    fmt: &Format,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/mtc/tree-size{}", ca_qs(&ca)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Show MTC tree size and root hash.
pub async fn root(client: &AdminClient, fmt: &Format, ca: Option<String>) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/mtc/root{}", ca_qs(&ca)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// List MTC landmarks as JSON.
pub async fn landmarks(
    client: &AdminClient,
    fmt: &Format,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/mtc/landmarks{}", ca_qs(&ca)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Show landmarks in spec section 3.4 text format.
pub async fn landmark_list(client: &AdminClient, ca: Option<String>) -> Result<(), CtlError> {
    let text = client
        .get_text(&format!("/admin/mtc/landmark-list{}", ca_qs(&ca)))
        .await?;
    print!("{text}");
    Ok(())
}

/// Download landmark certificate DER by sequence number.
pub async fn landmark_cert(
    client: &AdminClient,
    seq: i64,
    ca: Option<String>,
    output: Option<PathBuf>,
) -> Result<(), CtlError> {
    let bytes = client
        .get_bytes(&format!("/admin/mtc/landmarks/{seq}/cert{}", ca_qs(&ca)))
        .await?;
    write_binary(&bytes, output.as_deref())
}

/// Show parsed details of a landmark certificate.
pub async fn landmark_cert_show(
    client: &AdminClient,
    seq: i64,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let bytes = client
        .get_bytes(&format!("/admin/mtc/landmarks/{seq}/cert{}", ca_qs(&ca)))
        .await?;
    match akamu_client::cert_text::describe_landmark_cert_der(&bytes) {
        Some(text) => print!("{text}"),
        None => eprintln!("Failed to parse landmark certificate DER"),
    }
    Ok(())
}

/// Show inclusion proof for a certificate.
pub async fn inclusion_proof(
    client: &AdminClient,
    fmt: &Format,
    cert_id: &str,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/mtc/inclusion-proof/{}", urlenc(cert_id)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Download standalone DER certificate.
pub async fn standalone(
    client: &AdminClient,
    cert_id: &str,
    output: Option<PathBuf>,
) -> Result<(), CtlError> {
    let bytes = client
        .get_bytes(&format!("/admin/mtc/standalone/{}", urlenc(cert_id)))
        .await?;
    write_binary(&bytes, output.as_deref())
}

/// Show consistency proof between two tree sizes.
pub async fn consistency_proof(
    client: &AdminClient,
    fmt: &Format,
    from: u64,
    to: u64,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let mut qs = format!("?from={from}&to={to}");
    if let Some(ref id) = ca {
        qs.push_str(&format!("&ca_id={}", urlenc(id)));
    }
    let resp = client
        .get(&format!("/admin/mtc/consistency-proof{qs}"))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Compute subtree root hash over a leaf range.
pub async fn subtree_root(
    client: &AdminClient,
    fmt: &Format,
    start: u64,
    end: u64,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let mut qs = format!("?start={start}&end={end}");
    if let Some(ref id) = ca {
        qs.push_str(&format!("&ca_id={}", urlenc(id)));
    }
    let resp = client.get(&format!("/admin/mtc/subtree-root{qs}")).await?;
    print(fmt, &resp);
    Ok(())
}

/// Show revoked leaf-index ranges.
pub async fn revoked_ranges(
    client: &AdminClient,
    fmt: &Format,
    ca: Option<String>,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/mtc/revoked-ranges{}", ca_qs(&ca)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Show C2SP tlog operator checkpoint.
pub async fn checkpoint(client: &AdminClient, ca: Option<String>) -> Result<(), CtlError> {
    let text = client
        .get_text(&format!("/admin/mtc/checkpoint{}", ca_qs(&ca)))
        .await?;
    print!("{text}");
    Ok(())
}

/// Show C2SP tlog cosignature checkpoint.
pub async fn cosignature(client: &AdminClient, ca: Option<String>) -> Result<(), CtlError> {
    let text = client
        .get_text(&format!("/admin/mtc/cosignature{}", ca_qs(&ca)))
        .await?;
    print!("{text}");
    Ok(())
}

/// Force an immediate MTC checkpoint for the given CA.
pub async fn force_checkpoint(client: &AdminClient, ca: &str) -> Result<(), CtlError> {
    client
        .post_action(&format!("/admin/ca/{}/mtc/force-checkpoint", urlenc(ca)))
        .await?;
    println!("Checkpoint produced for CA '{ca}'.");
    Ok(())
}

/// Force an immediate MTC landmark allocation for the given CA.
pub async fn force_landmark(client: &AdminClient, ca: &str) -> Result<(), CtlError> {
    client
        .post_action(&format!("/admin/ca/{}/mtc/force-landmark", urlenc(ca)))
        .await?;
    println!("Landmark allocated for CA '{ca}'.");
    Ok(())
}

fn write_binary(bytes: &[u8], output: Option<&std::path::Path>) -> Result<(), CtlError> {
    if let Some(path) = output {
        std::fs::write(path, bytes)?;
        println!("Written {} bytes to {}", bytes.len(), path.display());
    } else {
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && i % 32 == 0 {
                println!();
            }
            print!("{b:02x}");
        }
        println!();
    }
    Ok(())
}

/// Print the Witness Network log-list entry for this CA's MTC log.
pub async fn log_list_entry(client: &AdminClient, ca: &str) -> Result<(), CtlError> {
    let text = client
        .get_text(&format!("/admin/ca/{}/mtc/log-list-entry", urlenc(ca)))
        .await?;
    print!("{text}");
    Ok(())
}
