use std::fs;

use akamu_client::error::ClientError;
use akamu_client::hex_encode;
use akamu_client::mtc_types::CertFetchResult;
use akamu_client::MtcClient;

use crate::args::{MtcBaseArgs, MtcCertArgs, MtcCommands};
use crate::helpers::resolve_directory_url;

fn build_client(base: &MtcBaseArgs) -> Result<MtcClient, ClientError> {
    let dir_url = resolve_directory_url(&base.server, base.ca.as_deref());
    let mut client = if let Some(ca_path) = &base.server_ca {
        let pem = fs::read(ca_path)
            .map_err(|e| ClientError::Mtc(format!("--server-ca {}: {e}", ca_path.display())))?;
        MtcClient::new_with_extra_root(&dir_url, &pem)?
    } else {
        MtcClient::new(&dir_url)?
    };
    if let Some(limit) = base.max_response_bytes {
        client.set_max_response_bytes(limit);
    }
    if let Some(secs) = base.request_timeout {
        client.set_request_timeout(std::time::Duration::from_secs(secs));
    }
    Ok(client)
}

fn write_der_or_hex(data: &[u8], out: &Option<std::path::PathBuf>) -> Result<(), ClientError> {
    match out {
        Some(path) => {
            fs::write(path, data)
                .map_err(|e| ClientError::Mtc(format!("write {}: {e}", path.display())))?;
            println!("Written {} bytes to {}", data.len(), path.display());
            Ok(())
        }
        None => {
            for b in data {
                print!("{b:02x}");
            }
            println!();
            Ok(())
        }
    }
}

pub(crate) async fn cmd_mtc(cmd: MtcCommands) -> Result<(), ClientError> {
    match cmd {
        MtcCommands::TreeSize(args) => {
            let client = build_client(&args)?;
            let ts = client.tree_size().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"treeSize": ts.tree_size}))
                    .unwrap()
            );
            Ok(())
        }
        MtcCommands::Root(args) => {
            let client = build_client(&args)?;
            let root = client.root().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "treeSize": root.tree_size,
                    "rootHash": root.root_hash,
                }))
                .unwrap()
            );
            Ok(())
        }
        MtcCommands::InclusionProof(args) => {
            let client = build_client(&args.base)?;
            let proof = client.inclusion_proof(&args.cert_id).await?;
            let nodes: Vec<_> = proof.proof.iter().map(|n| &n.hash).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "leafIndex": proof.leaf_index,
                    "treeSize": proof.tree_size,
                    "proof": nodes,
                }))
                .unwrap()
            );
            Ok(())
        }
        MtcCommands::Standalone(args) => {
            let client = build_client(&args.base)?;
            let der = client.standalone_cert(&args.cert_id).await?;
            write_der_or_hex(&der, &args.out)
        }
        MtcCommands::LandmarkCert(args) => {
            let client = build_client(&args.base)?;
            match client.landmark_cert_for(&args.cert_id).await? {
                CertFetchResult::Ok(der) => {
                    if args.out.is_some() {
                        write_der_or_hex(&der, &args.out)
                    } else {
                        match akamu_client::cert_text::describe_landmark_cert_der(&der) {
                            Some(text) => {
                                print!("{text}");
                                Ok(())
                            }
                            None => write_der_or_hex(&der, &args.out),
                        }
                    }
                }
                CertFetchResult::RetryAfter(secs) => Err(ClientError::Mtc(format!(
                    "landmark not ready; retry after {secs}s"
                ))),
            }
        }
        MtcCommands::Landmarks(args) => {
            let client = build_client(&args)?;
            let landmarks = client.landmarks().await?;
            let json: Vec<_> = landmarks
                .iter()
                .map(|l| {
                    serde_json::json!({
                        "sequenceNo": l.sequence_no,
                        "treeSize": l.tree_size,
                        "createdAt": l.created_at,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
        MtcCommands::LandmarkList(args) => {
            let client = build_client(&args)?;
            let text = client.landmark_list().await?;
            print!("{text}");
            Ok(())
        }
        MtcCommands::ConsistencyProof(args) => {
            let client = build_client(&args.base)?;
            let proof = client.consistency_proof(args.from, args.to).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "fromSize": proof.from_size,
                    "toSize": proof.to_size,
                    "fromRoot": proof.from_root,
                    "toRoot": proof.to_root,
                }))
                .unwrap()
            );
            Ok(())
        }
        MtcCommands::SubtreeRoot(args) => {
            let client = build_client(&args.base)?;
            let sr = client.subtree_root(args.start, args.end).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "start": sr.start,
                    "end": sr.end,
                    "rootHash": sr.root_hash,
                }))
                .unwrap()
            );
            Ok(())
        }
        MtcCommands::RevokedRanges(args) => {
            let client = build_client(&args)?;
            let ranges = client.revoked_ranges().await?;
            println!("{}", serde_json::to_string_pretty(&ranges).unwrap());
            Ok(())
        }
        MtcCommands::Verify(args) => cmd_mtc_verify(args).await,
        MtcCommands::Checkpoint(args) => {
            let client = build_client(&args)?;
            let text = client.tlog_checkpoint().await?;
            print!("{text}");
            Ok(())
        }
    }
}

async fn cmd_mtc_verify(args: MtcCertArgs) -> Result<(), ClientError> {
    use akamu_client::{mtc_verify, HashAlgorithm};

    let algorithm = HashAlgorithm::Sha256;
    let client = build_client(&args.base)?;

    let der = if let Some(path) = &args.cert_file {
        fs::read(path).map_err(|e| ClientError::Mtc(format!("read {}: {e}", path.display())))?
    } else {
        client.standalone_cert(&args.cert_id).await?
    };

    let (details, mtc_proof) = mtc_verify::extract_cert_and_proof(&der)?;

    println!("Subject:       {}", details.subject);
    println!("Issuer:        {}", details.issuer);
    println!(
        "Validity:      {} .. {}",
        details.not_before, details.not_after
    );
    println!(
        "Serial:        0x{} (log={}, leaf={})",
        details.serial_hex, details.log_number, details.entry_index
    );
    if !details.sans.is_empty() {
        println!("SANs:          {}", details.sans.join(", "));
    }
    for ext in &details.extensions {
        let crit = if ext.critical { " (critical)" } else { "" };
        if let Some(val) = &ext.value {
            println!("Extension:     {}{}: {}", ext.name, crit, val);
        } else {
            println!("Extension:     {}{}", ext.name, crit);
        }
    }

    let leaf_hash = mtc_verify::compute_leaf_hash(&der, algorithm)?;
    println!("Leaf hash:     {}", hex_encode(&leaf_hash));

    let sibling_count = mtc_verify::proof_sibling_count(&mtc_proof, algorithm);

    let sr = client.subtree_root(mtc_proof.start, mtc_proof.end).await?;
    let root_hash = mtc_verify::parse_hex_hash(&sr.root_hash)?;
    let proof_desc = if mtc_proof.start > 0 {
        format!("subtree [{}..{})", mtc_proof.start, mtc_proof.end)
    } else {
        format!("tree at size {}", mtc_proof.end)
    };

    println!("Proof:         {proof_desc}, {sibling_count} sibling hash(es)");
    println!("Root hash:     {}", hex_encode(&root_hash));

    mtc_verify::verify_standalone_inclusion(
        &leaf_hash,
        details.entry_index,
        &mtc_proof,
        &root_hash,
        algorithm,
    )?;

    println!("Verification:  PASSED");
    Ok(())
}
