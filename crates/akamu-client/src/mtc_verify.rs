//! MTC standalone certificate verification: parsing, leaf hashing, and inclusion proof checks.

use synta::{Decoder, Encoding};
use synta_certificate::{
    decode_extensions, extension_oid_name, format_dn, format_extension_value, Certificate, Time,
};
use synta_mtc::crypto::mtcproof::MtcProof;
use synta_mtc::crypto::{
    hash_log_entry, verify_inclusion_proof, verify_subtree_inclusion_proof, HashAlgorithm,
};
use synta_mtc::types::MerkleTreeCertEntry;

use crate::error::ClientError;

#[derive(Debug, Clone)]
pub struct ExtensionDetail {
    pub name: String,
    pub critical: bool,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CertDetails {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_hex: String,
    pub entry_index: u64,
    pub log_number: u64,
    pub sans: Vec<String>,
    pub extensions: Vec<ExtensionDetail>,
}

fn split_serial(serial: u64) -> (u64, u64) {
    let entry_index = serial & ((1u64 << 48) - 1);
    let log_number = serial >> 48;
    (entry_index, log_number)
}

fn fmt_time(t: &Time) -> String {
    const M: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match t {
        Time::UtcTime(u) => format!(
            "{} {:2} {:02}:{:02}:{:02} {} GMT",
            M.get(u.month.wrapping_sub(1) as usize).unwrap_or(&"???"),
            u.day,
            u.hour,
            u.minute,
            u.second,
            u.year,
        ),
        Time::GeneralTime(g) => format!(
            "{} {:2} {:02}:{:02}:{:02} {} GMT",
            M.get(g.month.wrapping_sub(1) as usize).unwrap_or(&"???"),
            g.day,
            g.hour,
            g.minute,
            g.second,
            g.year,
        ),
    }
}

pub fn extract_cert_and_proof(der: &[u8]) -> Result<(CertDetails, MtcProof), ClientError> {
    let cert: Certificate<'_> = Decoder::new(der, Encoding::Der)
        .decode()
        .map_err(|e| ClientError::Mtc(format!("parse cert DER: {e}")))?;

    let proof_bytes = cert.signature_value.as_bytes();
    let proof = MtcProof::decode(proof_bytes)
        .map_err(|e| ClientError::Mtc(format!("decode MtcProof: {e}")))?;

    let details = extract_cert_details_from(&cert)?;
    Ok((details, proof))
}

fn extract_cert_details_from(cert: &Certificate<'_>) -> Result<CertDetails, ClientError> {
    let tbs = &cert.tbs_certificate;

    let subject = format_dn(tbs.subject.as_bytes());
    let issuer = format_dn(tbs.issuer.as_bytes());
    let not_before = fmt_time(&tbs.validity.not_before);
    let not_after = fmt_time(&tbs.validity.not_after);

    let serial_hex = native_ossl::util::hex_encode(tbs.serial_number.as_bytes());
    let serial_u64 = tbs
        .serial_number
        .as_u64()
        .map_err(|e| ClientError::Mtc(format!("serial number too large for u64: {e}")))?;
    let (entry_index, log_number) = split_serial(serial_u64);

    let sans: Vec<String> = cert
        .subject_alt_names()
        .iter()
        .map(|(tag, value)| match tag {
            0 => {
                if let Some(krb5) = synta_krb5::principal::decode_krb5_san(value) {
                    format!("KRB5:{krb5}")
                } else {
                    format!("otherName:{} bytes", value.len())
                }
            }
            1 => {
                let email = std::str::from_utf8(value).unwrap_or("<invalid UTF-8>");
                format!("email:{email}")
            }
            2 => {
                let dns = std::str::from_utf8(value).unwrap_or("<invalid UTF-8>");
                format!("DNS:{dns}")
            }
            6 => {
                let uri = std::str::from_utf8(value).unwrap_or("<invalid UTF-8>");
                format!("URI:{uri}")
            }
            7 if value.len() == 4 => {
                format!("IP:{}.{}.{}.{}", value[0], value[1], value[2], value[3])
            }
            7 if value.len() == 16 => {
                let parts: Vec<String> = value
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                format!("IP:{}", parts.join(":"))
            }
            _ => format!("tag={tag}, {} bytes", value.len()),
        })
        .collect();

    let extensions = if let Some(exts_raw) = &tbs.extensions {
        decode_extensions(exts_raw.as_bytes())
            .into_iter()
            .map(|ext| {
                let name = extension_oid_name(&ext.extn_id);
                let critical = ext.critical.map(bool::from).unwrap_or(false);
                let value = format_extension_value(&ext);
                ExtensionDetail {
                    name,
                    critical,
                    value,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(CertDetails {
        subject,
        issuer,
        not_before,
        not_after,
        serial_hex,
        entry_index,
        log_number,
        sans,
        extensions,
    })
}

pub fn compute_leaf_hash(der: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, ClientError> {
    let cert: Certificate<'_> = Decoder::new(der, Encoding::Der)
        .decode()
        .map_err(|e| ClientError::Mtc(format!("parse cert DER: {e}")))?;
    let mut log_entry =
        synta_mtc::integration::tbs_certificate_to_log_entry(&cert.tbs_certificate, algorithm)
            .map_err(|e| ClientError::Mtc(format!("build log entry: {e}")))?;
    log_entry.version = cert.tbs_certificate.version.clone();
    let entry = MerkleTreeCertEntry::TbsCertEntry(log_entry);
    hash_log_entry(algorithm, &entry, &[]).map_err(|e| ClientError::Mtc(format!("hash: {e}")))
}

pub fn verify_standalone_inclusion(
    leaf_hash: &[u8],
    entry_index: u64,
    mtc_proof: &MtcProof,
    root_or_subtree_hash: &[u8],
    algorithm: HashAlgorithm,
) -> Result<(), ClientError> {
    let subtree_size = mtc_proof.end.checked_sub(mtc_proof.start).ok_or_else(|| {
        ClientError::Mtc(format!(
            "invalid proof: end ({}) < start ({})",
            mtc_proof.end, mtc_proof.start
        ))
    })?;
    if mtc_proof.inclusion_proof.is_empty() {
        if subtree_size <= 1 {
            if leaf_hash == root_or_subtree_hash {
                return Ok(());
            }
            return Err(ClientError::Mtc(
                "single-leaf tree: leaf hash does not match root".into(),
            ));
        }
        return Err(ClientError::Mtc(format!(
            "empty inclusion proof but subtree has {subtree_size} leaves"
        )));
    }

    let hash_size = algorithm.output_size();
    if !mtc_proof.inclusion_proof.len().is_multiple_of(hash_size) {
        return Err(ClientError::Mtc(format!(
            "inclusion proof length {} is not a multiple of hash size {hash_size}",
            mtc_proof.inclusion_proof.len()
        )));
    }
    let sibling_hashes: Vec<Vec<u8>> = mtc_proof
        .inclusion_proof
        .chunks(hash_size)
        .map(|c| c.to_vec())
        .collect();

    if mtc_proof.start > 0 {
        verify_subtree_inclusion_proof(
            algorithm,
            entry_index,
            mtc_proof.start,
            mtc_proof.end,
            leaf_hash,
            &sibling_hashes,
            root_or_subtree_hash,
        )
        .map_err(|e| ClientError::Mtc(format!("subtree inclusion proof: {e}")))
    } else {
        verify_inclusion_proof(
            algorithm,
            entry_index,
            mtc_proof.end,
            leaf_hash,
            &sibling_hashes,
            root_or_subtree_hash,
        )
        .map_err(|e| ClientError::Mtc(format!("inclusion proof: {e}")))
    }
}

pub fn proof_sibling_count(mtc_proof: &MtcProof, algorithm: HashAlgorithm) -> usize {
    let hash_size = algorithm.output_size();
    if mtc_proof.inclusion_proof.is_empty() {
        0
    } else {
        mtc_proof.inclusion_proof.len() / hash_size
    }
}

pub fn parse_hex_hash(hex_str: &str) -> Result<Vec<u8>, ClientError> {
    if !hex_str.is_ascii() {
        return Err(ClientError::Mtc(format!(
            "hex hash contains non-ASCII characters: {hex_str:?}"
        )));
    }
    if !hex_str.len().is_multiple_of(2) {
        return Err(ClientError::Mtc(format!(
            "hex hash must have even length, got {}: {hex_str:?}",
            hex_str.len()
        )));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| ClientError::Mtc(format!("invalid hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_valid() {
        assert_eq!(
            parse_hex_hash("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn parse_hex_empty() {
        assert_eq!(parse_hex_hash("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_hex_odd_length_rejected() {
        assert!(parse_hex_hash("abc").is_err());
    }

    #[test]
    fn parse_hex_invalid_chars_rejected() {
        assert!(parse_hex_hash("zzzz").is_err());
    }

    #[test]
    fn parse_hex_uppercase() {
        assert_eq!(parse_hex_hash("AABB").unwrap(), vec![0xaa, 0xbb]);
    }
}
