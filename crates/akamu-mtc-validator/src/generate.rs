//! Build MTC artifacts from parsed test vectors.
//!
//! Implements the same logic as the Go demo tool:
//!   1. Expand entries (handling Repeat and Null).
//!   2. Resolve checkpoint-based subtrees using SubtreesForInterval.
//!   3. Compute leaf hashes via synta-mtc.
//!   4. Generate inclusion proofs and subtree hashes.

use std::collections::HashMap;

use synta::types::primitive::{Integer, Null};
use synta::types::string::{OctetString, PrintableStringRef, Utf8StringRef};
use synta::{Boolean, Decoder, Encoder, Encoding, ObjectIdentifier};
use synta_certificate::{
    encode_basic_constraints, encode_key_usage, oids, parse_time, ExtendedKeyUsageBuilder,
    NameBuilder, SubjectAlternativeNameBuilder, SubjectPublicKeyInfo, Validity, KEY_USAGE_C_RLSIGN,
    KEY_USAGE_DATA_ENCIPHERMENT, KEY_USAGE_DECIPHER_ONLY, KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_ENCIPHER_ONLY, KEY_USAGE_KEY_AGREEMENT, KEY_USAGE_KEY_CERT_SIGN,
    KEY_USAGE_KEY_ENCIPHERMENT, KEY_USAGE_NON_REPUDIATION,
};
use synta_mtc::crypto::{compute_root, MtcDigest, Sha256Digest};
use synta_mtc::{
    crypto::hash::{hash_log_entry, HashAlgorithm},
    integration::parse_raw_name,
    types::{Extension, MerkleTreeCertEntry, TBSCertificateLogEntry},
};

use crate::vectors::{EntryConfig, MtcVectors, SubjectConfig};
use crate::{Error, Result};

// OID for TrustAnchorID experiment (1.3.6.1.4.1.44363.47.1) as u32 components.
const OID_TRUST_ANCHOR_ID: &[u32] = &[1, 3, 6, 1, 4, 1, 44363, 47, 1];

/// A resolved certificate that can be validated: leaf index, subtree bounds.
#[derive(Debug, Clone)]
pub struct ResolvedCert {
    /// Absolute index in the log (0-based, matching Go demo indexing).
    pub leaf_index: u64,
    /// Index into the original entry list.
    pub entry_config_idx: usize,
    /// Index into the entry's Certificates list.
    pub cert_config_idx: usize,
    pub subtree_start: u64,
    pub subtree_end: u64,
    /// IDs of cosigners specified for this cert.
    pub cosigner_ids: Vec<String>,
    /// If true, proof should have a flipped bit (negative test).
    pub bit_flip_proof: bool,
}

/// All artifacts generated from mtc.json.
#[derive(Debug)]
pub struct GeneratedArtifacts {
    /// Leaf hashes for every log entry (in order, 0-indexed, no automatic null prepended).
    pub leaf_hashes: Vec<Vec<u8>>,
    /// Resolved certificates with subtree bounds.
    pub certs: Vec<ResolvedCert>,
    /// Total number of log entries.
    pub tree_size: u64,
}

impl GeneratedArtifacts {
    /// Compute the Merkle tree root from the leaf hashes.
    pub fn compute_root(&self) -> Result<Vec<u8>> {
        compute_root(HashAlgorithm::Sha256, self.leaf_hashes.clone())
            .map_err(|e| Error::Crypto(format!("compute_root: {e}")))
    }

    /// Generate the inclusion proof for the leaf at `leaf_index`.
    pub fn generate_inclusion_proof(&self, leaf_index: u64) -> Result<Vec<Vec<u8>>> {
        synta_mtc::crypto::proof::generate_inclusion_proof(
            HashAlgorithm::Sha256,
            leaf_index,
            &self.leaf_hashes,
        )
        .map_err(|e| Error::Crypto(format!("generate_inclusion_proof({leaf_index}): {e}")))
    }

    /// Generate the subtree-relative inclusion proof for a cert.
    pub fn generate_subtree_proof(&self, cert: &ResolvedCert) -> Result<Vec<Vec<u8>>> {
        let start = cert.subtree_start as usize;
        let end = cert.subtree_end as usize;
        let idx = cert.leaf_index as usize;
        let subtree_hashes = self.leaf_hashes[start..end].to_vec();
        let rel_idx = (idx - start) as u64;
        synta_mtc::crypto::proof::generate_inclusion_proof(
            HashAlgorithm::Sha256,
            rel_idx,
            &subtree_hashes,
        )
        .map_err(|e| {
            Error::Crypto(format!(
                "generate_subtree_proof({idx}, [{start},{end})): {e}"
            ))
        })
    }

    /// Compute the subtree hash for [start, end).
    pub fn subtree_hash(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let slice = &self.leaf_hashes[start as usize..end as usize];
        synta_mtc::crypto::proof::generate_subtree_hash(HashAlgorithm::Sha256, slice)
            .map_err(|e| Error::Crypto(format!("subtree_hash([{start},{end})): {e}")))
    }
}

/// Build all MTC artifacts from the test vectors.
pub fn build_artifacts(vectors: &MtcVectors) -> Result<GeneratedArtifacts> {
    // The issuer DN carries the TrustAnchorID (the CA identifier), not the
    // LogID (which additionally encodes the log number).
    let trust_anchor_id_str = &vectors.id;

    // Build the issuer DN DER once — shared by all entries.
    let issuer_dn_der = NameBuilder::new()
        .add_attr(OID_TRUST_ANCHOR_ID, trust_anchor_id_str)
        .build()
        .map_err(|e| Error::Parse(format!("build issuer DN: {e}")))?;

    // --- Phase 1: expand entries and compute leaf hashes ---
    let mut leaf_hashes: Vec<Vec<u8>> = Vec::new();
    let mut checkpoint_seqs: HashMap<String, u64> = HashMap::new();

    struct PendingCert {
        cert_idx: usize,
        prev: u64,
    }
    let mut awaiting: HashMap<String, Vec<PendingCert>> = HashMap::new();
    let mut certs: Vec<ResolvedCert> = Vec::new();

    for (entry_config_idx, entry) in vectors.entries.iter().enumerate() {
        let repeat = entry.effective_repeat();
        for _ in 0..repeat {
            let leaf_hash = encode_entry(entry, &issuer_dn_der)?;
            leaf_hashes.push(leaf_hash);
            let entry_idx = (leaf_hashes.len() - 1) as u64;

            for (cert_config_idx, cert_cfg) in entry.certificates.iter().enumerate() {
                let cert_idx = certs.len();
                if cert_cfg.subtree_end != 0 {
                    if !cert_cfg.checkpoint.is_empty() {
                        return Err(Error::Parse(format!(
                            "entry {entry_config_idx} cert {cert_config_idx}: \
                            both Checkpoint and SubtreeEnd specified"
                        )));
                    }
                    certs.push(ResolvedCert {
                        leaf_index: entry_idx,
                        entry_config_idx,
                        cert_config_idx,
                        subtree_start: cert_cfg.subtree_start,
                        subtree_end: cert_cfg.subtree_end,
                        cosigner_ids: cert_cfg.cosigners.clone(),
                        bit_flip_proof: cert_cfg.bit_flip_proof,
                    });
                } else if !cert_cfg.checkpoint.is_empty() {
                    let seq = &cert_cfg.checkpoint;
                    let prev = *checkpoint_seqs.get(seq).unwrap_or(&0);
                    certs.push(ResolvedCert {
                        leaf_index: entry_idx,
                        entry_config_idx,
                        cert_config_idx,
                        subtree_start: 0,
                        subtree_end: 0,
                        cosigner_ids: cert_cfg.cosigners.clone(),
                        bit_flip_proof: cert_cfg.bit_flip_proof,
                    });
                    awaiting
                        .entry(seq.clone())
                        .or_default()
                        .push(PendingCert { cert_idx, prev });
                } else {
                    return Err(Error::Parse(format!(
                        "entry {entry_config_idx} cert {cert_config_idx}: \
                        neither Checkpoint nor SubtreeEnd specified"
                    )));
                }
            }

            for seq in &entry.checkpoints {
                let new_size = leaf_hashes.len() as u64;
                checkpoint_seqs.insert(seq.clone(), new_size);
                if let Some(pending) = awaiting.remove(seq) {
                    for p in pending {
                        let cert = &certs[p.cert_idx];
                        let (s1, e1, s2, e2) = subtrees_for_interval(p.prev, new_size)?;
                        let idx = cert.leaf_index as usize;
                        let (start, end) = if idx < e1 as usize {
                            (s1, e1)
                        } else {
                            (s2, e2)
                        };
                        certs[p.cert_idx].subtree_start = start;
                        certs[p.cert_idx].subtree_end = end;
                    }
                }
            }
        }
    }

    for (seq, pending) in &awaiting {
        if !pending.is_empty() {
            return Err(Error::Parse(format!(
                "checkpoint sequence {seq:?} referenced but never defined"
            )));
        }
    }

    let tree_size = leaf_hashes.len() as u64;

    Ok(GeneratedArtifacts {
        leaf_hashes,
        certs,
        tree_size,
    })
}

/// Compute the leaf hash for one log entry.
///
/// For null entries hashes `NullEntry`; for TBS cert entries builds a
/// `TBSCertificateLogEntry` and hashes it via `hash_log_entry`, matching
/// Go's plants-05 encoding.
fn encode_entry(entry: &EntryConfig, issuer_dn_der: &[u8]) -> Result<Vec<u8>> {
    if entry.null {
        let null_entry = MerkleTreeCertEntry::NullEntry(Null);
        return hash_log_entry(HashAlgorithm::Sha256, &null_entry, &[])
            .map_err(|e| Error::Crypto(format!("hash_log_entry(null): {e}")));
    }

    let spki = entry
        .public_key
        .as_deref()
        .ok_or_else(|| Error::Parse("non-null entry missing PublicKey".into()))?;

    // Parse issuer from DER bytes (built once per log).
    let issuer =
        parse_raw_name(issuer_dn_der).map_err(|e| Error::Parse(format!("parse issuer DN: {e}")))?;

    // Build subject Name.
    let subject_der = build_subject_der(entry.subject.as_ref())?;
    let subject =
        parse_raw_name(&subject_der).map_err(|e| Error::Parse(format!("parse subject DN: {e}")))?;

    // Parse validity from ISO 8601 strings.
    let not_before_str = entry
        .not_before
        .as_deref()
        .unwrap_or("2020-01-01T00:00:00Z");
    let not_after_str = entry.not_after.as_deref().unwrap_or("2030-12-31T23:59:59Z");
    let validity = Validity {
        not_before: parse_time(&iso8601_to_rfc5280(not_before_str)?)
            .map_err(|e| Error::Parse(format!("not_before: {e}")))?,
        not_after: parse_time(&iso8601_to_rfc5280(not_after_str)?)
            .map_err(|e| Error::Parse(format!("not_after: {e}")))?,
    };

    // Parse SPKI to extract algorithm (borrows from `spki` for its lifetime).
    let spki_parsed: SubjectPublicKeyInfo = Decoder::new(spki, Encoding::Der)
        .decode()
        .map_err(|e| Error::Parse(format!("parse SPKI: {e}")))?;
    let algorithm = spki_parsed.algorithm.clone();

    // Hash the SPKI bytes (plain SHA-256, no domain separation).
    let spki_hash = sha256_bytes(spki);

    // Build extensions.
    let extensions = build_extensions(entry)?;
    let extensions_field = if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    };

    // Go demo always includes the version field (v3 = integer 2).
    let log_entry = TBSCertificateLogEntry {
        version: Some(Integer::from(2u64)),
        issuer,
        validity,
        subject,
        subject_public_key_algorithm: algorithm,
        subject_public_key_info_hash: OctetString::from(spki_hash),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: extensions_field,
    };

    let mtc_entry = MerkleTreeCertEntry::TbsCertEntry(log_entry);
    hash_log_entry(HashAlgorithm::Sha256, &mtc_entry, &[])
        .map_err(|e| Error::Crypto(format!("hash_log_entry: {e}")))
}

/// Build the DER-encoded Name for the subject field.
///
/// Go's crypto/x509 uses PrintableString for printable-charset commonNames.
/// `NameBuilder::common_name()` always produces UTF8String, so for CN we
/// replicate the same three-step pattern (encode OID + value, wrap in
/// SEQUENCE/SET/SEQUENCE) but use `PrintableStringRef` when the value is
/// in the PrintableString character set and `Utf8StringRef` otherwise.
fn build_subject_der(subject: Option<&SubjectConfig>) -> Result<Vec<u8>> {
    match subject {
        None => NameBuilder::new()
            .build()
            .map_err(|e| Error::Parse(format!("empty subject: {e}"))),
        Some(s) if s.common_name.is_empty() => NameBuilder::new()
            .build()
            .map_err(|e| Error::Parse(format!("empty subject: {e}"))),
        Some(s) => build_cn_name_der(&s.common_name),
    }
}

const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];

/// Build a single-CN Name DER using PrintableString when possible, UTF8String otherwise.
fn build_cn_name_der(cn: &str) -> Result<Vec<u8>> {
    let oid = ObjectIdentifier::new(OID_COMMON_NAME)
        .map_err(|e| Error::Parse(format!("commonName OID: {e}")))?;
    let mut oid_enc = Encoder::new(Encoding::Der);
    oid_enc
        .encode(&oid)
        .map_err(|e| Error::Parse(format!("encode OID: {e}")))?;
    let oid_bytes = oid_enc
        .finish()
        .map_err(|e| Error::Parse(format!("finish OID enc: {e}")))?;

    let val_bytes = if let Ok(ps) = PrintableStringRef::new(cn) {
        let mut enc = Encoder::new(Encoding::Der);
        enc.encode(&ps)
            .map_err(|e| Error::Parse(format!("encode PS: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Parse(format!("finish PS enc: {e}")))?
    } else {
        let us = Utf8StringRef::new(cn);
        let mut enc = Encoder::new(Encoding::Der);
        enc.encode(&us)
            .map_err(|e| Error::Parse(format!("encode US: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Parse(format!("finish US enc: {e}")))?
    };

    let mut atv = Vec::with_capacity(oid_bytes.len() + val_bytes.len());
    atv.extend_from_slice(&oid_bytes);
    atv.extend_from_slice(&val_bytes);
    let atv = der_wrap(0x30, &atv);
    let rdn = der_wrap(0x31, &atv);
    Ok(der_wrap(0x30, &rdn))
}

/// Wrap `content` in a DER TLV with the given `tag`.
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.push(tag);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// Convert ISO 8601 "YYYY-MM-DDTHH:MM:SSZ" to "YYYYMMDDHHMMSSZ" for `parse_time`.
fn iso8601_to_rfc5280(iso: &str) -> Result<String> {
    let s = iso.trim_end_matches('Z');
    let parts: Vec<&str> = s.splitn(2, 'T').collect();
    if parts.len() != 2 {
        return Err(Error::Parse(format!("invalid datetime: {iso}")));
    }
    let date = parts[0].replace('-', "");
    let time = parts[1].replace(':', "");
    Ok(format!("{date}{time}Z"))
}

/// SHA-256 of `data` without domain separation.
fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    Sha256Digest::hash_raw(data)
}

/// Build extensions for a log entry using synta-certificate builders.
fn build_extensions(entry: &EntryConfig) -> Result<Vec<Extension>> {
    let mut exts: Vec<Extension> = Vec::new();

    if !entry.key_usage.is_empty() {
        let bits = parse_key_usage(&entry.key_usage);
        let value =
            encode_key_usage(bits).ok_or_else(|| Error::Parse("encode_key_usage failed".into()))?;
        exts.push(Extension {
            extn_id: ObjectIdentifier::new(oids::KEY_USAGE)
                .map_err(|e| Error::Parse(format!("KEY_USAGE OID: {e}")))?,
            critical: Some(Boolean::new(true)),
            extn_value: OctetString::from(value),
        });
    }

    if !entry.ext_key_usage.is_empty() {
        let mut b = ExtendedKeyUsageBuilder::new();
        for name in &entry.ext_key_usage {
            b = eku_add(b, name)?;
        }
        let value = b
            .build()
            .map_err(|e| Error::Parse(format!("ExtKeyUsage: {e}")))?;
        exts.push(Extension {
            extn_id: ObjectIdentifier::new(oids::EXTENDED_KEY_USAGE)
                .map_err(|e| Error::Parse(format!("EXTENDED_KEY_USAGE OID: {e}")))?,
            critical: Some(Boolean::new(true)),
            extn_value: OctetString::from(value),
        });
    }

    if !entry.dns_names.is_empty() {
        let mut b = SubjectAlternativeNameBuilder::new();
        for dns in &entry.dns_names {
            b = b.dns_name(dns);
        }
        let value = b.build().map_err(|e| Error::Parse(format!("SAN: {e}")))?;
        exts.push(Extension {
            extn_id: ObjectIdentifier::new(oids::SUBJECT_ALT_NAME)
                .map_err(|e| Error::Parse(format!("SUBJECT_ALT_NAME OID: {e}")))?,
            critical: Some(Boolean::new(true)),
            extn_value: OctetString::from(value),
        });
    }

    if entry.is_ca.is_some() || entry.max_path_len.is_some() {
        let is_ca = entry.is_ca.unwrap_or(false);
        let path_len = entry.max_path_len.map(|v| v as u64);
        let value = encode_basic_constraints(is_ca, path_len)
            .ok_or_else(|| Error::Parse("encode_basic_constraints failed".into()))?;
        exts.push(Extension {
            extn_id: ObjectIdentifier::new(oids::BASIC_CONSTRAINTS)
                .map_err(|e| Error::Parse(format!("BASIC_CONSTRAINTS OID: {e}")))?,
            // Go marks basicConstraints critical when cA=true (per RFC 5280 §4.2.1.9 SHOULD).
            critical: if is_ca {
                Some(Boolean::new(true))
            } else {
                None
            },
            extn_value: OctetString::from(value),
        });
    }

    Ok(exts)
}

/// Map key usage name strings to the bitmask for `encode_key_usage`.
fn parse_key_usage(names: &[String]) -> u16 {
    let mut bits: u16 = 0;
    for name in names {
        let bit = match name.as_str() {
            "DigitalSignature" | "digitalSignature" => KEY_USAGE_DIGITAL_SIGNATURE,
            "ContentCommitment" | "contentCommitment" | "NonRepudiation" => {
                KEY_USAGE_NON_REPUDIATION
            }
            "KeyEncipherment" | "keyEncipherment" => KEY_USAGE_KEY_ENCIPHERMENT,
            "DataEncipherment" | "dataEncipherment" => KEY_USAGE_DATA_ENCIPHERMENT,
            "KeyAgreement" | "keyAgreement" => KEY_USAGE_KEY_AGREEMENT,
            "CertSign" | "KeyCertSign" | "keyCertSign" => KEY_USAGE_KEY_CERT_SIGN,
            "CRLSign" | "cRLSign" => KEY_USAGE_C_RLSIGN,
            "EncipherOnly" | "encipherOnly" => KEY_USAGE_ENCIPHER_ONLY,
            "DecipherOnly" | "decipherOnly" => KEY_USAGE_DECIPHER_ONLY,
            _ => continue,
        };
        bits |= 1 << bit;
    }
    bits
}

/// Add an extended key usage OID by name to the builder.
fn eku_add(builder: ExtendedKeyUsageBuilder, name: &str) -> Result<ExtendedKeyUsageBuilder> {
    Ok(match name {
        "ServerAuth" | "serverAuth" => builder.server_auth(),
        "ClientAuth" | "clientAuth" => builder.client_auth(),
        "CodeSigning" | "codeSigning" => builder.code_signing(),
        "EmailProtection" | "emailProtection" => builder.email_protection(),
        "TimeStamping" | "timeStamping" => builder.time_stamping(),
        "OCSPSigning" | "oCSPSigning" => builder.ocsp_signing(),
        _ => return Err(Error::Parse(format!("unknown ExtKeyUsage: {name}"))),
    })
}

/// Compute the two power-of-2 aligned subtrees covering [start, end).
///
/// Mirrors Go's `SubtreesForInterval`. Used to resolve checkpoint-based
/// certificate subtree bounds.
pub fn subtrees_for_interval(start: u64, end: u64) -> Result<(u64, u64, u64, u64)> {
    if end <= start {
        return Err(Error::SubtreeAlignment(format!(
            "invalid interval [{start}, {end})"
        )));
    }
    if end - start == 1 {
        return Ok((start, end, start, end));
    }
    let last = end - 1;
    let split_bits = 64 - (start ^ last).leading_zeros();
    let mask = (1u64 << (split_bits - 1)) - 1;
    let mid = last & !mask;
    let left_split_bits = 64 - (!start & mask).leading_zeros();
    let start1 = start & !((1u64 << left_split_bits) - 1);
    let end1 = mid;
    let start2 = mid;
    let end2 = end;
    Ok((start1, end1, start2, end2))
}
