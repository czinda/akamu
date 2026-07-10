//! Standalone MTC certificate construction (§6.1 of draft-ietf-plants-merkle-tree-certs).
//!
//! Produces a spec-compliant X.509 v3 certificate whose `signatureAlgorithm`
//! is `id-alg-mtcProof` and whose `signatureValue` carries a TLS-encoded
//! `MTCProof` (inclusion proof + cosignatures), per draft §5.

use synta::traits::Encode;
use synta::{Decoder, Element, Encoder, Encoding, Null};
use synta_certificate::{AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo};
use synta_mtc::builder::x509cert::MtcX509CertificateBuilder;
use synta_mtc::crypto::hash::HashAlgorithm;
use synta_mtc::crypto::mtcproof::{MtcProof, MtcSignature};
use synta_mtc::types::{LogID, SubtreeSignature};

use crate::error::AcmeError;

/// Pre-compute the DER encoding of the LogID issuer DN.
///
/// Returns the DER-encoded X.509 `Name` that `MtcX509CertificateBuilder` uses
/// as the standalone cert's issuer.  The same issuer must be used when computing
/// the Merkle leaf hash so that log entry verification matches.
pub fn build_logid_issuer_dn_der(
    spki_der: &[u8],
    log_algorithm: HashAlgorithm,
) -> Result<Vec<u8>, AcmeError> {
    use synta::types::string::OctetStringRef;
    use synta::{ObjectIdentifier, SetOf};
    use synta_certificate::owned::{AttributeTypeAndValue, Name};

    let log_id = build_log_id(spki_der, log_algorithm)?;

    let mut log_id_enc = Encoder::new(Encoding::Der);
    log_id
        .encode(&mut log_id_enc)
        .map_err(|e| AcmeError::Mtc(format!("encode LogID: {e}")))?;
    let log_id_der = log_id_enc
        .finish()
        .map_err(|e| AcmeError::Mtc(format!("finish LogID DER: {e}")))?;

    let attr_type = ObjectIdentifier::new(synta_mtc::types::constants::ID_RDNA_TRUST_ANCHOR_ID_EXP)
        .map_err(|_| AcmeError::Mtc("invalid trustAnchorID OID".into()))?;

    let atv = AttributeTypeAndValue {
        r#type: attr_type,
        value: Element::OctetString(OctetStringRef::new(&log_id_der)),
    };
    let name = Name::RdnSequence(vec![SetOf::from_vec(vec![atv])]);

    let mut enc = Encoder::new(Encoding::Der);
    name.encode(&mut enc)
        .map_err(|e| AcmeError::Mtc(format!("encode LogID issuer DN: {e}")))?;
    enc.finish()
        .map_err(|e| AcmeError::Mtc(format!("finish LogID issuer DN DER: {e}")))
}

/// All inputs required to build a standalone MTC certificate.
///
/// `proof` must have been generated against a Merkle tree of exactly `tree_size`
/// leaves — the caller is responsible for this invariant (generate the proof
/// and pass the tree_size atomically; see `produce_checkpoint` which does both
/// under the same `blocking_lock` guard).
///
/// `cosignature_ders` is a slice of `(cosigner_url, DER)` pairs where each DER
/// is an encoded `SubtreeSignature` collected from an external cosigner.  The URL
/// is used only for diagnostic logging on decode failure.  An empty slice produces
/// a standalone cert without any cosignatures; decoding failures for individual
/// entries are logged and skipped.
///
/// `spki_der` is the DER-encoded `SubjectPublicKeyInfo` of the MTC log's
/// signing key.  It is used to build the `LogID` that becomes the issuer DN.
pub struct StandaloneParams<'a> {
    pub cert_der: &'a [u8],
    pub leaf_index: u64,
    pub proof: Vec<Vec<u8>>,
    pub tree_size: u64,
    pub spki_der: &'a [u8],
    pub log_algorithm: HashAlgorithm,
    /// `(cosigner_url, DER)` pairs.  The URL is used only for diagnostic logging
    /// on decode failure; an empty string is acceptable when no URL is available.
    pub cosignature_ders: &'a [(String, Vec<u8>)],
    /// Log number for serialNumber encoding (draft-05 §6.1).
    pub log_number: u16,
    /// Start of the subtree range for the inclusion proof.
    /// `0` means the proof covers the full tree `[0, tree_size)`.
    pub subtree_start: u64,
}

/// Build and DER-encode an X.509 standalone MTC certificate.
///
/// The produced certificate:
/// - `serialNumber`       = `leaf_index`
/// - `signatureAlgorithm` = `id-alg-mtcProof` (OID 1.3.6.1.4.1.44363.47.0)
/// - `issuer`             = `LogID` as single-RDN DN with `id-rdna-trustAnchorID`
/// - `validity`           = from the original `TBSCertificate`
/// - `subject`            = from the original `TBSCertificate`
/// - `signatureValue`     = TLS-encoded `MTCProof`
pub fn build_standalone_der(p: StandaloneParams<'_>) -> Result<Vec<u8>, AcmeError> {
    let StandaloneParams {
        cert_der,
        leaf_index,
        proof,
        tree_size,
        spki_der,
        log_algorithm,
        cosignature_ders,
        log_number,
        subtree_start,
    } = p;

    let log_id = build_log_id(spki_der, log_algorithm)?;

    let mut signatures: Vec<MtcSignature> = Vec::new();
    for (i, (url, der)) in cosignature_ders.iter().enumerate() {
        match extract_mtc_signature(der) {
            Ok((sig, cosig_start, cosig_end)) => {
                if cosig_start == subtree_start && cosig_end == tree_size {
                    signatures.push(sig);
                } else {
                    tracing::debug!(
                        cosig_start,
                        cosig_end,
                        subtree_start,
                        tree_size,
                        cosigner_url = %url,
                        "skipping cosignature: subtree range mismatch"
                    );
                }
            }
            Err(e) => tracing::warn!(
                index = i,
                cosigner_url = %url,
                "extract MtcSignature from cosignature DER: {e}"
            ),
        }
    }

    // §6.1: signatures MUST be ordered by cosigner_id (shorter first, then lex)
    // and MUST have unique cosigner IDs.
    signatures.sort_by(|a, b| {
        a.cosigner_id
            .len()
            .cmp(&b.cosigner_id.len())
            .then_with(|| a.cosigner_id.cmp(&b.cosigner_id))
    });
    signatures.dedup_by(|a, b| a.cosigner_id == b.cosigner_id);

    let inclusion_proof_bytes: Vec<u8> = proof.into_iter().flatten().collect();

    let mtc_proof = MtcProof {
        extensions: vec![],
        start: subtree_start,
        end: tree_size,
        inclusion_proof: inclusion_proof_bytes,
        signatures,
    };

    // cert_der from the DB is the full Certificate DER; extract only the TBSCertificate.
    let full_cert: Certificate<'_> = Decoder::new(cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("parse cert DER for TBS extraction: {e}")))?;
    let mut tbs_enc = Encoder::new(Encoding::Der);
    full_cert
        .tbs_certificate
        .encode(&mut tbs_enc)
        .map_err(|e| AcmeError::Mtc(format!("encode TBSCertificate for standalone: {e}")))?;
    let tbs_der = tbs_enc
        .finish()
        .map_err(|e| AcmeError::Mtc(format!("finish TBSCertificate DER for standalone: {e}")))?;

    MtcX509CertificateBuilder::new()
        .original_tbs_der(&tbs_der)
        .log_id(log_id)
        .log_entry_index(leaf_index)
        .log_number(log_number)
        .mtc_proof(mtc_proof)
        .build()
        .map_err(|e| AcmeError::Mtc(format!("build MtcX509 standalone cert: {e}")))
}

/// Construct a `LogID` from a DER-encoded SPKI and a hash algorithm.
///
/// Called by both `build_standalone_der` (in this module) and
/// `checkpoint::build_checkpoint_der`; kept `pub(crate)` so those callers
/// do not duplicate the SPKI-decode + OID-lookup logic.
pub(crate) fn build_log_id(
    spki_der: &[u8],
    log_algorithm: HashAlgorithm,
) -> Result<LogID<'_>, AcmeError> {
    let spki: SubjectPublicKeyInfo = Decoder::new(spki_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode MTC signing key SPKI for LogID: {e}")))?;

    let hash_oid = super::hash_algorithm_to_oid(log_algorithm)?;

    Ok(LogID {
        hash_algorithm: AlgorithmIdentifier {
            algorithm: hash_oid,
            parameters: Some(Element::Null(Null)),
        },
        public_key: spki,
    })
}

/// Extract an `MtcSignature` plus the cosignature's subtree range from a
/// DER-encoded `SubtreeSignature`.
///
/// Returns `(signature, subtree_start, subtree_end)` so callers can filter
/// cosignatures by subtree range.
fn extract_mtc_signature(cosig_der: &[u8]) -> Result<(MtcSignature, u64, u64), AcmeError> {
    let sig: SubtreeSignature<'_> = Decoder::new(cosig_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode SubtreeSignature: {e}")))?;

    let cosig_start: u64 = sig
        .subtree
        .start
        .as_u64()
        .map_err(|e| AcmeError::Mtc(format!("subtree start: {e}")))?;
    let cosig_end: u64 = sig
        .subtree
        .end
        .as_u64()
        .map_err(|e| AcmeError::Mtc(format!("subtree end: {e}")))?;

    let mut enc = Encoder::new(Encoding::Der);
    sig.cosigner
        .encode(&mut enc)
        .map_err(|e| AcmeError::Mtc(format!("encode CosignerID: {e}")))?;
    let cosigner_id_der = enc
        .finish()
        .map_err(|e| AcmeError::Mtc(format!("finish CosignerID DER: {e}")))?;

    let signature_value = sig.signature.as_bytes().to_vec();

    Ok((
        MtcSignature {
            cosigner_id: cosigner_id_der,
            signature_value,
        },
        cosig_start,
        cosig_end,
    ))
}
