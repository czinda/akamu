//! Standalone MTC certificate construction (§6.1 of draft-ietf-plants-merkle-tree-certs).
//!
//! A `StandaloneCertificate` embeds the `TBSCertificate`, a Merkle inclusion
//! proof, and a signature, allowing relying parties to verify that the
//! certificate is present in the MTC log without querying the CA.

use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::{BackendPrivateKey, Certificate, CertificateSigner as _, PrivateKey as _};
use synta_mtc::builder::cert::StandaloneCertificateBuilder;
use synta_mtc::crypto::HashAlgorithm;
use synta_mtc::types::SubtreeSignature;

use crate::error::AcmeError;

/// All inputs required to build a `StandaloneCertificate`.
///
/// `proof` must have been generated against a Merkle tree of exactly `tree_size`
/// leaves — the caller is responsible for this invariant (generate the proof
/// and pass the tree_size atomically; see `produce_checkpoint` which does both
/// under the same `blocking_lock` guard).
///
/// `cosignature_ders` is a slice of DER-encoded `SubtreeSignature` values collected
/// from external cosigners.  An empty slice produces a standalone cert without
/// any cosignatures; decoding failures for individual entries are logged and skipped.
pub struct StandaloneParams<'a> {
    pub cert_der: &'a [u8],
    pub leaf_index: u64,
    pub proof: Vec<(bool, Vec<u8>)>,
    pub tree_size: u64,
    pub signing_key: &'a BackendPrivateKey,
    pub hash_alg_str: &'a str,
    pub log_algorithm: HashAlgorithm,
    pub cosignature_ders: &'a [Vec<u8>],
}

/// Build and DER-encode a `StandaloneCertificate` for the given certificate DER.
pub fn build_standalone_der(p: StandaloneParams<'_>) -> Result<Vec<u8>, AcmeError> {
    let StandaloneParams {
        cert_der,
        leaf_index,
        proof,
        tree_size,
        signing_key,
        hash_alg_str,
        log_algorithm,
        cosignature_ders,
    } = p;
    use synta::types::string::BitString;

    // Parse the full certificate to extract TBSCertificate (borrows from cert_der).
    let cert: Certificate<'_> = Decoder::new(cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode cert for standalone: {e}")))?;
    let tbs = cert.tbs_certificate;

    // DER-encode TBSCertificate so it can be signed.
    let mut enc = Encoder::new(Encoding::Der);
    tbs.encode(&mut enc)
        .map_err(|e| AcmeError::Mtc(format!("encode TBSCertificate: {e}")))?;
    let tbs_bytes = enc
        .finish()
        .map_err(|e| AcmeError::Mtc(format!("finish TBSCertificate DER: {e}")))?;

    // Sign and retrieve the DER-encoded AlgorithmIdentifier for the signature.
    let signer = signing_key.as_signer(hash_alg_str);
    let sig_bytes = signer
        .sign_tbs(&tbs_bytes)
        .map_err(|e| AcmeError::Mtc(format!("sign standalone TBS: {e}")))?;
    let sig_alg_der = signer
        .signature_algorithm_der()
        .map_err(|e| AcmeError::Mtc(format!("signature_algorithm_der: {e}")))?;

    // Decode AlgorithmIdentifier from its DER representation (borrows from sig_alg_der).
    let sig_alg = Decoder::new(&sig_alg_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode AlgorithmIdentifier: {e}")))?;

    // Decode each cosignature DER into a SubtreeSignature (borrows from cosignature_ders).
    let mut subtree_sigs: Vec<SubtreeSignature<'_>> = Vec::new();
    for (i, der) in cosignature_ders.iter().enumerate() {
        match Decoder::new(der, Encoding::Der).decode::<SubtreeSignature<'_>>() {
            Ok(sig) => subtree_sigs.push(sig),
            Err(e) => tracing::warn!(index = i, "decode SubtreeSignature for standalone: {e}"),
        }
    }

    // Build the StandaloneCertificate.
    let mut builder = StandaloneCertificateBuilder::new()
        .tbs_certificate(tbs)
        .log_entry_index(leaf_index)
        .with_proof_path(proof, tree_size)
        .hash_algorithm(log_algorithm)
        .signature_algorithm(sig_alg)
        .signature(
            BitString::new(sig_bytes, 0)
                .map_err(|e| AcmeError::Mtc(format!("build BitString signature: {e}")))?,
        );

    for sig in subtree_sigs {
        builder = builder.add_subtree_signature(sig);
    }

    let standalone = builder
        .build()
        .map_err(|e| AcmeError::Mtc(format!("build StandaloneCertificate: {e}")))?;

    standalone
        .to_der()
        .map_err(|e| AcmeError::Mtc(format!("DER-encode StandaloneCertificate: {e}")))
}
