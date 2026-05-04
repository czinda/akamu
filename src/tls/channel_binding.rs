//! RFC 5929 tls-server-end-point channel binding computation.

use native_ossl::digest::DigestAlg;
use synta::Decoder;
use synta::Encoding;
use synta::ToDer as _;
use synta_certificate::oids;
use synta_certificate::pkcs1_types::RsassaPssParams;
use synta_certificate::Certificate;

/// Typed extension injected per-connection when TLS is terminated by this server.
///
/// Contains the raw `tls-server-end-point` binding bytes (the hash of the
/// leaf certificate DER per RFC 5929 §4).  Absent when the server cert uses
/// an algorithm with no defined hash (e.g. ML-DSA, Ed448).
#[derive(Clone)]
pub struct TlsServerEndpointBinding(pub Vec<u8>);

/// Compute the `tls-server-end-point` binding from a leaf certificate DER.
///
/// Returns `None` for ML-DSA (pure or composite), Ed448, and any unrecognised
/// signature algorithm, because no canonical hash function is defined for those
/// schemes in RFC 5929.  The caller should pass `None` channel bindings to
/// `gss_accept_sec_context` in that case.
///
/// RFC 5929 §4: if the cert signature uses MD5 or SHA-1, use SHA-256 instead.
pub fn tls_server_endpoint_binding(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert: Certificate<'_> = Decoder::new(cert_der, Encoding::Der).decode().ok()?;

    let sig_alg = &cert.tbs_certificate.signature;
    let oid = sig_alg.algorithm.components();
    let alg_name = sig_oid_to_alg_name(oid, sig_alg.parameters.as_ref())?;
    let alg = DigestAlg::fetch(alg_name, None).ok()?;
    alg.digest_to_vec(cert_der).ok()
}

/// Map a signature algorithm OID (and optional AlgorithmIdentifier parameters)
/// to the OpenSSL digest name for `tls-server-end-point` channel binding (RFC 5929 §4).
fn sig_oid_to_alg_name<'a>(
    oid: &[u32],
    params: Option<&synta::Element<'a>>,
) -> Option<&'static std::ffi::CStr> {
    match oid {
        // ecdsa-with-SHA256 / sha256WithRSAEncryption /
        // md5WithRSAEncryption (RFC 5929 override) / sha1WithRSAEncryption (override)
        oids::ECDSA_WITH_SHA256
        | oids::SHA256_WITH_RSA
        | oids::MD5_WITH_RSA
        | oids::SHA1_WITH_RSA => Some(c"SHA2-256"),

        // id-RSASSA-PSS: hash algorithm is encoded in the RSASSA-PSS-params SEQUENCE
        // (RFC 4055 §3.1).  RFC 5929 §4 overrides SHA-1 to SHA-256.
        oids::RSASSA_PSS => pss_hash_alg_name(params?),

        // ecdsa-with-SHA384 / sha384WithRSAEncryption
        oids::ECDSA_WITH_SHA384 | oids::SHA384_WITH_RSA => Some(c"SHA2-384"),

        // ecdsa-with-SHA512 / sha512WithRSAEncryption / id-Ed25519
        oids::ECDSA_WITH_SHA512 | oids::SHA512_WITH_RSA | oids::ED25519 => Some(c"SHA2-512"),

        // ML-DSA pure (FIPS 204): no hash in signature algorithm → skip
        oids::ML_DSA_44 | oids::ML_DSA_65 | oids::ML_DSA_87 => None,

        // Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs, NIST arc
        // 2.16.840.1.114027.80.8.1.*): no canonical hash → skip.
        // No individual constants exist; matched by prefix.
        [2, 16, 840, 1, 114027, 80, 8, 1, ..] => None,

        // id-Ed448: SHAKE-256, no tls-server-end-point defined → skip
        oids::ED448 => None,

        // Unknown: skip channel bindings (safe conservative default)
        _ => None,
    }
}

/// Extract the digest name from an `RSASSA-PSS-params` element (RFC 4055 §3.1).
///
/// The default `hashAlgorithm` when absent is id-sha1; RFC 5929 §4 overrides
/// SHA-1 to SHA-256.  Returns `None` for unknown or undecodable parameters.
fn pss_hash_alg_name(params_elem: &synta::Element<'_>) -> Option<&'static std::ffi::CStr> {
    let params_der = params_elem.to_der().ok()?;
    let pss: RsassaPssParams<'_> = Decoder::new(&params_der, Encoding::Der).decode().ok()?;
    // RFC 4055 §3.1 default: absent hashAlgorithm means id-sha1.
    let hash_oid: &[u32] = pss
        .hash_algorithm
        .as_ref()
        .map(|h| h.algorithm.components())
        .unwrap_or(oids::ID_SHA1);
    match hash_oid {
        // id-sha1 → SHA-256 override per RFC 5929 §4
        oids::ID_SHA1 | oids::ID_SHA256 => Some(c"SHA2-256"),
        oids::ID_SHA384 => Some(c"SHA2-384"),
        oids::ID_SHA512 => Some(c"SHA2-512"),
        // Unknown hash — skip channel bindings conservatively
        _ => None,
    }
}
