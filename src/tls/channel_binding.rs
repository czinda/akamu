//! RFC 5929 tls-server-end-point channel binding computation.

use native_ossl::digest::DigestAlg;
use synta::Decoder;
use synta::Encoding;
use synta_certificate::oids;
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

    let oid = cert.tbs_certificate.signature.algorithm.components();
    let alg_name = sig_oid_to_alg_name(oid)?;
    let alg = DigestAlg::fetch(alg_name, None).ok()?;
    alg.digest_to_vec(cert_der).ok()
}

fn sig_oid_to_alg_name(oid: &[u32]) -> Option<&'static std::ffi::CStr> {
    match oid {
        // ecdsa-with-SHA256 / sha256WithRSAEncryption /
        // md5WithRSAEncryption (RFC 5929 override) / sha1WithRSAEncryption (override)
        oids::ECDSA_WITH_SHA256
        | oids::SHA256_WITH_RSA
        | oids::MD5_WITH_RSA
        | oids::SHA1_WITH_RSA => Some(c"SHA2-256"),

        // id-RSASSA-PSS: hash is in the parameters, but SHA-256 is the
        // recommended default; treat as SHA-256 for channel-binding purposes.
        oids::RSASSA_PSS => Some(c"SHA2-256"),

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
