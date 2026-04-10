//! Hybrid composite ML-DSA TLS 1.3 SignatureScheme code points.
//!
//! Source: draft-ietf-lamps-pq-composite-sigs (IANA provisional registry).
//! Verify these code points against the current draft before shipping.
//!
//! These are advertised via `SignatureScheme::Unknown(u16)` in rustls, which
//! allows arbitrary 16-bit code points.  The corresponding
//! `verify_tls13_signature` call fires when a client presents a composite
//! CertificateVerify — at which point the verifier routes to OpenSSL.

use rustls::SignatureScheme;

pub const MLDSA44_ECDSA_P256_SHA256: u16 = 0x0901;
pub const MLDSA44_RSA2048_PKCS15_SHA256: u16 = 0x0902;
pub const MLDSA44_RSA2048_PSS_SHA256: u16 = 0x0903;
pub const MLDSA44_ED25519_SHA512: u16 = 0x0904;
pub const MLDSA65_ECDSA_P256_SHA512: u16 = 0x0905;
pub const MLDSA65_ECDSA_P384_SHA512: u16 = 0x0906;
pub const MLDSA65_RSA3072_PKCS15_SHA384: u16 = 0x0907;
pub const MLDSA65_RSA3072_PSS_SHA384: u16 = 0x0908;
pub const MLDSA65_ED25519_SHA512: u16 = 0x0909;
pub const MLDSA87_ECDSA_P384_SHA512: u16 = 0x090A;
pub const MLDSA87_ECDSA_P521_SHA512: u16 = 0x090B;
pub const MLDSA87_ED448_SHA512: u16 = 0x090C;

/// All composite ML-DSA schemes as `SignatureScheme::Unknown` values.
pub static COMPOSITE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::Unknown(MLDSA44_ECDSA_P256_SHA256),
    SignatureScheme::Unknown(MLDSA44_RSA2048_PKCS15_SHA256),
    SignatureScheme::Unknown(MLDSA44_RSA2048_PSS_SHA256),
    SignatureScheme::Unknown(MLDSA44_ED25519_SHA512),
    SignatureScheme::Unknown(MLDSA65_ECDSA_P256_SHA512),
    SignatureScheme::Unknown(MLDSA65_ECDSA_P384_SHA512),
    SignatureScheme::Unknown(MLDSA65_RSA3072_PKCS15_SHA384),
    SignatureScheme::Unknown(MLDSA65_RSA3072_PSS_SHA384),
    SignatureScheme::Unknown(MLDSA65_ED25519_SHA512),
    SignatureScheme::Unknown(MLDSA87_ECDSA_P384_SHA512),
    SignatureScheme::Unknown(MLDSA87_ECDSA_P521_SHA512),
    SignatureScheme::Unknown(MLDSA87_ED448_SHA512),
];

/// Returns `true` if `scheme` is a composite ML-DSA TLS signature scheme.
pub fn is_composite(scheme: SignatureScheme) -> bool {
    if let SignatureScheme::Unknown(code) = scheme {
        COMPOSITE_SCHEMES
            .iter()
            .any(|s| *s == SignatureScheme::Unknown(code))
    } else {
        false
    }
}
