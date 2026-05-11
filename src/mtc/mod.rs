pub mod checkpoint;
pub mod cosign;
pub mod landmark;
pub mod log;
pub mod standalone;
pub mod tlog;

use synta::ObjectIdentifier;
use synta_certificate::oids::{
    ID_SHA256, ID_SHA384, ID_SHA3_256, ID_SHA3_384, ID_SHA3_512, ID_SHA512,
};
use synta_mtc::crypto::HashAlgorithm;

use crate::error::AcmeError;

/// Map a `HashAlgorithm` variant to the corresponding ASN.1 `ObjectIdentifier`.
///
/// Covers all six variants: SHA-256/384/512 and SHA3-256/384/512.
/// Uses named OID constants from `synta_certificate::oids` to avoid raw-integer
/// maintenance hazards; callers in `standalone` and `landmark` use this instead
/// of duplicating the match.
///
/// The `Result` is a formality: `ObjectIdentifier::new` only fails for malformed
/// arc sequences, which cannot happen with the compile-time constants used here.
pub(super) fn hash_algorithm_to_oid(alg: HashAlgorithm) -> Result<ObjectIdentifier, AcmeError> {
    match alg {
        HashAlgorithm::Sha256 => ObjectIdentifier::new(ID_SHA256),
        HashAlgorithm::Sha384 => ObjectIdentifier::new(ID_SHA384),
        HashAlgorithm::Sha512 => ObjectIdentifier::new(ID_SHA512),
        HashAlgorithm::Sha3_256 => ObjectIdentifier::new(ID_SHA3_256),
        HashAlgorithm::Sha3_384 => ObjectIdentifier::new(ID_SHA3_384),
        HashAlgorithm::Sha3_512 => ObjectIdentifier::new(ID_SHA3_512),
    }
    .map_err(|e| AcmeError::Mtc(format!("hash algorithm OID: {e}")))
}
