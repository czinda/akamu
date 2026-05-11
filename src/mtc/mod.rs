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
/// Uses named OID constants from `synta_certificate::oids` to avoid raw-integer
/// maintenance hazards across the three modules that need this mapping.
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
