//! `akamu-jose` — JWK/JWS primitives for ACME (RFC 7515/7638).
//!
//! Supports classical algorithms (EC, RSA, OKP) and post-quantum ML-DSA
//! per draft-ietf-cose-dilithium-11.  No axum, rusqlite, or server-specific
//! dependencies.

pub mod error;
pub mod jwk;
pub mod jws;
pub mod jwt;

pub use error::JoseError;
pub use jwk::JwkPublic;
pub use jws::{JwsFlattened, JwsKeyRef, JwsProtectedHeader};
pub use jwt::{x5c_leaf_der, AuthorityToken, AuthorityTokenHeader};
