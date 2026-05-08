//! C2SP tlog-tiles and signed-note support for the MTC transparency log.
//!
//! Implements:
//! - C2SP signed-note checkpoint format (tlog-checkpoint spec)
//! - Key ID computation for **all** C2SP signed-note signature types
//! - Cosignature note production (tlog-cosignature spec)
//! - Hash tile computation (tlog-tiles spec, levels 0..N)
//! - Tile index URL path encoding/decoding
//!
//! # C2SP signed-note signature types
//!
//! | Type | Description | Key ID formula |
//! |------|-------------|----------------|
//! | 0x01 | Ed25519 (log operator) | `SHA-256(name \|\| LF \|\| 0x01 \|\| 32-byte pubkey)[:4]` |
//! | 0x02 | ECDSA P-256/P-384/P-521 | `SHA-256(SPKI_DER)[:4]` |
//! | 0x04 | Timestamped Ed25519 cosignature | `SHA-256(name \|\| LF \|\| 0x04 \|\| 32-byte pubkey)[:4]` |
//! | 0x05 | RFC 6962 TreeHeadSignature | per c2sp.org/static-ct-api |
//! | 0x06 | Timestamped ML-DSA-44 cosignature | `SHA-256(name \|\| LF \|\| 0x06 \|\| 1312-byte pubkey)[:4]` |
//!
//! Types 0x01 and 0x02 are for the **primary log operator**.
//! Types 0x04 and 0x06 are for **cosigners** (including Akāmu acting as a
//! cosigner for another log via `sign_as_cosigner`).
//! Type 0x05 is a CT-log compatibility type; its key ID and signature format
//! are defined in c2sp.org/static-ct-api and are not produced here.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use synta_certificate::{
    default_data_hasher, CertificateSigner, DataHasher, PrivateKey, SubjectPublicKeyInfo,
};
use synta_mtc::crypto::{hash_interior, HashAlgorithm};

use crate::error::AcmeError;
use crate::mtc::log::{read_hash_range, tree_size_and_root, SharedLog};

// ── Tile constants ────────────────────────────────────────────────────────────

/// Number of hash entries per full tile (and branching factor per tree level).
const TILE_WIDTH: usize = 256;

/// Maximum supported tile level.  256^6 ≈ 281 trillion entries — more than any
/// realistic log will reach.  Requests for higher levels are rejected with 400.
const MAX_TILE_LEVEL: u32 = 6;

/// ML-DSA-44 public key length per FIPS 204.
const ML_DSA_44_PUBKEY_LEN: usize = 1312;

/// ML-DSA-44 signature length per FIPS 204.
const ML_DSA_44_SIG_LEN: usize = 2420;

// ── C2SP signed-note type bytes ───────────────────────────────────────────────

/// Ed25519 primary log operator (type 0x01).
const NOTE_TYPE_ED25519_OPERATOR: u8 = 0x01;
/// ECDSA P-256/P-384/P-521 (type 0x02; applies to both operator and cosigner roles).
const NOTE_TYPE_ECDSA: u8 = 0x02;
/// Timestamped Ed25519 cosignature (type 0x04).
const NOTE_TYPE_ED25519_COSIGNER: u8 = 0x04;
/// Timestamped ML-DSA-44 cosignature (type 0x06).
const NOTE_TYPE_ML_DSA_44_COSIGNER: u8 = 0x06;

// ── Signing role ──────────────────────────────────────────────────────────────

/// Whether the key is used as the primary log operator or as an external cosigner.
///
/// The role determines which C2SP signature type byte is selected:
///
/// | Key type   | `LogOperator` type | `Cosigner` type |
/// |------------|-------------------|-----------------|
/// | Ed25519    | 0x01              | 0x04            |
/// | ECDSA      | 0x02              | 0x02 (same)     |
/// | ML-DSA-44  | (unsupported)     | 0x06            |
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NoteSigningRole {
    /// Primary log operator; signs the checkpoint note body directly.
    LogOperator,
    /// External cosigner; embeds a timestamp and uses the tlog-cosignature
    /// message format before signing.
    Cosigner,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract the raw public key bytes from a DER-encoded SubjectPublicKeyInfo.
fn raw_pubkey_from_spki(spki_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let spki = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| AcmeError::Mtc(format!("parse SPKI for key ID: {e}")))?;
    Ok(spki.subject_public_key.as_bytes().to_vec())
}

/// Compute `SHA-256(name || 0x0A || type_byte || raw_pubkey)[:4]`.
fn key_id_from_bytes(
    key_name: &str,
    type_byte: u8,
    raw_pubkey: &[u8],
) -> Result<[u8; 4], AcmeError> {
    let mut input = Vec::with_capacity(key_name.len() + 2 + raw_pubkey.len());
    input.extend_from_slice(key_name.as_bytes());
    input.push(0x0A); // line-feed separator per C2SP signed-note spec
    input.push(type_byte);
    input.extend_from_slice(raw_pubkey);
    let hash = default_data_hasher()
        .hash_data("sha256", &input)
        .map_err(|e| AcmeError::Mtc(format!("SHA-256 for key ID: {e}")))?;
    hash.get(..4)
        .ok_or_else(|| AcmeError::Mtc("SHA-256 output too short for key ID".into()))?
        .try_into()
        .map_err(|_| AcmeError::Mtc("key ID conversion failed".into()))
}

// ── Key ID computation ────────────────────────────────────────────────────────

/// Compute the C2SP signed-note type byte and 4-byte key ID for the given key and role.
///
/// Returns `(type_byte, key_id)`:
/// - Ed25519 + `LogOperator`  → `(NOTE_TYPE_ED25519_OPERATOR, SHA-256(name||LF||0x01||pubkey)[:4])`
/// - Ed25519 + `Cosigner`     → `(NOTE_TYPE_ED25519_COSIGNER, SHA-256(name||LF||0x04||pubkey)[:4])`
/// - ECDSA (any role)         → `(NOTE_TYPE_ECDSA, SHA-256(SPKI_DER)[:4])`
/// - ML-DSA-44 + `Cosigner`  → `(NOTE_TYPE_ML_DSA_44_COSIGNER, SHA-256(name||LF||0x06||pubkey)[:4])`
///
/// Returns an error for Ed448, RSA, ML-DSA-44 as `LogOperator`, or any other
/// key type without a defined C2SP signed-note type byte.
pub fn compute_key_id(
    key_name: &str,
    key: &synta_certificate::BackendPrivateKey,
    role: NoteSigningRole,
) -> Result<(u8, [u8; 4]), AcmeError> {
    let pub_key = key
        .public_key()
        .map_err(|e| AcmeError::Mtc(format!("get public key for key ID: {e}")))?;
    let spki_der = pub_key.spki_der();

    match (key.key_type(), role) {
        ("ed25519", NoteSigningRole::LogOperator) => {
            let raw = raw_pubkey_from_spki(spki_der)?;
            if raw.len() != 32 {
                return Err(AcmeError::Mtc(format!(
                    "Ed25519 public key must be 32 bytes, got {}",
                    raw.len()
                )));
            }
            Ok((
                NOTE_TYPE_ED25519_OPERATOR,
                key_id_from_bytes(key_name, NOTE_TYPE_ED25519_OPERATOR, &raw)?,
            ))
        }
        ("ed25519", NoteSigningRole::Cosigner) => {
            let raw = raw_pubkey_from_spki(spki_der)?;
            if raw.len() != 32 {
                return Err(AcmeError::Mtc(format!(
                    "Ed25519 public key must be 32 bytes, got {}",
                    raw.len()
                )));
            }
            Ok((
                NOTE_TYPE_ED25519_COSIGNER,
                key_id_from_bytes(key_name, NOTE_TYPE_ED25519_COSIGNER, &raw)?,
            ))
        }
        ("ec", _) => {
            // Applies to both LogOperator and Cosigner roles (no ECDSA cosig type defined).
            let hash = default_data_hasher()
                .hash_data("sha256", spki_der)
                .map_err(|e| AcmeError::Mtc(format!("SHA-256 ECDSA SPKI: {e}")))?;
            let key_id = hash
                .get(..4)
                .ok_or_else(|| AcmeError::Mtc("SHA-256 output too short for key ID".into()))?
                .try_into()
                .map_err(|_| AcmeError::Mtc("key ID conversion failed".into()))?;
            Ok((NOTE_TYPE_ECDSA, key_id))
        }
        ("ml-dsa-44", NoteSigningRole::Cosigner) => {
            let raw = raw_pubkey_from_spki(spki_der)?;
            if raw.len() != ML_DSA_44_PUBKEY_LEN {
                return Err(AcmeError::Mtc(format!(
                    "ML-DSA-44 public key must be {} bytes, got {}",
                    ML_DSA_44_PUBKEY_LEN,
                    raw.len()
                )));
            }
            Ok((
                NOTE_TYPE_ML_DSA_44_COSIGNER,
                key_id_from_bytes(key_name, NOTE_TYPE_ML_DSA_44_COSIGNER, &raw)?,
            ))
        }
        ("ml-dsa-44", NoteSigningRole::LogOperator) => Err(AcmeError::Mtc(
            "ML-DSA-44 is not a valid primary log operator key type in C2SP signed-note; \
             use Cosigner role (type 0x06) or switch to Ed25519 / ECDSA P-256"
                .into(),
        )),
        ("ed448", _) => Err(AcmeError::Mtc(
            "Ed448 has no assigned C2SP signed-note type byte; \
             use Ed25519 (type 0x01/0x04) or ECDSA P-256 (type 0x02)"
                .into(),
        )),
        ("rsa", _) => Err(AcmeError::Mtc(
            "RSA has no assigned C2SP signed-note type byte; \
             use Ed25519 (type 0x01/0x04) or ECDSA P-256 (type 0x02)"
                .into(),
        )),
        // Type 0x05 (RFC 6962 TreeHeadSignature) is not generated by Akāmu.
        (t, _) => Err(AcmeError::Mtc(format!(
            "key type '{t}' has no C2SP signed-note type byte supported by Akāmu"
        ))),
    }
}

// ── Note body and primary operator signing ────────────────────────────────────

/// Build the C2SP tlog-checkpoint note body (unsigned).
///
/// Format: `{origin}\n{tree_size}\n{base64(root_hash)}\n`
pub fn checkpoint_note_body(origin: &str, tree_size: u64, root_hash: &[u8]) -> String {
    format!("{}\n{}\n{}\n", origin, tree_size, BASE64.encode(root_hash))
}

/// Sign `data` with a `BackendPrivateKey`, returning the raw signature bytes.
///
/// For Ed25519: signs directly (no pre-hash, per RFC 8032) → 64 bytes.
/// For ECDSA: pre-hashes with `hash_alg`, then signs → DER-encoded ECDSA sig.
/// For ML-DSA-44: signs directly (pure lattice signature) → 2420 bytes.
fn raw_sign(
    key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    data: &[u8],
) -> Result<Vec<u8>, AcmeError> {
    key.as_signer(hash_alg)
        .sign_tbs(data)
        .map_err(|e| AcmeError::Mtc(format!("sign: {e}")))
}

/// Produce a complete C2SP signed-note for a checkpoint, signed by the **log
/// operator** (types 0x01 for Ed25519, 0x02 for ECDSA).
///
/// Returned format:
/// ```text
/// <origin>
/// <tree_size>
/// <base64(root_hash)>
///
/// — <key_name> <base64(key_id || signature)>
/// ```
pub fn sign_checkpoint_as_operator(
    key_name: &str,
    key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    origin: &str,
    tree_size: u64,
    root_hash: &[u8],
) -> Result<String, AcmeError> {
    let body = checkpoint_note_body(origin, tree_size, root_hash);
    let (type_byte, key_id) = compute_key_id(key_name, key, NoteSigningRole::LogOperator)?;
    let sig = raw_sign(key, hash_alg, body.as_bytes())?;

    // Wire format: type_byte(1) || key_id(4) || signature
    let mut blob = Vec::with_capacity(1 + 4 + sig.len());
    blob.push(type_byte);
    blob.extend_from_slice(&key_id);
    blob.extend_from_slice(&sig);

    Ok(format!(
        "{body}\n\u{2014} {key_name} {}\n",
        BASE64.encode(&blob)
    ))
}

// ── Cosignature production ────────────────────────────────────────────────────

/// Produce a complete C2SP signed-note cosignature for a checkpoint.
///
/// The cosignature includes a POSIX timestamp (seconds since Unix epoch).
///
/// **Ed25519 cosignature (type 0x04):**
/// Signed message = `"cosignature/v1\ntime {ts}\n{body}"`.
/// Signature blob = `u64_be(ts) || ed25519_sig`.
///
/// **ML-DSA-44 cosignature (type 0x06):**
/// Signed message = binary `cosigned_message`:
/// `"subtree/v1\n\0" || u8(len) || cosigner_name || u64_be(ts) ||
///  u8(len) || origin || u64_be(0) || u64_be(tree_size) || root_hash`.
/// Signature blob = `u64_be(ts) || ml_dsa_44_sig`.
///
/// Returns the full signed-note string with the cosignature appended.
///
/// # Arguments
///
/// * `cosigner_name` — The cosigner's note key name (= its note verifier ID).
/// * `key` — The cosigner's private key (Ed25519 or ML-DSA-44).
/// * `hash_alg` — Hash algorithm string for ECDSA keys (ignored for Ed25519/ML-DSA).
/// * `origin` — The log's tlog origin (first line of the checkpoint body).
/// * `tree_size` — The tree size from the checkpoint.
/// * `root_hash` — The Merkle root from the checkpoint.
/// * `timestamp_unix` — POSIX time to embed in the cosignature.
pub fn sign_checkpoint_as_cosigner(
    cosigner_name: &str,
    key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    origin: &str,
    tree_size: u64,
    root_hash: &[u8],
    timestamp_unix: u64,
) -> Result<String, AcmeError> {
    let body = checkpoint_note_body(origin, tree_size, root_hash);
    let (type_byte, key_id) = compute_key_id(cosigner_name, key, NoteSigningRole::Cosigner)?;

    match key.key_type() {
        "ed25519" => {
            // Type 0x04: sign "cosignature/v1\ntime {ts}\n{body}"
            let msg = format!("cosignature/v1\ntime {timestamp_unix}\n{body}");
            let sig = raw_sign(key, hash_alg, msg.as_bytes())?;

            // Wire format: type_byte(1) || key_id(4) || timestamp_be(8) || sig(64)
            let mut blob = Vec::with_capacity(1 + 4 + 8 + sig.len());
            blob.push(type_byte);
            blob.extend_from_slice(&key_id);
            blob.extend_from_slice(&timestamp_unix.to_be_bytes());
            blob.extend_from_slice(&sig);

            Ok(format!(
                "{body}\n\u{2014} {cosigner_name} {}\n",
                BASE64.encode(&blob)
            ))
        }
        "ec" => {
            // ECDSA has no dedicated cosignature type; use primary-operator format (0x02).
            // `timestamp_unix` is not embedded — ECDSA cosignatures carry no timestamp.
            let sig = raw_sign(key, hash_alg, body.as_bytes())?;
            // Wire format: type_byte(1) || key_id(4) || sig
            let mut blob = Vec::with_capacity(1 + 4 + sig.len());
            blob.push(type_byte);
            blob.extend_from_slice(&key_id);
            blob.extend_from_slice(&sig);
            Ok(format!(
                "{body}\n\u{2014} {cosigner_name} {}\n",
                BASE64.encode(&blob)
            ))
        }
        "ml-dsa-44" => {
            // Type 0x06: sign binary cosigned_message
            let msg = build_ml_dsa_cosigned_message(
                cosigner_name,
                timestamp_unix,
                origin,
                0, // start = 0 for checkpoints
                tree_size,
                root_hash,
            )?;
            let sig = raw_sign(key, hash_alg, &msg)?;
            if sig.len() != ML_DSA_44_SIG_LEN {
                return Err(AcmeError::Mtc(format!(
                    "ML-DSA-44 signature length {} ≠ expected {}",
                    sig.len(),
                    ML_DSA_44_SIG_LEN
                )));
            }

            // Wire format: type_byte(1) || key_id(4) || timestamp_be(8) || sig(2420)
            let mut blob = Vec::with_capacity(1 + 4 + 8 + sig.len());
            blob.push(type_byte);
            blob.extend_from_slice(&key_id);
            blob.extend_from_slice(&timestamp_unix.to_be_bytes());
            blob.extend_from_slice(&sig);

            Ok(format!(
                "{body}\n\u{2014} {cosigner_name} {}\n",
                BASE64.encode(&blob)
            ))
        }
        t => Err(AcmeError::Mtc(format!(
            "key type '{t}' is not supported for C2SP cosignatures"
        ))),
    }
}

/// Build the binary `cosigned_message` for ML-DSA-44 cosignatures (type 0x06).
///
/// Format (tlog-cosignature spec):
/// ```text
/// label[12]        = "subtree/v1\n\0"
/// u8               = len(cosigner_name)
/// cosigner_name    = bytes
/// u64 big-endian   = timestamp (0 if start ≠ 0)
/// u8               = len(log_origin)
/// log_origin       = bytes
/// u64 big-endian   = start  (0 for full checkpoints)
/// u64 big-endian   = end    (= tree_size for full checkpoints)
/// u8[32]           = root_hash
/// ```
fn build_ml_dsa_cosigned_message(
    cosigner_name: &str,
    timestamp_unix: u64,
    log_origin: &str,
    start: u64,
    end: u64,
    root_hash: &[u8],
) -> Result<Vec<u8>, AcmeError> {
    let name_bytes = cosigner_name.as_bytes();
    let origin_bytes = log_origin.as_bytes();

    if name_bytes.len() > 255 {
        return Err(AcmeError::Mtc("cosigner_name exceeds 255 bytes".into()));
    }
    if origin_bytes.len() > 255 {
        return Err(AcmeError::Mtc("log_origin exceeds 255 bytes".into()));
    }
    if root_hash.len() != 32 {
        return Err(AcmeError::Mtc(format!(
            "root_hash must be 32 bytes, got {}",
            root_hash.len()
        )));
    }
    // Timestamps and start are mutually exclusive per spec.
    if timestamp_unix != 0 && start != 0 {
        return Err(AcmeError::Mtc(
            "ML-DSA-44 cosigned_message: timestamp and start cannot both be non-zero".into(),
        ));
    }

    let mut msg =
        Vec::with_capacity(12 + 1 + name_bytes.len() + 8 + 1 + origin_bytes.len() + 8 + 8 + 32);
    msg.extend_from_slice(b"subtree/v1\n\0"); // 12-byte label (LF + NUL)
    msg.push(name_bytes.len() as u8);
    msg.extend_from_slice(name_bytes);
    msg.extend_from_slice(&timestamp_unix.to_be_bytes());
    msg.push(origin_bytes.len() as u8);
    msg.extend_from_slice(origin_bytes);
    msg.extend_from_slice(&start.to_be_bytes());
    msg.extend_from_slice(&end.to_be_bytes());
    msg.extend_from_slice(root_hash);
    Ok(msg)
}

// ── Merkle Tree Hash (RFC 9162 §2) ───────────────────────────────────────────

/// Compute `MTH(hashes)` according to RFC 9162 §2.
///
/// Each entry in `hashes` must be a leaf hash (pre-computed by `hash_leaf`).
/// Interior nodes use `SHA-256(0x01 || left || right)`.
pub fn mth(hashes: &[Vec<u8>], algorithm: HashAlgorithm) -> Result<Vec<u8>, AcmeError> {
    match hashes.len() {
        0 => {
            let alg_str = match algorithm {
                HashAlgorithm::Sha256 => "sha256",
                HashAlgorithm::Sha384 => "sha384",
                HashAlgorithm::Sha512 => "sha512",
                HashAlgorithm::Sha3_256 => "sha3-256",
                HashAlgorithm::Sha3_384 => "sha3-384",
                HashAlgorithm::Sha3_512 => "sha3-512",
            };
            default_data_hasher()
                .hash_data(alg_str, &[])
                .map_err(|e| AcmeError::Mtc(format!("hash empty MTH: {e}")))
        }
        1 => Ok(hashes[0].clone()),
        n => {
            // k = 2^floor(log2(n-1)) — largest power of 2 that is < n
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros()) as usize;
            let left = mth(&hashes[..k], algorithm)?;
            let right = mth(&hashes[k..], algorithm)?;
            Ok(hash_interior(algorithm, &left, &right))
        }
    }
}

// ── Tile index encoding / decoding ────────────────────────────────────────────

/// Encode a tile index `n` as a C2SP tlog-tiles URL path component.
///
/// Splits the decimal representation into 3-digit groups right-to-left,
/// prefixes all but the rightmost with `x`, and joins with `/`.
///
/// ```text
/// 0         → "000"
/// 255       → "255"
/// 1000      → "x001/000"
/// 1_234_567 → "x001/x234/567"
/// ```
pub fn tile_index_path(n: u64) -> String {
    let mut groups: Vec<String> = Vec::new();
    let mut remaining = n;
    loop {
        groups.push(format!("{:03}", remaining % 1000));
        remaining /= 1000;
        if remaining == 0 {
            break;
        }
    }
    // groups[0] is the least-significant (rightmost) group — no "x" prefix.
    // All others get "x".  Reverse to emit left-to-right order.
    let mut parts: Vec<String> = Vec::with_capacity(groups.len());
    for (i, g) in groups.iter().enumerate().rev() {
        if i == 0 {
            parts.push(g.clone());
        } else {
            parts.push(format!("x{g}"));
        }
    }
    parts.join("/")
}

/// Decode a C2SP tile index from a URL path component.
fn decode_tile_index(path: &str) -> Option<u64> {
    let mut n: u64 = 0;
    for component in path.split('/') {
        let digits = component.strip_prefix('x').unwrap_or(component);
        if digits.len() != 3 {
            return None;
        }
        let part: u64 = digits.parse().ok()?;
        if part >= 1000 {
            return None;
        }
        n = n.checked_mul(1000)?.checked_add(part)?;
    }
    Some(n)
}

/// Parsed tile path from the URL `{level}/{index_path}[.p/{width}]`.
pub struct TilePath {
    /// Tree level: 0 = leaf hashes, L>0 = Merkle subtree roots.
    pub level: u32,
    /// Tile index within this level.
    pub tile_n: u64,
    /// Present for partial tiles; gives the number of entries (1–255).
    /// `None` = full tile (256 entries).
    pub partial_width: Option<usize>,
}

/// Parse a tile URL path like `"0/x001/234"` or `"1/000.p/42"`.
pub fn parse_tile_path(path: &str) -> Result<TilePath, AcmeError> {
    let bad = || AcmeError::BadRequest(format!("invalid tile path: '{path}'"));

    // Split off optional ".p/{width}" partial-tile suffix.
    let (path_part, partial_width) = match path.find(".p/") {
        Some(idx) => {
            let w: usize = path[idx + 3..]
                .parse()
                .map_err(|_| AcmeError::BadRequest("invalid partial tile width".into()))?;
            if w == 0 || w >= TILE_WIDTH {
                return Err(AcmeError::BadRequest(format!(
                    "partial tile width {w} out of range 1..255"
                )));
            }
            (&path[..idx], Some(w))
        }
        None => (path, None),
    };

    // First path segment is the level number.
    let slash = path_part.find('/').ok_or_else(bad)?;
    let level: u32 = path_part[..slash].parse().map_err(|_| bad())?;
    if level > MAX_TILE_LEVEL {
        return Err(AcmeError::BadRequest(format!(
            "tile level {level} exceeds maximum {MAX_TILE_LEVEL}"
        )));
    }
    let index_path = &path_part[slash + 1..];
    if index_path.is_empty() {
        return Err(bad());
    }
    let tile_n = decode_tile_index(index_path).ok_or_else(bad)?;

    Ok(TilePath {
        level,
        tile_n,
        partial_width,
    })
}

// ── Hash tile computation ─────────────────────────────────────────────────────

/// Compute all hash entries for the tile at `(level, tile_n)`, up to `max_width`.
///
/// - Level 0: raw leaf hashes read directly from the log.
/// - Level L>0: each entry = `MTH` of 256 entries from the level-(L-1) tile below.
///
/// Returns an empty vec when the tile is entirely beyond the log.
/// Returns a shorter-than-`max_width` vec when the log ends mid-tile.
async fn tile_entries(
    log: &SharedLog,
    algorithm: HashAlgorithm,
    level: u32,
    tile_n: u64,
    max_width: usize,
) -> Result<Vec<Vec<u8>>, AcmeError> {
    if level == 0 {
        let start = tile_n
            .checked_mul(TILE_WIDTH as u64)
            .ok_or(AcmeError::NotFound)?;
        return read_hash_range(log, start, max_width).await;
    }

    let mut result = Vec::with_capacity(max_width);
    for i in 0..max_width as u64 {
        let base = tile_n
            .checked_mul(TILE_WIDTH as u64)
            .ok_or(AcmeError::NotFound)?;
        let sub_tile_n = base.checked_add(i).ok_or(AcmeError::NotFound)?;
        let sub = Box::pin(tile_entries(
            log,
            algorithm,
            level - 1,
            sub_tile_n,
            TILE_WIDTH,
        ))
        .await?;
        if sub.is_empty() {
            break; // reached end of log
        }
        result.push(mth(&sub, algorithm)?);
    }
    Ok(result)
}

/// Compute the raw bytes for a hash tile HTTP response.
///
/// Concatenates all hash entries for the tile; each entry is `hash_size` bytes.
/// Returns `AcmeError::NotFound` when no entries exist for the requested tile.
pub async fn get_tile_bytes(
    log: &SharedLog,
    algorithm: HashAlgorithm,
    tile: &TilePath,
) -> Result<Vec<u8>, AcmeError> {
    let max_width = tile.partial_width.unwrap_or(TILE_WIDTH);
    let entries = tile_entries(log, algorithm, tile.level, tile.tile_n, max_width).await?;

    match tile.partial_width {
        None => {
            if entries.len() < TILE_WIDTH {
                return Err(AcmeError::NotFound);
            }
        }
        Some(w) => {
            if entries.len() != w {
                return Err(AcmeError::NotFound);
            }
        }
    }

    let hash_size = entries[0].len();
    let mut out = Vec::with_capacity(entries.len() * hash_size);
    for h in &entries {
        out.extend_from_slice(h);
    }
    Ok(out)
}

// ── Async checkpoint helpers ──────────────────────────────────────────────────

/// Compute the current checkpoint and return it as a C2SP signed note (log
/// operator signature, types 0x01 / 0x02 depending on key type).
pub async fn produce_operator_checkpoint(
    log: &SharedLog,
    key_name: &str,
    key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    origin: &str,
) -> Result<String, AcmeError> {
    let (tree_size, root_hash) = tree_size_and_root(log).await?;
    sign_checkpoint_as_operator(key_name, key, hash_alg, origin, tree_size, &root_hash)
}

/// Compute the current checkpoint and return it as a C2SP signed note
/// (cosignature, types 0x04 / 0x06 depending on key type).
pub async fn produce_cosigner_checkpoint(
    log: &SharedLog,
    cosigner_name: &str,
    key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    origin: &str,
) -> Result<String, AcmeError> {
    let (tree_size, root_hash) = tree_size_and_root(log).await?;
    // Sample timestamp after the tree snapshot to minimise clock/state skew.
    let timestamp_unix = crate::util::unix_now() as u64;
    sign_checkpoint_as_cosigner(
        cosigner_name,
        key,
        hash_alg,
        origin,
        tree_size,
        &root_hash,
        timestamp_unix,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::BackendPrivateKey;
    use synta_mtc::crypto::HashAlgorithm;

    // ── Tile index encoding ────────────────────────────────────────────────────

    #[test]
    fn tile_index_path_encodes_correctly() {
        assert_eq!(tile_index_path(0), "000");
        assert_eq!(tile_index_path(255), "255");
        assert_eq!(tile_index_path(999), "999");
        assert_eq!(tile_index_path(1000), "x001/000");
        assert_eq!(tile_index_path(1_234_567), "x001/x234/567");
    }

    #[test]
    fn tile_index_roundtrip() {
        for n in [0u64, 1, 255, 256, 999, 1000, 65535, 1_234_567] {
            let path = tile_index_path(n);
            assert_eq!(
                decode_tile_index(&path),
                Some(n),
                "roundtrip failed for {n}"
            );
        }
    }

    #[test]
    fn parse_tile_path_full() {
        let tp = parse_tile_path("0/000").unwrap();
        assert_eq!(tp.level, 0);
        assert_eq!(tp.tile_n, 0);
        assert!(tp.partial_width.is_none());
    }

    #[test]
    fn parse_tile_path_partial() {
        let tp = parse_tile_path("1/x001/234.p/42").unwrap();
        assert_eq!(tp.level, 1);
        assert_eq!(tp.tile_n, 1000 + 234);
        assert_eq!(tp.partial_width, Some(42));
    }

    #[test]
    fn parse_tile_path_bad_width() {
        assert!(parse_tile_path("0/000.p/0").is_err());
        assert!(parse_tile_path("0/000.p/256").is_err());
    }

    // ── Key ID computation ────────────────────────────────────────────────────

    #[test]
    fn compute_key_id_ed25519_operator() {
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let (type_byte, id) =
            compute_key_id("log.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        assert_eq!(type_byte, NOTE_TYPE_ED25519_OPERATOR);
        assert_eq!(id.len(), 4);
    }

    #[test]
    fn compute_key_id_ed25519_cosigner() {
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let (type_byte, id) =
            compute_key_id("log.example.com", &key, NoteSigningRole::Cosigner).unwrap();
        assert_eq!(type_byte, NOTE_TYPE_ED25519_COSIGNER);
        assert_eq!(id.len(), 4);
    }

    #[test]
    fn compute_key_id_ed25519_operator_vs_cosigner_differ() {
        // Same key, same name — but type byte 0x01 ≠ 0x04, so IDs differ.
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let (_, op_id) =
            compute_key_id("log.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        let (_, co_id) =
            compute_key_id("log.example.com", &key, NoteSigningRole::Cosigner).unwrap();
        assert_ne!(op_id, co_id);
    }

    #[test]
    fn compute_key_id_ecdsa_p256() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let (type_byte, id) =
            compute_key_id("log.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        assert_eq!(type_byte, NOTE_TYPE_ECDSA);
        assert_eq!(id.len(), 4);
    }

    #[test]
    fn compute_key_id_ecdsa_independent_of_name_and_role() {
        // Type 0x02: SHA-256(SPKI_DER)[:4] — ignores key_name and role.
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let (_, id_a) =
            compute_key_id("log-a.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        let (_, id_b) =
            compute_key_id("log-b.example.com", &key, NoteSigningRole::Cosigner).unwrap();
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn compute_key_id_ed25519_differs_by_name() {
        // Type 0x01: name is hashed in, so different names → different IDs.
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let (_, id_a) =
            compute_key_id("log-a.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        let (_, id_b) =
            compute_key_id("log-b.example.com", &key, NoteSigningRole::LogOperator).unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn compute_key_id_rsa_fails() {
        let key = BackendPrivateKey::generate_rsa(2048, 65537).unwrap();
        assert!(compute_key_id("log.example.com", &key, NoteSigningRole::LogOperator).is_err());
    }

    #[test]
    fn compute_key_id_mldsa44_as_operator_fails() {
        let key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
        assert!(compute_key_id("log.example.com", &key, NoteSigningRole::LogOperator).is_err());
    }

    #[test]
    fn compute_key_id_mldsa44_as_cosigner() {
        let key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
        let (type_byte, id) =
            compute_key_id("cosigner.example.com", &key, NoteSigningRole::Cosigner).unwrap();
        assert_eq!(type_byte, NOTE_TYPE_ML_DSA_44_COSIGNER);
        assert_eq!(id.len(), 4);
    }

    // ── Checkpoint note format ────────────────────────────────────────────────

    #[test]
    fn checkpoint_note_body_format() {
        let body = checkpoint_note_body("https://log.example.com/2024", 42, &[0u8; 32]);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "https://log.example.com/2024");
        assert_eq!(lines[1], "42");
        assert_eq!(lines[2], BASE64.encode([0u8; 32]));
    }

    #[test]
    fn sign_operator_ed25519_contains_em_dash() {
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let note = sign_checkpoint_as_operator(
            "log.example.com",
            &key,
            "sha256",
            "https://log.example.com/2024",
            10,
            &[0xab; 32],
        )
        .unwrap();
        assert!(note.contains("\u{2014} log.example.com "));
    }

    #[test]
    fn sign_operator_ecdsa_p256_contains_em_dash() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let note = sign_checkpoint_as_operator(
            "log.example.com",
            &key,
            "sha256",
            "https://log.example.com/2024",
            10,
            &[0xab; 32],
        )
        .unwrap();
        assert!(note.contains("\u{2014} log.example.com "));
    }

    #[test]
    fn sign_cosigner_ed25519_blob_includes_timestamp() {
        let key = BackendPrivateKey::generate_ed25519().unwrap();
        let ts = 1_700_000_000u64;
        let note = sign_checkpoint_as_cosigner(
            "cosigner.example.com",
            &key,
            "sha256",
            "https://log.example.com/2024",
            10,
            &[0xcd; 32],
            ts,
        )
        .unwrap();
        // Decode the signature blob and verify the embedded timestamp bytes.
        let sig_line = note.lines().find(|l| l.starts_with("\u{2014}")).unwrap();
        let b64 = sig_line.splitn(3, ' ').nth(2).unwrap();
        let blob = BASE64.decode(b64).unwrap();
        // blob = type_byte(1) || key_id(4) || timestamp_be(8) || sig(64)
        assert_eq!(blob[0], NOTE_TYPE_ED25519_COSIGNER);
        let ts_bytes: [u8; 8] = blob[5..13].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(ts_bytes), ts);
    }

    #[test]
    fn sign_cosigner_mldsa44_blob_includes_timestamp() {
        let key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
        let ts = 1_700_000_001u64;
        let note = sign_checkpoint_as_cosigner(
            "cosigner.example.com",
            &key,
            "sha256",
            "https://log.example.com/2024",
            10,
            &[0xef; 32],
            ts,
        )
        .unwrap();
        let sig_line = note.lines().find(|l| l.starts_with("\u{2014}")).unwrap();
        let b64 = sig_line.splitn(3, ' ').nth(2).unwrap();
        let blob = BASE64.decode(b64).unwrap();
        // blob = type_byte(1) || key_id(4) || timestamp_be(8) || sig(2420) = 2433 bytes
        assert_eq!(blob.len(), 1 + 4 + 8 + ML_DSA_44_SIG_LEN);
        assert_eq!(blob[0], NOTE_TYPE_ML_DSA_44_COSIGNER);
        let ts_bytes: [u8; 8] = blob[5..13].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(ts_bytes), ts);
    }

    #[test]
    fn ml_dsa_cosigned_message_rejects_nonzero_ts_and_start() {
        let result =
            build_ml_dsa_cosigned_message("cosigner", 100, "log.example.com", 5, 10, &[0u8; 32]);
        assert!(result.is_err());
    }

    // ── MTH computation ───────────────────────────────────────────────────────

    #[test]
    fn mth_single_leaf_is_identity() {
        let h = vec![vec![0xabu8; 32]];
        let result = mth(&h, HashAlgorithm::Sha256).unwrap();
        assert_eq!(result, h[0]);
    }

    #[test]
    fn mth_two_leaves_uses_interior_hash() {
        let left = vec![0u8; 32];
        let right = vec![1u8; 32];
        let expected = hash_interior(HashAlgorithm::Sha256, &left, &right);
        let result = mth(&[left, right], HashAlgorithm::Sha256).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn mth_256_leaves_is_deterministic_and_32_bytes() {
        let hashes: Vec<Vec<u8>> = (0u16..256).map(|i| vec![i as u8; 32]).collect();
        let r1 = mth(&hashes, HashAlgorithm::Sha256).unwrap();
        let r2 = mth(&hashes, HashAlgorithm::Sha256).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }
}
