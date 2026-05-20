//! CMS `SignedData(EnvelopedData)` seal/open for Akamu cluster gossip.
//!
//! Wire format: outer `SignedData` (ECDSA P-256 sender auth) wrapping inner `EnvelopedData`
//! (ML-KEM-768 per-recipient encryption with AES-256-GCM content encryption).
//!
//! Ported from `ekishib-cms`; adapted to accept PEM input for the signing private key
//! (Akamu stores signing keys as PEM) and to use the `akamu-cms-kek` HKDF info string.

use native_ossl::cipher::{AeadDecryptCtx, AeadEncryptCtx, CipherAlg};
use native_ossl::cms::{CmsContentInfo, CmsSignFlags, CmsVerifyFlags};
use native_ossl::digest::DigestAlg;
use native_ossl::kdf::HkdfBuilder;
use native_ossl::params::{ParamBuilder, Params};
use native_ossl::pkey::{DecapCtx, EncapCtx, Pkey, Private, Public};
use native_ossl::rand::Rand;
use native_ossl::x509::{X509Store, X509};
use synta::{Integer, ObjectIdentifier, OctetStringRef, RawDer};
use synta_certificate::cms_kem_types::{KEMRecipientInfo, ID_ORI_KEM};
use synta_certificate::cms_rfc5652_types::{EnvelopedData, OtherRecipientInfo};
use synta_certificate::{AlgorithmIdentifier, EnvelopedDataBuilder};

const AES256_GCM_OID_BODY: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e];

const ML_KEM_768_ALG_DER: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
];

const HKDF_SHA256_ALG_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x1c,
];

const AES256_WRAP_ALG_DER: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d,
];

const HKDF_INFO: &[u8] = b"akamu-cms-kek";

const AES_WRAP_IV: u64 = 0xA6A6A6A6A6A6A6A6;

// ── Public API ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CmsError {
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] native_ossl::error::ErrorStack),
    #[error("ASN.1 encode error")]
    Encode,
    #[error("DER parse error")]
    ParseError,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("no matching KEM recipient")]
    NoMatchingRecipient,
    #[error("no signer certificate in SignedData")]
    NoSignerCert,
    #[error("compression error: {0}")]
    Compress(#[source] std::io::Error),
    #[error("decompression error: {0}")]
    Decompress(#[source] std::io::Error),
}

impl From<synta::Error> for CmsError {
    fn from(_: synta::Error) -> Self {
        CmsError::ParseError
    }
}

/// A recipient for CMS `EnvelopedData` encryption.
pub struct SealRecipient<'a> {
    pub hint: &'a str,
    pub spki_der: &'a [u8],
}

/// Sign-then-encrypt for gossip send.
///
/// `signing_priv_pem` — PEM bytes of the sender's ECDSA P-256 gossip signing key.
/// `signing_cert_der` — DER of the self-signed P-256 cert embedded in SignedData.
pub fn sign_and_seal(
    plaintext: &[u8],
    recipients: &[SealRecipient<'_>],
    signing_priv_pem: &[u8],
    signing_cert_der: &[u8],
) -> Result<Vec<u8>, CmsError> {
    let enveloped_der = seal(plaintext, recipients)?;
    let priv_key = Pkey::<Private>::from_pem(signing_priv_pem)?;
    let cert = X509::from_der(signing_cert_der)?;
    let cms = CmsContentInfo::sign(
        &cert,
        &priv_key,
        &[],
        &enveloped_der,
        CmsSignFlags::BINARY | CmsSignFlags::NOSMIMECAP,
    )?;
    cms.to_der().map_err(CmsError::OpenSsl)
}

/// Verify-then-decrypt for gossip receive.
///
/// `sender_signing_pub_spki` — expected sender ECDSA P-256 SPKI DER.
/// `None` for TOFU from an unknown node (WARN logged; signature still verified).
pub fn verify_and_open(
    signed_der: &[u8],
    kem_priv_pkcs8_der: &[u8],
    sender_signing_pub_spki: Option<&[u8]>,
) -> Result<Vec<u8>, CmsError> {
    let cms = CmsContentInfo::from_der(signed_der)?;

    let certs = cms.certs();
    let signer_cert = certs.first().ok_or(CmsError::NoSignerCert)?;
    let embedded_pub = signer_cert.public_key()?.public_key_to_der()?;

    match sender_signing_pub_spki {
        Some(expected) => {
            if embedded_pub.as_slice() != expected {
                return Err(CmsError::SignatureInvalid);
            }
        }
        None => {
            tracing::warn!("gossip: verifying SignedData from unknown node (TOFU)");
        }
    }

    let store = X509Store::new()?;
    let enveloped_der = cms
        .verify(&store, &[], CmsVerifyFlags::NO_SIGNER_CERT_VERIFY)
        .map_err(|_| CmsError::SignatureInvalid)?;

    open(&enveloped_der, kem_priv_pkcs8_der)
}

// ── Internal: seal / open ──────────────────────────────────────────────────

fn seal(plaintext: &[u8], recipients: &[SealRecipient<'_>]) -> Result<Vec<u8>, CmsError> {
    let compressed = zstd::encode_all(plaintext, 3).map_err(CmsError::Compress)?;
    seal_raw(&compressed, recipients)
}

fn open(ciphertext_der: &[u8], kem_priv_pkcs8_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let compressed = open_raw(ciphertext_der, kem_priv_pkcs8_der)?;
    zstd::decode_all(compressed.as_slice()).map_err(CmsError::Decompress)
}

fn seal_raw(plaintext: &[u8], recipients: &[SealRecipient<'_>]) -> Result<Vec<u8>, CmsError> {
    let cek: [u8; 32] = Rand::bytes(32)?.try_into().unwrap();
    let nonce: [u8; 12] = Rand::bytes(12)?.try_into().unwrap();

    let gcm = CipherAlg::fetch(c"AES-256-GCM", None)?;
    let mut enc = AeadEncryptCtx::new(&gcm, &cek, &nonce, None)?;
    let mut ciphertext = vec![0u8; plaintext.len()];
    let n = enc.update(plaintext, &mut ciphertext)?;
    let nf = enc.finalize(&mut ciphertext[n..])?;
    ciphertext.truncate(n + nf);
    let mut tag = [0u8; 16];
    enc.tag(&mut tag)?;
    ciphertext.extend_from_slice(&tag);

    let enc_alg_id = aes256gcm_alg_id_der(&nonce);
    let mut builder = EnvelopedDataBuilder::new(enc_alg_id, ciphertext);

    for r in recipients {
        let pub_key = Pkey::<Public>::from_der(r.spki_der).inspect_err(|_| {
            tracing::warn!(hint = %r.hint, "gossip seal: invalid KEM public key");
        })?;

        let result = EncapCtx::new(&pub_key)?.encapsulate()?;
        let kek = hkdf_sha256_kek(&result.shared_secret)?;
        let encrypted_cek = aes_key_wrap(&kek, &cek)?;

        let ski_der = build_ski_der(&sha256(r.spki_der)?);
        let ori_der = build_kem_ori_der(&result.wrapped_key, &ski_der, &encrypted_cek)?;
        builder = builder.add_recipient_info(ori_der);
    }

    builder.build().map_err(|_| CmsError::Encode)
}

fn open_raw(ciphertext_der: &[u8], kem_priv_pkcs8_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let env = EnvelopedData::from_der(ciphertext_der)?;
    let priv_key = Pkey::<Private>::from_der(kem_priv_pkcs8_der)?;

    let elements = iter_der_elements(env.recipient_infos.0)?;

    for elem in elements {
        if elem.is_empty() || elem[0] != 0xa4 {
            continue;
        }
        let mut seq = elem.to_vec();
        seq[0] = 0x30;

        let ori = match OtherRecipientInfo::from_der(&seq) {
            Ok(o) => o,
            Err(_) => continue,
        };

        if ori.ori_type.components() != ID_ORI_KEM {
            continue;
        }

        let kri = match KEMRecipientInfo::from_der(ori.ori_value.0) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let kemct = kri.kemct.as_bytes();
        let shared_secret = match DecapCtx::new(&priv_key).and_then(|mut c| c.decapsulate(kemct)) {
            Ok(ss) => ss,
            Err(_) => continue,
        };

        let kek = hkdf_sha256_kek(&shared_secret)?;
        let cek = match aes_key_unwrap(&kek, kri.encrypted_key.as_bytes()) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let enc_alg_der = env
            .encrypted_content_info
            .content_encryption_algorithm
            .to_der()
            .map_err(|_| CmsError::ParseError)?;
        let nonce = extract_gcm_nonce(&enc_alg_der)?;

        let encrypted = env
            .encrypted_content_info
            .encrypted_content
            .map(|ec| ec.as_bytes().to_vec())
            .unwrap_or_default();

        if encrypted.len() < 16 {
            return Err(CmsError::ParseError);
        }
        let (ct, tag_bytes) = encrypted.split_at(encrypted.len() - 16);

        let gcm = CipherAlg::fetch(c"AES-256-GCM", None)?;
        let mut dec = AeadDecryptCtx::new(&gcm, &cek, &nonce, None)?;
        dec.set_tag(tag_bytes)?;
        let mut plaintext = vec![0u8; ct.len()];
        let n = dec.update(ct, &mut plaintext)?;
        let nf = dec.finalize(&mut plaintext[n..])?;
        plaintext.truncate(n + nf);
        return Ok(plaintext);
    }

    Err(CmsError::NoMatchingRecipient)
}

// ── ASN.1 / crypto helpers ─────────────────────────────────────────────────

fn aes256gcm_alg_id_der(nonce: &[u8; 12]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&[0x30, 0x1e, 0x06, 0x09]);
    v.extend_from_slice(AES256_GCM_OID_BODY);
    v.extend_from_slice(&[0x30, 0x11, 0x04, 0x0c]);
    v.extend_from_slice(nonce);
    v.extend_from_slice(&[0x02, 0x01, 0x10]);
    v
}

fn extract_gcm_nonce(alg_der: &[u8]) -> Result<[u8; 12], CmsError> {
    for i in 0..alg_der.len().saturating_sub(AES256_GCM_OID_BODY.len() + 4) {
        if alg_der[i] == 0x06
            && alg_der.get(i + 1) == Some(&0x09)
            && alg_der.get(i + 2..i + 11) == Some(AES256_GCM_OID_BODY)
        {
            let nonce_start = i + 11 + 4;
            if nonce_start + 12 <= alg_der.len() {
                return alg_der[nonce_start..nonce_start + 12]
                    .try_into()
                    .map_err(|_| CmsError::ParseError);
            }
        }
    }
    Err(CmsError::ParseError)
}

fn sha256(data: &[u8]) -> Result<[u8; 32], CmsError> {
    let alg = DigestAlg::fetch(c"SHA2-256", None)?;
    alg.digest_to_vec(data)?
        .try_into()
        .map_err(|_| CmsError::Encode)
}

fn hkdf_sha256_kek(shared_secret: &[u8]) -> Result<[u8; 32], CmsError> {
    let digest = DigestAlg::fetch(c"SHA2-256", None)?;
    HkdfBuilder::new(&digest)
        .key(shared_secret)
        .info(HKDF_INFO)
        .derive_to_vec(32)?
        .try_into()
        .map_err(|_| CmsError::Encode)
}

fn build_ski_der(hash: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(34);
    v.push(0x80);
    v.push(0x20);
    v.extend_from_slice(hash);
    v
}

fn build_kem_ori_der(
    kemct: &[u8],
    ski_der: &[u8],
    encrypted_cek: &[u8; 40],
) -> Result<Vec<u8>, CmsError> {
    let kem_alg = AlgorithmIdentifier::from_der(ML_KEM_768_ALG_DER)?;
    let kdf_alg = AlgorithmIdentifier::from_der(HKDF_SHA256_ALG_DER)?;
    let wrap_alg = AlgorithmIdentifier::from_der(AES256_WRAP_ALG_DER)?;

    let kri = KEMRecipientInfo {
        version: Integer::from_u64(0),
        rid: RawDer(ski_der),
        kem: kem_alg,
        kemct: OctetStringRef::new(kemct),
        kdf: kdf_alg,
        kek_length: Integer::from_u64(32),
        ukm: None,
        wrap: wrap_alg,
        encrypted_key: OctetStringRef::new(encrypted_cek),
    };

    let kri_der = kri.to_der().map_err(|_| CmsError::Encode)?;
    let ori_oid = ObjectIdentifier::new(ID_ORI_KEM).map_err(|_| CmsError::Encode)?;

    let ori = OtherRecipientInfo {
        ori_type: ori_oid,
        ori_value: RawDer(&kri_der),
    };

    let mut ori_der = ori.to_der().map_err(|_| CmsError::Encode)?;
    if ori_der.first() != Some(&0x30) {
        return Err(CmsError::Encode);
    }
    ori_der[0] = 0xa4;
    Ok(ori_der)
}

fn iter_der_elements(set_der: &[u8]) -> Result<Vec<&[u8]>, CmsError> {
    let mut elements = Vec::new();
    if set_der.len() < 2 {
        return Ok(elements);
    }
    let mut pos = 1usize;
    let (outer_len, lb) = decode_der_length(&set_der[pos..])?;
    pos += lb;
    let end = pos + outer_len;
    if end > set_der.len() {
        return Err(CmsError::ParseError);
    }
    while pos < end {
        if pos + 2 > end {
            break;
        }
        let start = pos;
        pos += 1;
        let (elem_len, lb) = decode_der_length(&set_der[pos..])?;
        pos += lb + elem_len;
        if pos > end {
            return Err(CmsError::ParseError);
        }
        elements.push(&set_der[start..pos]);
    }
    Ok(elements)
}

fn decode_der_length(data: &[u8]) -> Result<(usize, usize), CmsError> {
    let first = *data.first().ok_or(CmsError::ParseError)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || data.len() < 1 + n {
        return Err(CmsError::ParseError);
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

// ── RFC 3394 AES-256 Key Wrap ──────────────────────────────────────────────

fn no_pad_params() -> Result<Params<'static>, CmsError> {
    ParamBuilder::new()
        .map_err(CmsError::OpenSsl)?
        .push_int(c"padding", 0)
        .map_err(CmsError::OpenSsl)?
        .build()
        .map_err(CmsError::OpenSsl)
}

fn aes_ecb_block(
    ecb: &CipherAlg,
    kek: &[u8; 32],
    block: &[u8; 16],
    encrypt: bool,
) -> Result<[u8; 16], CmsError> {
    let no_pad = no_pad_params()?;
    let mut out = [0u8; 32];
    let total = if encrypt {
        let mut ctx = ecb.encrypt(kek, &[], None)?;
        ctx.set_params(&no_pad)?;
        let n1 = ctx.update(block, &mut out)?;
        let n2 = ctx.finalize(&mut out[n1..])?;
        n1 + n2
    } else {
        let mut ctx = ecb.decrypt(kek, &[], None)?;
        ctx.set_params(&no_pad)?;
        let n1 = ctx.update(block, &mut out)?;
        let n2 = ctx.finalize(&mut out[n1..])?;
        n1 + n2
    };
    out[..total].try_into().map_err(|_| CmsError::Encode)
}

fn aes_key_wrap(kek: &[u8; 32], cek: &[u8; 32]) -> Result<[u8; 40], CmsError> {
    const N: usize = 4;
    let ecb = CipherAlg::fetch(c"AES-256-ECB", None)?;

    let mut r: [[u8; 8]; N] = Default::default();
    for (i, chunk) in r.iter_mut().enumerate() {
        chunk.copy_from_slice(&cek[i * 8..(i + 1) * 8]);
    }
    let mut a = AES_WRAP_IV.to_be_bytes();

    for j in 0u64..6 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(ri);
            let b = aes_ecb_block(&ecb, kek, &block, true)?;
            let t = (N as u64 * j + i as u64 + 1).to_be_bytes();
            for k in 0..8 {
                a[k] = b[k] ^ t[k];
            }
            ri.copy_from_slice(&b[8..16]);
        }
    }

    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&a);
    for (i, ri) in r.iter().enumerate() {
        out[8 + i * 8..8 + (i + 1) * 8].copy_from_slice(ri);
    }
    Ok(out)
}

fn aes_key_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32], CmsError> {
    if wrapped.len() != 40 {
        return Err(CmsError::ParseError);
    }
    const N: usize = 4;
    let ecb = CipherAlg::fetch(c"AES-256-ECB", None)?;

    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    let mut r: [[u8; 8]; N] = Default::default();
    for i in 0..N {
        r[i].copy_from_slice(&wrapped[8 + i * 8..8 + (i + 1) * 8]);
    }

    for j in (0u64..6).rev() {
        for i in (0..N).rev() {
            let t = (N as u64 * j + i as u64 + 1).to_be_bytes();
            let mut block = [0u8; 16];
            for k in 0..8 {
                block[k] = a[k] ^ t[k];
            }
            block[8..].copy_from_slice(&r[i]);
            let b = aes_ecb_block(&ecb, kek, &block, false)?;
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..16]);
        }
    }

    if a != AES_WRAP_IV.to_be_bytes() {
        return Err(CmsError::NoMatchingRecipient);
    }

    let mut cek = [0u8; 32];
    for i in 0..N {
        cek[i * 8..(i + 1) * 8].copy_from_slice(&r[i]);
    }
    Ok(cek)
}
