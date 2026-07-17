//! Human-readable text descriptions of DER-encoded certificates.
//!
//! Produces openssl-style text output for standard X.509 `Certificate`s and
//! MTC `LandmarkCertificate`s.  Shared by the server admin API and CLI tools.

use std::fmt::Write as FmtWrite;

use synta::{Decoder, Encoding};
use synta_certificate::{
    decode_extensions, decode_public_key_info, extension_oid_name, format_dn,
    format_extension_value, identify_public_key_algorithm, identify_signature_algorithm,
    Certificate, PublicKeyInfo, Time,
};

// ── Shared helpers ───────────────────────────────────────────────────────────

fn fmt_time(t: &Time) -> String {
    const M: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match t {
        Time::UtcTime(u) => format!(
            "{} {:2} {:02}:{:02}:{:02} {} GMT",
            M.get(u.month.wrapping_sub(1) as usize).unwrap_or(&"???"),
            u.day,
            u.hour,
            u.minute,
            u.second,
            u.year,
        ),
        Time::GeneralTime(g) => format!(
            "{} {:2} {:02}:{:02}:{:02} {} GMT",
            M.get(g.month.wrapping_sub(1) as usize).unwrap_or(&"???"),
            g.day,
            g.hour,
            g.minute,
            g.second,
            g.year,
        ),
    }
}

fn write_hex(out: &mut String, data: &[u8], per_line: usize, indent: usize) {
    let pad = " ".repeat(indent);
    let chunks: Vec<_> = data.chunks(per_line).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let _ = write!(out, "{}", pad);
        for (j, b) in chunk.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ":");
            }
            let _ = write!(out, "{:02x}", b);
        }
        if i < chunks.len() - 1 {
            let _ = write!(out, ":");
        }
        let _ = writeln!(out);
    }
}

fn write_serial(out: &mut String, serial_bytes: &[u8]) {
    if serial_bytes.len() <= 8 {
        let mut val: u64 = 0;
        for b in serial_bytes {
            val = (val << 8) | (*b as u64);
        }
        let _ = writeln!(out, "        Serial Number: {} (0x{:x})", val, val);
    } else {
        let hex = serial_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        let _ = writeln!(out, "        Serial Number: {}", hex);
    }
}

fn write_tbs(out: &mut String, tbs: &synta_certificate::TBSCertificate<'_>) {
    let version = tbs
        .version
        .as_ref()
        .and_then(|v| v.as_i64().ok())
        .map(|v| v + 1)
        .unwrap_or(1);

    let _ = writeln!(out, "    Data:");
    let _ = writeln!(out, "        Version: {} (0x{:x})", version, version - 1);

    write_serial(out, tbs.serial_number.as_bytes());

    let sig_alg = if tbs.signature.algorithm.components()
        == synta_mtc::types::constants::ID_ALG_MTC_PROOF_EXP
    {
        "id-alg-mtcProof"
    } else {
        identify_signature_algorithm(&tbs.signature.algorithm)
    };
    let _ = writeln!(out, "        Signature Algorithm: {}", sig_alg);
    let _ = writeln!(out, "        Issuer: {}", format_dn(tbs.issuer.as_bytes()));
    let _ = writeln!(out, "        Validity");
    let _ = writeln!(
        out,
        "            Not Before: {}",
        fmt_time(&tbs.validity.not_before)
    );
    let _ = writeln!(
        out,
        "            Not After : {}",
        fmt_time(&tbs.validity.not_after)
    );
    let _ = writeln!(
        out,
        "        Subject: {}",
        format_dn(tbs.subject.as_bytes())
    );

    write_spki(out, &tbs.subject_public_key_info);

    if let Some(exts_raw) = &tbs.extensions {
        let exts = decode_extensions(exts_raw.as_bytes());
        if !exts.is_empty() {
            let _ = writeln!(out, "        X509v3 extensions:");
            for ext in &exts {
                let name = extension_oid_name(&ext.extn_id);
                let critical = ext.critical.map(bool::from).unwrap_or(false);
                if critical {
                    let _ = writeln!(out, "            {}: critical", name);
                } else {
                    let _ = writeln!(out, "            {}:", name);
                }
                if let Some(val) = format_extension_value(ext) {
                    let _ = writeln!(out, "                {}", val);
                }
            }
        }
    }
}

fn write_spki(out: &mut String, spki: &synta_certificate::SubjectPublicKeyInfo<'_>) {
    let pub_alg = identify_public_key_algorithm(&spki.algorithm.algorithm).unwrap_or("unknown");
    let _ = writeln!(out, "        Subject Public Key Info:");
    let _ = writeln!(out, "            Public Key Algorithm: {}", pub_alg);

    match decode_public_key_info(
        &spki.algorithm.algorithm,
        spki.algorithm.parameters.as_ref(),
        spki.subject_public_key.as_bytes(),
        spki.subject_public_key.bit_len(),
    ) {
        PublicKeyInfo::Rsa {
            modulus,
            exponent,
            bit_count,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                Modulus:");
            write_hex(out, &modulus, 15, 20);
            let _ = writeln!(
                out,
                "                Exponent: {} (0x{:x})",
                exponent, exponent
            );
        }
        PublicKeyInfo::Ec {
            key_bytes,
            bit_count,
            curve_short_name,
            curve_nist_name,
            curve_oid_str,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(out, &key_bytes, 15, 20);
            let name = curve_short_name.map(str::to_owned).unwrap_or(curve_oid_str);
            let _ = writeln!(out, "                ASN1 OID: {}", name);
            if let Some(nist) = curve_nist_name {
                let _ = writeln!(out, "                NIST CURVE: {}", nist);
            }
        }
        PublicKeyInfo::Unknown {
            key_bytes,
            bit_count,
            ..
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(out, &key_bytes, 15, 20);
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Produce an openssl-style text description of a DER-encoded X.509 certificate.
pub fn describe_cert_der(der: &[u8]) -> Option<String> {
    let mut decoder = Decoder::new(der, Encoding::Der);
    let cert: Certificate = match decoder.decode() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(der_len = der.len(), "describe_cert_der: parse failed: {e}");
            return None;
        }
    };
    let tbs = &cert.tbs_certificate;
    let mut out = String::new();

    let _ = writeln!(out, "Certificate:");
    write_tbs(&mut out, tbs);

    let is_mtc_proof =
        tbs.signature.algorithm.components() == synta_mtc::types::constants::ID_ALG_MTC_PROOF_EXP;

    if is_mtc_proof {
        let _ = writeln!(out, "    Signature Algorithm: id-alg-mtcProof");
        match synta_mtc::crypto::mtcproof::MtcProof::decode(cert.signature_value.as_bytes()) {
            Ok(proof) => write_mtc_proof(&mut out, &proof),
            Err(_) => {
                let _ = writeln!(out, "    MTC Proof: <decode error>");
                let _ = writeln!(out, "    Raw Value:");
                write_hex(&mut out, cert.signature_value.as_bytes(), 18, 8);
            }
        }
    } else {
        let sig_alg = identify_signature_algorithm(&tbs.signature.algorithm);
        let _ = writeln!(out, "    Signature Algorithm: {}", sig_alg);
        let _ = writeln!(out, "    Signature Value:");
        write_hex(&mut out, cert.signature_value.as_bytes(), 18, 8);
    }

    Some(out)
}

/// Produce a text description of a DER-encoded MTC `LandmarkCertificate`.
pub fn describe_landmark_cert_der(der: &[u8]) -> Option<String> {
    use synta_mtc::types::LandmarkCertificate;

    let cert = match LandmarkCertificate::from_der(der) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                der_len = der.len(),
                "describe_landmark_cert_der: parse failed: {e}"
            );
            return None;
        }
    };
    let mut out = String::new();

    let _ = writeln!(out, "Landmark Certificate:");
    write_tbs(&mut out, &cert.tbs_certificate);

    // ── Inclusion Proof ──
    let proof = &cert.inclusion_proof;
    let start = proof.subtree_start.as_i64().unwrap_or(-1);
    let end = proof.subtree_end.as_i64().unwrap_or(-1);
    let _ = writeln!(out, "    Inclusion Proof:");
    let _ = writeln!(out, "        Subtree Range: [{}, {})", start, end);
    let node_count = proof.inclusion_path.len();
    let _ = writeln!(
        out,
        "        Inclusion Path ({} node{}):",
        node_count,
        if node_count == 1 { "" } else { "s" }
    );
    for node in &proof.inclusion_path {
        let hex: String = node
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let _ = writeln!(out, "            {}", hex);
    }

    // ── Landmark ID ──
    let lid = &cert.landmark_id;
    let tree_size = lid.tree_size.as_i64().unwrap_or(-1);
    let _ = writeln!(out, "    Landmark ID:");
    let _ = writeln!(out, "        Tree Size: {}", tree_size);
    let log_hash_alg = identify_signature_algorithm(&lid.log_id.hash_algorithm.algorithm);
    let _ = writeln!(out, "        Log Hash Algorithm: {}", log_hash_alg);

    // ── Signature ──
    let _ = writeln!(
        out,
        "    Signature Algorithm: {}",
        identify_signature_algorithm(&cert.signature_algorithm.algorithm)
    );
    let _ = writeln!(out, "    Signature Value:");
    write_hex(&mut out, cert.signature.as_bytes(), 18, 8);

    Some(out)
}

fn write_mtc_proof(out: &mut String, proof: &synta_mtc::crypto::mtcproof::MtcProof) {
    let _ = writeln!(out, "    MTC Proof:");
    if proof.extensions.is_empty() {
        let _ = writeln!(out, "        Extensions: <none>");
    } else {
        let _ = writeln!(out, "        Extensions: {} bytes", proof.extensions.len());
    }
    let _ = writeln!(
        out,
        "        Subtree Range: [{}, {})",
        proof.start, proof.end
    );
    let hash_size = 32;
    if !proof.inclusion_proof.is_empty() && !proof.inclusion_proof.len().is_multiple_of(hash_size) {
        let _ = writeln!(
            out,
            "        WARNING: inclusion proof length {} not divisible by hash size {}",
            proof.inclusion_proof.len(),
            hash_size
        );
    }
    let node_count = if proof.inclusion_proof.is_empty() {
        0
    } else {
        proof.inclusion_proof.len() / hash_size
    };
    let _ = writeln!(
        out,
        "        Inclusion Path ({} node{}):",
        node_count,
        if node_count == 1 { "" } else { "s" }
    );
    for chunk in proof.inclusion_proof.chunks(hash_size) {
        let hex: String = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let _ = writeln!(out, "            {}", hex);
    }
    if proof.signatures.is_empty() {
        let _ = writeln!(out, "        Cosigner Signatures: <none>");
    } else {
        let _ = writeln!(
            out,
            "        Cosigner Signatures ({}):",
            proof.signatures.len()
        );
        for (i, sig) in proof.signatures.iter().enumerate() {
            let cid_hex: String = sig
                .cosigner_id
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            let _ = writeln!(out, "            [{i}] cosigner_id: {}", cid_hex);
            let _ = writeln!(
                out,
                "                signature: {} bytes",
                sig.signature_value.len()
            );
        }
    }
}
