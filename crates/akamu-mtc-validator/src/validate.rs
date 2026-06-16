//! Validation logic: Layer A (reference comparison) and Layer B (self-consistency).

use std::path::Path;

use synta_mtc::crypto::{
    compute_root, generate_inclusion_proof, generate_subtree_hash, hash::HashAlgorithm,
    verify_subtree_inclusion_proof,
};

use crate::generate::{GeneratedArtifacts, ResolvedCert};
use crate::vectors::MtcVectors;
use crate::{Error, Result};

/// Result of a single validation check.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

impl CheckResult {
    fn pass(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: "ok".into(),
        }
    }
    fn fail(name: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: msg.into(),
        }
    }
}

/// Full validation report.
#[derive(Debug, Default)]
pub struct ValidationReport {
    pub checks: Vec<CheckResult>,
}

impl ValidationReport {
    pub fn all_pass(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    pub fn failures(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks.iter().filter(|c| !c.passed)
    }

    pub fn print(&self) {
        let pass = self.checks.iter().filter(|c| c.passed).count();
        let fail = self.checks.iter().filter(|c| !c.passed).count();
        for c in &self.checks {
            let status = if c.passed { "PASS" } else { "FAIL" };
            println!("[{status}] {}: {}", c.name, c.message);
        }
        println!("\n{pass} passed, {fail} failed");
    }

    fn add(&mut self, r: CheckResult) {
        self.checks.push(r);
    }
}

/// Run Layer B (internal consistency) checks.
pub fn validate_layer_b(
    vectors: &MtcVectors,
    artifacts: &GeneratedArtifacts,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::default();

    // --- B1: tree size matches expected entry count ---
    {
        let expected = count_expected_entries(vectors);
        let name = "B1:tree_size";
        if artifacts.tree_size == expected {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(
                name,
                format!("expected {expected} entries, got {}", artifacts.tree_size),
            ));
        }
    }

    // --- B2: all leaf hashes have correct length ---
    {
        let name = "B2:leaf_hash_length";
        let bad: Vec<_> = artifacts
            .leaf_hashes
            .iter()
            .enumerate()
            .filter(|(_, h)| h.len() != 32)
            .map(|(i, h)| (i, h.len()))
            .collect();
        if bad.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(
                name,
                format!("wrong hash length at indices: {:?}", bad),
            ));
        }
    }

    // --- B3: null entries have the correct hash ---
    {
        let name = "B3:null_entry_hashes";
        let expected_null_hash =
            synta_mtc::crypto::hash::hash_leaf(HashAlgorithm::Sha256, &[0x00, 0x00, 0x00, 0x00]);
        let mut bad_count = 0usize;
        let mut idx = 0u64;
        for entry in &vectors.entries {
            let repeat = entry.effective_repeat();
            for _ in 0..repeat {
                if entry.null && artifacts.leaf_hashes[idx as usize] != expected_null_hash {
                    bad_count += 1;
                }
                idx += 1;
            }
        }
        if bad_count == 0 {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(
                name,
                format!("{bad_count} null entries have unexpected leaf hash"),
            ));
        }
    }

    // --- B4: Merkle root computation succeeds ---
    let root = match artifacts.compute_root() {
        Ok(r) => {
            report.add(CheckResult::pass("B4:root_computation"));
            r
        }
        Err(e) => {
            report.add(CheckResult::fail("B4:root_computation", e.to_string()));
            return Ok(report);
        }
    };

    // --- B5: subtree alignment for every resolved cert ---
    {
        let name = "B5:subtree_alignment";
        let mut bad = Vec::new();
        for (i, cert) in artifacts.certs.iter().enumerate() {
            if let Err(e) = check_subtree_alignment(cert) {
                bad.push(format!("cert[{i}]: {e}"));
            }
        }
        if bad.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(name, bad.join("; ")));
        }
    }

    // --- B6: subtree end ≤ tree size for every cert ---
    {
        let name = "B6:subtree_in_bounds";
        let bad: Vec<_> = artifacts
            .certs
            .iter()
            .enumerate()
            .filter(|(_, c)| c.subtree_end > artifacts.tree_size)
            .map(|(i, c)| {
                format!(
                    "cert[{i}] end={} > tree_size={}",
                    c.subtree_end, artifacts.tree_size
                )
            })
            .collect();
        if bad.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(name, bad.join("; ")));
        }
    }

    // --- B7: leaf index in subtree for every cert ---
    {
        let name = "B7:leaf_in_subtree";
        let bad: Vec<_> = artifacts
            .certs
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.subtree_start < c.subtree_end
                    && (c.leaf_index < c.subtree_start || c.leaf_index >= c.subtree_end)
            })
            .map(|(i, c)| {
                format!(
                    "cert[{i}] leaf={} not in [{}, {})",
                    c.leaf_index, c.subtree_start, c.subtree_end
                )
            })
            .collect();
        if bad.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(name, bad.join("; ")));
        }
    }

    // --- B8: inclusion proofs verify for all resolved certs ---
    {
        let name = "B8:inclusion_proofs";
        let mut errors = Vec::new();
        for (i, cert) in artifacts.certs.iter().enumerate() {
            if cert.subtree_start == cert.subtree_end {
                continue; // skip unresolved
            }
            let start = cert.subtree_start;
            let end = cert.subtree_end;
            let leaf_idx = cert.leaf_index;
            let rel_idx = leaf_idx - start;
            let subtree_hashes = artifacts.leaf_hashes[start as usize..end as usize].to_vec();
            let leaf_hash = &artifacts.leaf_hashes[leaf_idx as usize];

            let proof =
                match generate_inclusion_proof(HashAlgorithm::Sha256, rel_idx, &subtree_hashes) {
                    Ok(p) => p,
                    Err(e) => {
                        errors.push(format!("cert[{i}] proof gen: {e}"));
                        continue;
                    }
                };

            let subtree_hash = match generate_subtree_hash(HashAlgorithm::Sha256, &subtree_hashes) {
                Ok(h) => h,
                Err(e) => {
                    errors.push(format!("cert[{i}] subtree hash: {e}"));
                    continue;
                }
            };

            if let Err(e) = verify_subtree_inclusion_proof(
                HashAlgorithm::Sha256,
                leaf_idx, // absolute index; function computes relative internally
                start,
                end,
                leaf_hash,
                &proof,
                &subtree_hash,
            ) {
                errors.push(format!("cert[{i}]: {e}"));
            }
        }
        if errors.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(name, errors.join("; ")));
        }
    }

    // --- B9: checkpoint-resolved subtrees are power-of-2 aligned ---
    {
        let name = "B9:subtrees_for_interval";
        let mut errors = Vec::new();
        for (i, cert) in artifacts.certs.iter().enumerate() {
            let entry = &vectors.entries[cert.entry_config_idx];
            let cert_cfg = &entry.certificates[cert.cert_config_idx];
            if cert_cfg.subtree_end != 0 {
                if let Err(e) = check_subtree_alignment(cert) {
                    errors.push(format!("cert[{i}] alignment: {e}"));
                }
                continue;
            }
            if cert_cfg.checkpoint.is_empty() {
                continue;
            }
            if cert.subtree_start == cert.subtree_end {
                errors.push(format!("cert[{i}] checkpoint subtree not resolved"));
                continue;
            }
            if let Err(e) = check_subtree_alignment(cert) {
                errors.push(format!("cert[{i}] checkpoint alignment: {e}"));
            }
        }
        if errors.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(name, errors.join("; ")));
        }
    }

    // B10: Full tree root verification (all leaf hashes → root)
    {
        let name = "B10:root_all_leaves";
        let computed = match compute_root(HashAlgorithm::Sha256, artifacts.leaf_hashes.clone()) {
            Ok(r) => r,
            Err(e) => {
                report.add(CheckResult::fail(name, e.to_string()));
                return Ok(report);
            }
        };
        if computed == root {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(
                name,
                "root mismatch between two computations",
            ));
        }
    }

    Ok(report)
}

/// Run Layer A (reference comparison) checks.
///
/// `reference_dir` must contain Go demo tool outputs:
///   - `tile/0/000` (and partial tile): leaf hashes (32 bytes each, concatenated)
///   - `checkpoint`: signed note with tree size and root hash (base64)
pub fn validate_layer_a(
    artifacts: &GeneratedArtifacts,
    reference_dir: &Path,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::default();

    // A1: read reference leaf hashes from tile/0/* and compare
    let ref_hashes = match read_reference_leaf_hashes(reference_dir, artifacts.tree_size) {
        Ok(h) => {
            report.add(CheckResult::pass("A1:reference_tile_read"));
            h
        }
        Err(e) => {
            report.add(CheckResult::fail("A1:reference_tile_read", e.to_string()));
            return Ok(report);
        }
    };

    // A2: leaf hash count matches
    {
        let name = "A2:leaf_hash_count";
        if ref_hashes.len() == artifacts.leaf_hashes.len() {
            report.add(CheckResult::pass(name));
        } else {
            report.add(CheckResult::fail(
                name,
                format!(
                    "reference has {} hashes, we have {}",
                    ref_hashes.len(),
                    artifacts.leaf_hashes.len()
                ),
            ));
            return Ok(report);
        }
    }

    // A3: leaf hash comparison
    {
        let name = "A3:leaf_hash_values";
        let mismatches: Vec<_> = ref_hashes
            .iter()
            .zip(artifacts.leaf_hashes.iter())
            .enumerate()
            .filter(|(_, (r, g))| r != g)
            .map(|(i, _)| i)
            .collect();
        if mismatches.is_empty() {
            report.add(CheckResult::pass(name));
        } else {
            let sample: Vec<_> = mismatches.iter().take(5).collect();
            report.add(CheckResult::fail(
                name,
                format!(
                    "{} leaf hash mismatches (first 5 indices: {:?})",
                    mismatches.len(),
                    sample
                ),
            ));
        }
    }

    // A4: tree root matches reference checkpoint
    match read_reference_root(reference_dir) {
        Ok(Some(ref_root)) => {
            let our_root = match artifacts.compute_root() {
                Ok(r) => r,
                Err(e) => {
                    report.add(CheckResult::fail("A4:root_match", e.to_string()));
                    return Ok(report);
                }
            };
            let name = "A4:root_match";
            if ref_root == our_root {
                report.add(CheckResult::pass(name));
            } else {
                report.add(CheckResult::fail(
                    name,
                    format!(
                        "reference root {} != ours {}",
                        hex_str(&ref_root),
                        hex_str(&our_root)
                    ),
                ));
            }
        }
        Ok(None) => {
            report.add(CheckResult::fail(
                "A4:root_match",
                "checkpoint file not found in reference directory",
            ));
        }
        Err(e) => {
            report.add(CheckResult::fail("A4:root_match", e.to_string()));
        }
    }

    Ok(report)
}

// --- helpers ---

// §4.3.1: start must be a multiple of BIT_CEIL(size) = next_power_of_two(end - start).
// Size need not itself be a power of two.
fn check_subtree_alignment(cert: &ResolvedCert) -> core::result::Result<(), String> {
    let start = cert.subtree_start;
    let end = cert.subtree_end;
    if start >= end {
        return Err(format!("start {start} >= end {end}"));
    }
    let size = end - start;
    let alignment = size.next_power_of_two();
    if !start.is_multiple_of(alignment) {
        return Err(format!(
            "[{start}, {end}): start not aligned to next_power_of_two({size}) = {alignment}"
        ));
    }
    Ok(())
}

fn count_expected_entries(vectors: &MtcVectors) -> u64 {
    vectors.entries.iter().map(|e| e.effective_repeat()).sum()
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read leaf hashes from the reference `tile/0/*` tile files.
///
/// Go tlog format: each tile at level 0 contains raw 32-byte SHA-256 hashes
/// concatenated. Full tiles contain 256 hashes; the last partial tile is in a
/// file named like `000.p/N` where N is the count of partial hashes.
fn read_reference_leaf_hashes(reference_dir: &Path, tree_size: u64) -> Result<Vec<Vec<u8>>> {
    let tile_dir = reference_dir.join("tile").join("0");
    if !tile_dir.exists() {
        return Err(Error::Io(format!(
            "reference tile/0 directory not found at {}",
            tile_dir.display()
        )));
    }

    let mut hashes: Vec<Vec<u8>> = Vec::new();
    let full_tiles = tree_size / 256;
    let partial = tree_size % 256;

    for i in 0..full_tiles {
        let path = tile_dir.join(tlog_index(i, false));
        let data =
            std::fs::read(&path).map_err(|e| Error::Io(format!("read {}: {e}", path.display())))?;
        if data.len() != 256 * 32 {
            return Err(Error::Parse(format!(
                "tile {} has {} bytes, expected {}",
                path.display(),
                data.len(),
                256 * 32
            )));
        }
        for chunk in data.chunks(32) {
            hashes.push(chunk.to_vec());
        }
    }

    if partial > 0 {
        let partial_base = tlog_index(full_tiles, true);
        let path = tile_dir.join(partial_base).join(partial.to_string());
        let data = std::fs::read(&path)
            .map_err(|e| Error::Io(format!("read partial tile {}: {e}", path.display())))?;
        let expected_bytes = partial as usize * 32;
        if data.len() != expected_bytes {
            return Err(Error::Parse(format!(
                "partial tile has {} bytes, expected {expected_bytes}",
                data.len()
            )));
        }
        for chunk in data.chunks(32) {
            hashes.push(chunk.to_vec());
        }
    }

    Ok(hashes)
}

/// Read the tree root hash from the reference `checkpoint` signed note.
///
/// Go checkpoint format (lines):
///   1. log origin (e.g. "oid/1.3.6.1.4.1.32473.1.0.1")
///   2. tree size (decimal)
///   3. root hash (base64)
///   4. empty line
///   5. signature lines
fn read_reference_root(reference_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = reference_dir.join("checkpoint");
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| Error::Io(format!("read checkpoint: {e}")))?;
    let mut lines = text.lines();
    let _origin = lines.next();
    let _size = lines.next();
    let root_b64 = lines
        .next()
        .ok_or_else(|| Error::Parse("checkpoint missing root line".into()))?;
    use base64::Engine as _;
    let root = base64::engine::general_purpose::STANDARD
        .decode(root_b64)
        .map_err(|e| Error::Parse(format!("checkpoint root base64: {e}")))?;
    Ok(Some(root))
}

/// Build the tlog tile path for index `n`.
///
/// Full tile: "000" for n=0, "001" for n=1, "x001/000" for n=1000, etc.
/// Partial tile: "000.p" (directory) for the last partial tile index.
fn tlog_index(n: u64, partial: bool) -> std::path::PathBuf {
    let mut components: Vec<String> = Vec::new();
    let suffix = if partial {
        format!("{:03}.p", n % 1000)
    } else {
        format!("{:03}", n % 1000)
    };
    let mut v = n / 1000;
    components.push(suffix);
    while v > 0 {
        components.push(format!("x{:03}", v % 1000));
        v /= 1000;
    }
    components.reverse();
    components.iter().collect()
}
