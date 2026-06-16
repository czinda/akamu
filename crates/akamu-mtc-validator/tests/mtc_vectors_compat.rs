use akamu_mtc_validator::{build_artifacts, validate_layer_b, MtcVectors};

#[test]
fn mtc_vectors_layer_b_passes() {
    let vectors_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contrib/test-vectors/mtc/mtc.json"
    );
    let vectors = MtcVectors::load(std::path::Path::new(vectors_path)).unwrap();
    let artifacts = build_artifacts(&vectors).unwrap();
    let report = validate_layer_b(&vectors, &artifacts).unwrap();
    for f in report.failures() {
        eprintln!("FAIL [{}]: {}", f.name, f.message);
    }
    assert!(report.all_pass(), "Layer B checks failed");
}
