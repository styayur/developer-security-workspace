use super::*;
use serde_json::json;
use tokio_util::sync::CancellationToken;
fn setup(dir: &Path) -> (Database, Project) {
    let db = Database::new(&dir.join("db")).unwrap();
    let p = db
        .open_project(&Project {
            id: "p".into(),
            name: "test".into(),
            path: dir.to_string_lossy().into(),
            created_at: Utc::now().to_rfc3339(),
            last_opened_at: Utc::now().to_rfc3339(),
            ..Default::default()
        })
        .unwrap();
    (db, p)
}
fn write_report(path: &Path, count: usize) {
    let results=(0..count).map(|i|json!({"ruleId":"rule","message":{"text":format!("synthetic {i}")},"locations":[{"physicalLocation":{"artifactLocation":{"uri":if i==count-1 {"file-0".into()}else{format!("file-{i}")}},"region":{"startLine":1}}}],"properties":{"Raw":"SYNTHETIC_VALUE"}})).collect::<Vec<_>>();
    // Results before tool is legal SARIF and requires staging metadata independently.
    std::fs::write(path,format!("{{\"runs\":[{{\"results\":{},\"tool\":{{\"driver\":{{\"name\":\"demo\"}}}}}}],\"version\":\"2.1.0\"}}",serde_json::to_string(&results).unwrap())).unwrap();
}
#[test]
fn streaming_global_collisions_raw_and_cancel_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let (db, p) = setup(dir.path());
    let path = dir.path().join("input.sarif");
    write_report(&path, 300);
    let first = db.create_scan_run(&p.id, "sarif_import").unwrap();
    streaming::import(&db, &path, &p, &first, &CancellationToken::new(), &|_| {}).unwrap();
    let second = db.create_scan_run(&p.id, "sarif_import").unwrap();
    streaming::import(&db, &path, &p, &second, &CancellationToken::new(), &|_| {}).unwrap();
    let diff = db
        .scan_diff(&p.id, &second.id, Some(&first.id))
        .unwrap()
        .unwrap();
    assert_eq!(diff.existing_count, 298);
    assert_eq!(diff.new_count, 2);
    assert_eq!(diff.fixed_count, 2);
    let raw = db.scan_artifacts(&first.id).unwrap();
    let raw: serde_json::Value = serde_json::from_str(&raw[0]).unwrap();
    assert_eq!(raw["runs"][0]["results"].as_array().unwrap().len(), 300);
    assert!(!raw.to_string().contains("SYNTHETIC_VALUE"));
    let before: String = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT json_group_array(candidate_json) FROM finding_identities",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for phase in ["parsing", "normalizing", "committing"] {
        let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
        let cancel = CancellationToken::new();
        assert!(streaming::import(&db, &path, &p, &run, &cancel, &|event| {
            if event.phase == phase && event.processed >= 256 {
                cancel.cancel();
            }
        })
        .is_err());
        assert!(db
            .list_findings(&FindingFilters {
                scan_run_id: Some(run.id.clone()),
                ..Default::default()
            })
            .unwrap()
            .is_empty());
        assert!(db.scan_artifacts(&run.id).unwrap().is_empty());
        let after: String = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT json_group_array(candidate_json) FROM finding_identities",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
    }
    // Reusing the connection after cancellation must not retain attachment or SQL interrupt state.
    let third = db.create_scan_run(&p.id, "sarif_import").unwrap();
    streaming::import(&db, &path, &p, &third, &CancellationToken::new(), &|_| {}).unwrap();
}
#[test]
fn streaming_rejects_trailing_invalid_duplicate_and_oversized_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.sarif");
    for value in ["{\"version\":\"2.1.0\",\"runs\":[]} garbage".to_string(),"{\"version\":\"2.1.0\",\"version\":\"2.1.0\",\"runs\":[]}".into(),
        format!("{{\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"demo\"}}}},\"results\":[{{\"message\":{{\"text\":\"{}\"}}}}]}}]}}","x".repeat(crate::sarif::streaming::MAX_VALUE_BYTES+1))] {
        std::fs::write(&path,value).unwrap();assert!(crate::sarif::streaming::stage(&path,&CancellationToken::new(),&|_|{}).is_err());
    }
}
#[test]
fn streaming_ir_matches_batch_normalization() {
    let dir = tempfile::tempdir().unwrap();
    let (db, p) = setup(dir.path());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ir/rich.sarif");
    let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
    let log = crate::sarif::parse_sarif(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let batch = crate::sarif::normalize_log(&log, dir.path(), &p.id, &run.id).unwrap();
    streaming::import(&db, &path, &p, &run, &CancellationToken::new(), &|_| {}).unwrap();
    let list = db
        .list_findings(&FindingFilters {
            scan_run_id: Some(run.id),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(list.len(), batch.len());
    for f in batch {
        let row = list
            .iter()
            .find(|r| r.rule_id == f.rule_id && r.file_path == f.location.file_path)
            .unwrap();
        let stored = db.get_finding(&row.id).unwrap();
        assert_eq!(
            Candidate::from_finding(&f).signature,
            Candidate::from_finding(&stored).signature
        );
        assert_eq!(
            serde_json::to_value(f.fingerprints).unwrap(),
            serde_json::to_value(stored.fingerprints).unwrap()
        );
    }
}
#[test]
fn streaming_preserves_digest_before_secret_redaction() {
    let dir = tempfile::tempdir().unwrap();
    let (db, p) = setup(dir.path());
    let path = dir.path().join("native.sarif");
    let raw = json!({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo"}},"results":[{"ruleId":"r","message":{"text":"synthetic"},"fingerprints":{"secret-hash":"different-native-value"}}]}]});
    std::fs::write(&path, raw.to_string()).unwrap();
    let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
    let batch = crate::sarif::normalize_log(
        &crate::sarif::parse_sarif(&raw.to_string()).unwrap(),
        dir.path(),
        &p.id,
        &run.id,
    )
    .unwrap();
    streaming::import(&db, &path, &p, &run, &CancellationToken::new(), &|_| {}).unwrap();
    let rows = db
        .list_findings(&FindingFilters {
            scan_run_id: Some(run.id.clone()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        db.get_finding(&rows[0].id).unwrap().fingerprints.native,
        batch[0].fingerprints.native
    );
    assert!(!db.scan_artifacts(&run.id).unwrap()[0].contains("different-native-value"));
}
use crate::matching::Candidate;
#[test]
#[ignore = "manual streaming benchmark under process memory limit"]
fn streaming_large_benchmark() {
    let path = std::env::var("DSW_BENCH_SARIF").expect("DSW_BENCH_SARIF");
    let dir = tempfile::tempdir().unwrap();
    let (db, p) = setup(dir.path());
    let start = std::time::Instant::now();
    let mut previous: Option<String> = None;
    for pass in 0..2 {
        let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
        let count = streaming::import(
            &db,
            Path::new(&path),
            &p,
            &run,
            &CancellationToken::new(),
            &|e| {
                if e.processed == 0 {
                    println!("phase={}", e.phase);
                }
            },
        )
        .unwrap();
        let query = std::time::Instant::now();
        let page = db
            .finding_page(
                &FindingFilters {
                    scan_run_id: Some(run.id.clone()),
                    ..Default::default()
                },
                0,
                100,
            )
            .unwrap();
        println!(
            "pass={pass} count={count} elapsed_ms={} page_ms={} ipc_bytes={}",
            start.elapsed().as_millis(),
            query.elapsed().as_millis(),
            serde_json::to_vec(&page).unwrap().len()
        );
        if let Some(old) = previous {
            let diff = db.scan_diff(&p.id, &run.id, Some(&old)).unwrap().unwrap();
            assert_eq!(diff.existing_count, count);
        }
        previous = Some(run.id);
    }
}
