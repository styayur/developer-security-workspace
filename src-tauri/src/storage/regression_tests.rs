use super::tests::{finding, project};
use super::*;

fn complete(db: &Database, run: &ScanRun) {
    db.upsert_scanner_run(&ScannerRun {
        id: Uuid::new_v4().to_string(),
        scan_run_id: run.id.clone(),
        scanner_id: "demo".into(),
        scanner_name: "Demo".into(),
        status: ScannerRunStatus::Completed,
        ..Default::default()
    })
    .unwrap();
    db.finish_scan_run(&run.id, ScanStatus::Completed).unwrap();
}

#[test]
fn lifecycle_corpus_preserves_triage_across_absence_and_reappearance() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let project = db.open_project(&project(dir.path())).unwrap();
    let expected: Vec<String> =
        serde_json::from_str(include_str!("../../../fixtures/diff/scenarios.json")).unwrap();
    let mut first_identity = String::new();
    let mut previous: Option<ScanRun> = None;
    let mut first_id = String::new();
    for (index, state) in expected.iter().enumerate() {
        let run = db.create_scan_run(&project.id, "scan").unwrap();
        let mut f = finding(&project, &run.id, 10 + index as u32 * 20);
        if index >= 2 {
            f.severity = Severity::Critical;
        }
        if state != "fixed" {
            db.insert_findings(std::slice::from_ref(&f)).unwrap();
        }
        complete(&db, &run);
        if state == "fixed" {
            assert_eq!(
                db.get_finding(&first_id).unwrap().lifecycle.state,
                DiffClass::Fixed
            );
            assert!(db
                .get_finding(&first_id)
                .unwrap()
                .lifecycle
                .fixed_at
                .is_some());
        } else {
            let actual = db.get_finding(&f.id).unwrap();
            assert_eq!(enum_string(&actual.lifecycle.state).unwrap(), *state);
            if index == 0 {
                first_identity = actual.lifecycle.identity_id.clone();
                first_id = actual.id.clone();
                db.update_triage(
                    &actual.id,
                    FindingStatus::AcceptedRisk,
                    Some("reviewed".into()),
                )
                .unwrap();
            } else {
                assert_eq!(actual.lifecycle.identity_id, first_identity);
                assert_eq!(actual.status, FindingStatus::AcceptedRisk);
                assert_eq!(actual.triage_note.as_deref(), Some("reviewed"));
                assert!(actual.lifecycle.matched_by.is_some());
            }
            if state == "reopened" {
                assert_eq!(actual.lifecycle.occurrence_count, 4);
                assert!(actual.lifecycle.reopened_at.is_some());
            }
        }
        if let Some(old) = previous {
            let diff = db
                .scan_diff(&project.id, &run.id, Some(&old.id))
                .unwrap()
                .unwrap();
            let count = match state.as_str() {
                "existing" => diff.existing_count,
                "changed" => diff.changed_count,
                "fixed" => diff.fixed_count,
                "reopened" => diff.reopened_count,
                _ => diff.new_count,
            };
            assert_eq!(count, 1, "{state}");
        }
        previous = Some(run);
    }
}

#[test]
fn scanner_version_round_trips_with_scan_history() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let project = db.open_project(&project(dir.path())).unwrap();
    let run = db.create_scan_run(&project.id, "scan").unwrap();
    let scanner_run = ScannerRun {
        id: Uuid::new_v4().to_string(),
        scan_run_id: run.id.clone(),
        scanner_id: "semgrep".into(),
        scanner_name: "Semgrep".into(),
        status: ScannerRunStatus::Completed,
        version: Some("1.95.0".into()),
        started_at: Utc::now().to_rfc3339(),
        finished_at: Some(Utc::now().to_rfc3339()),
        duration_ms: Some(42),
        error: None,
        logs: Vec::new(),
    };
    db.upsert_scanner_run(&scanner_run).unwrap();
    db.finish_scan_run(&run.id, ScanStatus::Completed).unwrap();

    let restored = db.get_scan_run(&run.id).unwrap();
    assert_eq!(restored.scanners.len(), 1);
    assert_eq!(restored.scanners[0].version.as_deref(), Some("1.95.0"));
}

#[test]
fn current_findings_use_latest_identity_and_exclude_fixed() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let project = db.open_project(&project(dir.path())).unwrap();

    let first_run = db.create_scan_run(&project.id, "scan").unwrap();
    db.insert_findings(&[finding(&project, &first_run.id, 10)])
        .unwrap();
    complete(&db, &first_run);

    let second_run = db.create_scan_run(&project.id, "scan").unwrap();
    let latest = finding(&project, &second_run.id, 10);
    db.insert_findings(std::slice::from_ref(&latest)).unwrap();
    complete(&db, &second_run);

    let current = db.current_findings(&project.id).unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, latest.id);

    let fixed_run = db.create_scan_run(&project.id, "scan").unwrap();
    complete(&db, &fixed_run);
    assert!(db.current_findings(&project.id).unwrap().is_empty());
}

#[test]
fn same_rule_collisions_have_independent_triage_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let p = db.open_project(&project(dir.path())).unwrap();
    let r = db.create_scan_run(&p.id, "scan").unwrap();
    let a = finding(&p, &r.id, 10);
    let b = finding(&p, &r.id, 20);
    db.insert_findings(&[a.clone(), b.clone()]).unwrap();
    db.update_triage(&a.id, FindingStatus::FalsePositive, None)
        .unwrap();
    assert_eq!(db.get_finding(&b.id).unwrap().status, FindingStatus::New);
    assert_ne!(
        db.get_finding(&a.id).unwrap().lifecycle.identity_id,
        db.get_finding(&b.id).unwrap().lifecycle.identity_id
    );
    let next = db.create_scan_run(&p.id, "scan").unwrap();
    let current = finding(&p, &next.id, 50);
    db.insert_findings(std::slice::from_ref(&current)).unwrap();
    assert_eq!(
        db.get_finding(&current.id).unwrap().lifecycle.state,
        DiffClass::New
    );
}

#[test]
fn failed_partial_changed_and_uncovered_scans_do_not_fix_findings() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let p = db.open_project(&project(dir.path())).unwrap();
    let r = db.create_scan_run(&p.id, "scan").unwrap();
    let f = finding(&p, &r.id, 10);
    db.insert_findings(std::slice::from_ref(&f)).unwrap();
    complete(&db, &r);
    for (source, status) in [
        ("scan", ScanStatus::Failed),
        ("scan", ScanStatus::Partial),
        ("scan", ScanStatus::Cancelled),
        ("scan_changed", ScanStatus::Completed),
        ("scan", ScanStatus::Completed),
    ] {
        let next = db.create_scan_run(&p.id, source).unwrap();
        db.finish_scan_run(&next.id, status).unwrap();
        assert_ne!(
            db.get_finding(&f.id).unwrap().lifecycle.state,
            DiffClass::Fixed
        );
    }
}

#[test]
fn paginated_sql_filter_combinations_and_navigation() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let p = db.open_project(&project(dir.path())).unwrap();
    let run = db.create_scan_run(&p.id, "scan").unwrap();
    let findings = (0..31)
        .map(|i| {
            let mut f = finding(&p, &run.id, i + 1);
            f.message = format!("literal_% item {i}");
            f.cwe = vec!["CWE-89".into()];
            f
        })
        .collect::<Vec<_>>();
    db.insert_findings(&findings).unwrap();
    let filters = FindingFilters {
        project_id: Some(p.id),
        scan_run_id: Some(run.id),
        severities: vec![Severity::High],
        scanners: vec!["demo".into()],
        categories: vec![FindingCategory::Sast],
        statuses: vec![FindingStatus::New],
        search: Some("_%".into()),
        file_path: Some("src/".into()),
        rule_id: Some("rule.one".into()),
        cwe: Some("CWE-89".into()),
        diff_class: Some("new".into()),
    };
    let first = db.finding_page(&filters, 0, 10).unwrap();
    let second = db.finding_page(&filters, 10, 10).unwrap();
    assert_eq!(first.total, 31);
    assert_eq!(second.items.len(), 10);
    assert!(!first
        .items
        .iter()
        .any(|a| second.items.iter().any(|b| a.id == b.id)));
    assert_eq!(
        db.finding_navigation(&first.items[0].id).unwrap()["next"],
        first.items[1].id
    );
    assert_eq!(db.finding_page(&filters, 0, 10000).unwrap().limit, 500);
    assert!(!serde_json::to_string(&first).unwrap().contains("rawSarif"));
}

#[test]
fn artifacts_are_redacted_once_and_referenced_results_load_lazily() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let p = db.open_project(&project(dir.path())).unwrap();
    let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
    let raw = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Demo"}},"results":[{"ruleId":"secret","message":{"text":"synthetic"},"properties":{"api_token":"SYNTHETIC_NOT_A_SECRET"}}]}]}"#;
    let log = crate::sarif::parse_sarif(raw).unwrap();
    let mut findings = crate::sarif::normalize_log(&log, dir.path(), &p.id, &run.id).unwrap();
    let artifact = db
        .insert_scan_artifact(&run.id, "demo", "sarif", raw)
        .unwrap();
    findings[0].raw_reference.as_mut().unwrap().artifact_id = artifact;
    db.insert_findings(&findings).unwrap();
    let detail = db.get_finding(&findings[0].id).unwrap();
    assert!(detail.raw_sarif["properties"]["api_token"]
        .as_str()
        .unwrap()
        .starts_with('•'));
    assert!(!db.scan_artifacts(&run.id).unwrap()[0].contains("SYNTHETIC_NOT_A_SECRET"));
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row("SELECT raw_sarif_json FROM findings", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "null"
    );
}

#[test]
fn migration_preserves_v1_data_is_idempotent_and_rejects_future_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let old = Connection::open(&path).unwrap();
    old.execute_batch(schema::SCHEMA_SQL).unwrap();
    old.execute_batch(r#"
        INSERT INTO schema_migrations VALUES(1,'2026-01-01');
        INSERT INTO projects(id,name,path,last_opened_at,created_at) VALUES('p','old','legacy','2026-01-01','2026-01-01');
        INSERT INTO scan_runs(id,project_id,started_at,status) VALUES('s','p','2026-01-01','completed');
        INSERT INTO findings(id,scan_run_id,project_id,scanner_id,scanner_name,rule_id,title,message,severity,category,file_path,status,triage_note,workspace_fingerprint,location_json,raw_sarif_json)
        VALUES('f','s','p','demo','Demo','rule','title','message','high','sast','src/a.rs','confirmed','keep me','old-hash','{}','{}');
    "#).unwrap();
    drop(old);
    for _ in 0..2 {
        let db = Database::new(&path).unwrap();
        let f = db.get_finding("f").unwrap();
        assert_eq!(f.status, FindingStatus::Confirmed);
        assert_eq!(f.triage_note.as_deref(), Some("keep me"));
        assert!(!f.lifecycle.identity_id.is_empty());
        assert_eq!(f.lifecycle.occurrence_count, 1);
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert!(db.lock().unwrap().query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_findings_run_diff'",[],|r|r.get::<_,i64>(0)).unwrap()>0);
    }
    let conn = Connection::open(&path).unwrap();
    conn.execute("INSERT INTO schema_migrations VALUES(999,'future')", [])
        .unwrap();
    drop(conn);
    assert!(Database::new(&path).is_err());
    assert_eq!(
        Connection::open(path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn migration_failure_rolls_back_instead_of_resetting_data() {
    let mut connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(schema::SCHEMA_SQL).unwrap();
    connection
        .execute_batch("ALTER TABLE findings ADD COLUMN identity_id TEXT;")
        .unwrap();
    assert!(migrations::migrate(&mut connection).is_err());
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name='provenance_json'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
#[ignore = "manual benchmark; set DSW_BENCH_SARIF to a generated file"]
fn large_sarif_benchmark() {
    let path = std::env::var("DSW_BENCH_SARIF").expect("DSW_BENCH_SARIF");
    let source = std::fs::read_to_string(path).unwrap();
    let start = std::time::Instant::now();
    let log = crate::sarif::parse_sarif(&source).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("db")).unwrap();
    let p = db.open_project(&project(dir.path())).unwrap();
    let mut previous: Option<String> = None;
    for pass in 0..2 {
        let run = db.create_scan_run(&p.id, "sarif_import").unwrap();
        let artifact = db
            .insert_scan_artifact(&run.id, "benchmark", "sarif", &source)
            .unwrap();
        let mut findings = crate::sarif::normalize_log(&log, dir.path(), &p.id, &run.id).unwrap();
        for f in &mut findings {
            f.raw_reference.as_mut().unwrap().artifact_id = artifact.clone();
            f.raw_sarif = serde_json::Value::Null;
        }
        db.insert_findings(&findings).unwrap();
        complete(&db, &run);
        let query_start = std::time::Instant::now();
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
        assert_eq!(page.total, findings.len());
        assert!(page.items.len() <= 100);
        println!(
            "pass={pass} findings={} total_elapsed_ms={} page_ms={} ipc_bytes={}",
            findings.len(),
            start.elapsed().as_millis(),
            query_start.elapsed().as_millis(),
            serde_json::to_vec(&page).unwrap().len()
        );
        if let Some(old) = previous {
            let diff = db.scan_diff(&p.id, &run.id, Some(&old)).unwrap().unwrap();
            assert_eq!(diff.existing_count, findings.len());
            assert!(diff.existing.len() <= 100);
        }
        previous = Some(run.id);
    }
}
