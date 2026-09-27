use super::*;
use crate::{sarif, security_ir::*, storage::Database};

/// A repeatable local tutorial backed by the same parser, matcher and database as real scans.
pub fn open(database: &Database, root: &Path) -> AppResult<ImportResult> {
    ensure_demo_workspace(root)?;
    let project = database.open_project(&detect_project(root)?)?;
    let key = format!("demo-v2:{}", project.id);
    if let Some(id) = database
        .get_setting(&key)?
        .and_then(|v| v.as_str().map(str::to_owned))
    {
        let scan_run = database.get_scan_run(&id)?;
        return Ok(ImportResult {
            imported_findings: scan_run.finding_count,
            scan_run,
            warnings: vec![],
        });
    }
    let sources = [
        include_str!("../../../fixtures/sarif/trivy-example.sarif"),
        include_str!("../../../fixtures/sarif/trufflehog-example.sarif"),
        include_str!("../../../fixtures/sarif/bandit-example.sarif"),
        include_str!("../../../fixtures/ir/rich.sarif"),
        include_str!("../../../fixtures/sarif/multi-run-example.sarif"),
        include_str!("../../../fixtures/sarif/tutorial-iac.sarif"),
    ];
    let mut last = None;
    for pass in 0..2 {
        let run = database.create_scan_run(&project.id, "demo_fixture")?;
        let mut findings = Vec::new();
        let mut scanners = std::collections::BTreeSet::new();
        for source in sources {
            let mut log = sarif::parse_sarif(source)?;
            if pass == 1 && log.runs[0].tool.driver.name == "Trivy" {
                for result in &mut log.runs[0].results {
                    result.properties["security-severity"] = serde_json::json!("9.8");
                }
            }
            if pass == 0 && log.runs[0].tool.driver.name == "Tutorial IaC" {
                let mut resolved = log.runs[0].results[0].clone();
                resolved.rule_id = Some("demo.fixed".into());
                resolved.message.text =
                    Some("Synthetic issue resolved in the second tutorial scan".into());
                log.runs[0].results.push(resolved);
            }
            let artifact = database.insert_scan_artifact(
                &run.id,
                "demo",
                "sarif",
                &serde_json::to_string(&log)?,
            )?;
            let mut normalized = sarif::normalize_log(&log, root, &project.id, &run.id)?;
            for f in &mut normalized {
                f.provenance.source = "synthetic-demo".into();
                scanners.insert((f.scanner_id.clone(), f.scanner_name.clone()));
                if let Some(reference) = &mut f.raw_reference {
                    reference.artifact_id = artifact.clone();
                    f.raw_sarif = serde_json::Value::Null;
                }
            }
            findings.extend(normalized);
        }
        database.insert_findings(&findings)?;
        for (id, name) in scanners {
            database.upsert_scanner_run(&ScannerRun {
                id: Uuid::new_v4().to_string(),
                scan_run_id: run.id.clone(),
                scanner_id: id,
                scanner_name: name,
                status: ScannerRunStatus::Completed,
                started_at: run.started_at.clone(),
                finished_at: Some(Utc::now().to_rfc3339()),
                ..Default::default()
            })?;
        }
        last = Some(database.finish_scan_run(&run.id, ScanStatus::Completed)?);
    }
    let scan_run =
        last.ok_or_else(|| AppError::InvalidInput("Demo scan was not created.".into()))?;
    database.set_setting(&key, &serde_json::json!(scan_run.id))?;
    Ok(ImportResult {
        imported_findings: scan_run.finding_count,
        scan_run,
        warnings: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tutorial_has_trace_fix_redaction_sca_iac_and_repeatable_diff() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(&dir.path().join("db")).unwrap();
        let root = dir.path().join("demo");
        let result = open(&db, &root).unwrap();
        let again = open(&db, &root).unwrap();
        assert_eq!(result.scan_run.id, again.scan_run.id);
        let rows = db
            .list_findings(&FindingFilters {
                scan_run_id: Some(result.scan_run.id.clone()),
                ..Default::default()
            })
            .unwrap();
        for category in [
            FindingCategory::Sast,
            FindingCategory::Secrets,
            FindingCategory::Sca,
            FindingCategory::Iac,
        ] {
            assert!(rows.iter().any(|r| r.category == category), "{category:?}");
        }
        assert!(rows
            .iter()
            .any(|r| !db.get_finding(&r.id).unwrap().fixes.is_empty()));
        assert!(rows
            .iter()
            .any(|r| !db.get_finding(&r.id).unwrap().code_flows.is_empty()));
        let diff = db
            .scan_diff(&result.scan_run.project_id, &result.scan_run.id, None)
            .unwrap()
            .unwrap();
        assert!(diff.existing_count > 0);
        assert!(diff.changed_count > 0);
        assert_eq!(diff.fixed_count, 1);
    }
}
