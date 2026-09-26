use crate::commands::blocking;
use crate::error::{AppError, AppResult};
use crate::sarif::{normalize_log, parse_sarif};
use crate::security_ir::{
    Finding, ImportResult, LogEntry, ScanStatus, ScannerRun, ScannerRunStatus, Severity,
};
use crate::state::AppState;
use crate::workspace::{detect_project, ensure_demo_workspace};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

const BUILTIN_FIXTURES: &[(&str, &str)] = &[
    (
        "semgrep-example.sarif",
        include_str!("../../../fixtures/sarif/semgrep-example.sarif"),
    ),
    (
        "trivy-example.sarif",
        include_str!("../../../fixtures/sarif/trivy-example.sarif"),
    ),
    (
        "trufflehog-example.sarif",
        include_str!("../../../fixtures/sarif/trufflehog-example.sarif"),
    ),
    (
        "bandit-example.sarif",
        include_str!("../../../fixtures/sarif/bandit-example.sarif"),
    ),
    (
        "codeflow-example.sarif",
        include_str!("../../../fixtures/sarif/codeflow-example.sarif"),
    ),
    (
        "multi-run-example.sarif",
        include_str!("../../../fixtures/sarif/multi-run-example.sarif"),
    ),
];

#[tauri::command]
pub async fn import_sarif(
    state: State<'_, AppState>,
    path: String,
    project_id: Option<String>,
    workspace_root: Option<String>,
) -> AppResult<ImportResult> {
    let state = state.inner().clone();
    blocking(move || {
        import_path(
            &state,
            Path::new(&path),
            project_id.as_deref(),
            workspace_root.as_deref(),
        )
    })
    .await
}

#[tauri::command]
pub async fn open_demo_workspace(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ImportResult> {
    let state = state.inner().clone();
    let demo_root = state.data_dir.join("demo-workspace");
    blocking(move || {
        ensure_demo_workspace(&demo_root)?;
        let project = state.database.open_project(&detect_project(&demo_root)?)?;
        let run = state
            .database
            .create_scan_run(&project.id, "demo_fixture")?;
        let mut findings = Vec::new();
        let mut warnings = Vec::new();
        for (name, source) in BUILTIN_FIXTURES {
            match parse_sarif(source)
                .and_then(|log| normalize_log(&log, &demo_root, &project.id, &run.id))
            {
                Ok(mut normalized) => findings.append(&mut normalized),
                Err(error) => warnings.push(format!("{name}: {error}")),
            }
        }
        state.database.insert_findings(&findings)?;
        save_aggregate_scanner_runs(&state, &run.id, &findings)?;
        let scan_run = state
            .database
            .finish_scan_run(&run.id, ScanStatus::Completed)?;
        let _ = app.emit("scan://completed", &scan_run);
        Ok(ImportResult {
            scan_run,
            imported_findings: findings.len(),
            warnings,
        })
    })
    .await
}

#[tauri::command]
pub async fn export_sarif(
    state: State<'_, AppState>,
    project_id: String,
    destination: String,
) -> AppResult<String> {
    let state = state.inner().clone();
    blocking(move || {
        let findings = state
            .database
            .list_findings(&crate::security_ir::FindingFilters {
                project_id: Some(project_id),
                ..Default::default()
            })?;
        let document = build_export_document(&findings);
        let destination = PathBuf::from(destination);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&destination, serde_json::to_string_pretty(&document)?)?;
        Ok(destination.to_string_lossy().to_string())
    })
    .await
}

#[tauri::command]
pub async fn full_sarif(
    state: State<'_, AppState>,
    scan_run_id: String,
) -> AppResult<serde_json::Value> {
    let state = state.inner().clone();
    blocking(move || {
        let artifacts = state.database.scan_artifacts(&scan_run_id)?;
        if artifacts.is_empty() {
            return Err(AppError::NotFound(format!(
                "Raw SARIF for scan run {scan_run_id}"
            )));
        }
        if artifacts.len() == 1 {
            Ok(serde_json::from_str(&artifacts[0])
                .unwrap_or_else(|_| json!({ "raw": artifacts[0] })))
        } else {
            let runs = artifacts
                .iter()
                .filter_map(|artifact| serde_json::from_str::<serde_json::Value>(artifact).ok())
                .flat_map(|value| {
                    value
                        .get("runs")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            Ok(json!({ "version": "2.1.0", "runs": runs }))
        }
    })
    .await
}

fn import_path(
    state: &AppState,
    path: &Path,
    project_id: Option<&str>,
    workspace_root: Option<&str>,
) -> AppResult<ImportResult> {
    if !path.is_file() {
        return Err(AppError::InvalidInput(format!(
            "SARIF file does not exist: {}",
            path.display()
        )));
    }
    let source_text = std::fs::read_to_string(path)?;
    let log = parse_sarif(&source_text)?;
    let project = if let Some(project_id) = project_id {
        state.database.get_project(project_id)?
    } else {
        let root = workspace_root
            .map(PathBuf::from)
            .or_else(|| path.parent().map(Path::to_path_buf))
            .ok_or_else(|| {
                AppError::InvalidInput(
                    "Unable to infer a workspace root for this SARIF file.".into(),
                )
            })?;
        state.database.open_project(&detect_project(&root)?)?
    };
    let workspace = PathBuf::from(&project.path);
    let run = state
        .database
        .create_scan_run(&project.id, "sarif_import")?;
    let findings = normalize_log(&log, &workspace, &project.id, &run.id)?;
    state.database.insert_findings(&findings)?;
    state
        .database
        .insert_scan_artifact(&run.id, "import", "sarif", &source_text)?;
    save_aggregate_scanner_runs(state, &run.id, &findings)?;
    let scan_run = state
        .database
        .finish_scan_run(&run.id, ScanStatus::Completed)?;
    Ok(ImportResult {
        scan_run,
        imported_findings: findings.len(),
        warnings: Vec::new(),
    })
}

fn save_aggregate_scanner_runs(
    state: &AppState,
    scan_run_id: &str,
    findings: &[Finding],
) -> AppResult<()> {
    let mut groups: HashMap<(String, String), usize> = HashMap::new();
    for finding in findings {
        *groups
            .entry((finding.scanner_id.clone(), finding.scanner_name.clone()))
            .or_default() += 1;
    }
    if groups.is_empty() {
        groups.insert(("import".into(), "SARIF Import".into()), 0);
    }
    for ((scanner_id, scanner_name), count) in groups {
        let now = Utc::now().to_rfc3339();
        state.database.upsert_scanner_run(&ScannerRun {
            id: Uuid::new_v4().to_string(),
            scan_run_id: scan_run_id.to_string(),
            scanner_id,
            scanner_name,
            status: ScannerRunStatus::Completed,
            version: None,
            started_at: now.clone(),
            finished_at: Some(now),
            duration_ms: Some(0),
            error: None,
            logs: vec![LogEntry {
                timestamp: Utc::now().to_rfc3339(),
                stream: "info".into(),
                message: format!("Imported {count} normalized finding(s) from SARIF."),
            }],
        })?;
    }
    Ok(())
}

fn build_export_document(findings: &[crate::security_ir::FindingListItem]) -> serde_json::Value {
    let mut rules = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    let mut results = Vec::new();
    for finding in findings {
        if seen_rules.insert(finding.rule_id.clone()) {
            rules.push(json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": { "text": finding.title },
                "properties": { "cwe": finding.cwe }
            }));
        }
        let level = match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        };
        results.push(json!({
            "ruleId": finding.rule_id,
            "level": level,
            "message": { "text": finding.message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": finding.file_path },
                    "region": { "startLine": finding.start_line.max(1), "startColumn": 1 }
                }
            }],
            "partialFingerprints": {
                "workspaceFingerprint/v1": finding.workspace_fingerprint
            },
            "properties": {
                "scanner": finding.scanner_id,
                "category": finding.category,
                "status": finding.status,
                "cwe": finding.cwe
            }
        }));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Developer Security Workspace",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

#[allow(dead_code)]
fn fixture_sources() -> Vec<(&'static str, &'static str)> {
    BUILTIN_FIXTURES.to_vec()
}
