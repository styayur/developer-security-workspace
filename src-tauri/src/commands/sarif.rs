use crate::commands::blocking;
use crate::error::{AppError, AppResult};
use crate::security_ir::{ImportResult, ScanStatus, Severity};
use crate::state::AppState;
use crate::workspace::detect_project;
use serde_json::json;
#[cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

#[tauri::command]
pub fn prepare_import(state: State<'_, AppState>) -> AppResult<String> {
    let id = Uuid::new_v4().to_string();
    state
        .cancel_tokens
        .lock()
        .map_err(|_| AppError::Process("Cancellation state unavailable".into()))?
        .insert(
            format!("import:{id}"),
            tokio_util::sync::CancellationToken::new(),
        );
    Ok(id)
}

#[tauri::command]
pub fn cancel_import(state: State<'_, AppState>, import_id: String) -> AppResult<()> {
    if let Some(token) = state
        .cancel_tokens
        .lock()
        .map_err(|_| AppError::Process("Cancellation state unavailable".into()))?
        .get(&format!("import:{import_id}"))
    {
        token.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn import_sarif(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    project_id: Option<String>,
    workspace_root: Option<String>,
    import_id: Option<String>,
) -> AppResult<ImportResult> {
    let state = state.inner().clone();
    let id = import_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let key = format!("import:{id}");
    let cancel = state
        .cancel_tokens
        .lock()
        .map_err(|_| AppError::Process("Cancellation state unavailable".into()))?
        .entry(key.clone())
        .or_default()
        .clone();
    let worker = state.clone();
    let result = blocking(move || {
        import_path_with_cancel(
            &worker,
            Path::new(&path),
            project_id.as_deref(),
            workspace_root.as_deref(),
            &cancel,
            &|mut progress| {
                progress.import_id = id.clone();
                let _ = app.emit("import://progress", progress);
            },
        )
    })
    .await;
    if let Ok(mut tokens) = state.cancel_tokens.lock() {
        tokens.remove(&key);
    }
    result
}

#[tauri::command]
pub async fn open_demo_workspace(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ImportResult> {
    let state = state.inner().clone();
    let demo_root = state.data_dir.join("demo-workspace");
    blocking(move || {
        let result = crate::workspace::demo::open(&state.database, &demo_root)?;
        let _ = app.emit("scan://completed", &result.scan_run);
        Ok(result)
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

#[cfg(test)]
fn import_path(
    state: &AppState,
    path: &Path,
    project_id: Option<&str>,
    workspace_root: Option<&str>,
) -> AppResult<ImportResult> {
    import_path_with_cancel(
        state,
        path,
        project_id,
        workspace_root,
        &tokio_util::sync::CancellationToken::new(),
        &|_| {},
    )
}

fn import_path_with_cancel(
    state: &AppState,
    path: &Path,
    project_id: Option<&str>,
    workspace_root: Option<&str>,
    cancel: &tokio_util::sync::CancellationToken,
    progress: &dyn Fn(crate::sarif::streaming::ImportProgress),
) -> AppResult<ImportResult> {
    crate::sarif::streaming::check_cancel(cancel)?;
    if !path.is_file() {
        return Err(AppError::InvalidInput("SARIF file does not exist".into()));
    }
    let project = if let Some(id) = project_id {
        state.database.get_project(id)?
    } else {
        let root = workspace_root
            .map(PathBuf::from)
            .or_else(|| path.parent().map(Path::to_path_buf))
            .ok_or_else(|| AppError::InvalidInput("Unable to infer workspace root".into()))?;
        state.database.open_project(&detect_project(&root)?)?
    };
    let run = state
        .database
        .create_scan_run(&project.id, "sarif_import")?;
    match crate::storage::streaming::import(&state.database, path, &project, &run, cancel, progress)
    {
        Ok(count) => Ok(ImportResult {
            scan_run: state.database.get_scan_run(&run.id)?,
            imported_findings: count,
            warnings: Vec::new(),
        }),
        Err(error) => {
            state.database.finish_scan_run(
                &run.id,
                if cancel.is_cancelled() {
                    ScanStatus::Cancelled
                } else {
                    ScanStatus::Failed
                },
            )?;
            Err(error)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn state(root: &Path) -> AppState {
        AppState {
            database: Arc::new(crate::storage::Database::new(&root.join("db")).unwrap()),
            scanners: Arc::new(crate::scanners::ScannerRegistry::new()),
            data_dir: root.to_path_buf(),
            cancel_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn report(path: &Path, results: serde_json::Value) {
        std::fs::write(
            path,
            serde_json::to_vec(&json!({
                "version":"2.1.0", "runs":[{"tool":{"driver":{"name":"Demo"}},"results":results}]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn empty_import_retains_coverage_and_marks_absence_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let path = dir.path().join("input.sarif");
        report(
            &path,
            json!([{"ruleId":"demo.rule","message":{"text":"Synthetic finding"}}]),
        );
        let first = import_path(&state, &path, None, None).unwrap();
        report(&path, json!([]));
        let second = import_path(&state, &path, Some(&first.scan_run.project_id), None).unwrap();
        let diff = state
            .database
            .scan_diff(
                &first.scan_run.project_id,
                &second.scan_run.id,
                Some(&first.scan_run.id),
            )
            .unwrap()
            .unwrap();
        assert_eq!(diff.fixed_count, 1);
        assert_eq!(second.scan_run.scanners[0].scanner_id, "demo");
    }

    #[test]
    fn failed_import_does_not_leave_a_running_scan() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let path = dir.path().join("input.sarif");
        report(&path, json!([]));
        let connection = rusqlite::Connection::open(dir.path().join("db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_artifact BEFORE INSERT ON scan_artifacts BEGIN SELECT RAISE(ABORT,'test import failure'); END;").unwrap();
        assert!(import_path(&state, &path, None, None).is_err());
        let status: String = connection
            .query_row("SELECT status FROM scan_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "failed");
    }
}
