use crate::error::{AppError, AppResult};
use crate::scanners::{ScanContext, ScannerProvider};
use crate::security_ir::{
    LogEntry, ScanProgressEvent, ScanRequest, ScanRun, ScanStatus, ScannerRun, ScannerRunStatus,
};
use crate::state::AppState;
use chrono::Utc;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_CONCURRENT_SCANNERS: usize = 2;

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    mut request: ScanRequest,
) -> AppResult<ScanRun> {
    request.scanner_ids.sort();
    request.scanner_ids.dedup();
    if request.scanner_ids.is_empty() {
        return Err(AppError::InvalidInput(
            "Select at least one scanner.".into(),
        ));
    }
    if request.scanner_ids.len() > 8 {
        return Err(AppError::InvalidInput(
            "A scan can contain at most eight scanners.".into(),
        ));
    }
    let project = state.database.get_project(&request.project_id)?;
    let requested_root = std::fs::canonicalize(&request.workspace_root)
        .map_err(|error| AppError::Workspace(format!("Unable to open scan target: {error}")))?;
    let project_root = std::fs::canonicalize(&project.path)?;
    if requested_root != project_root {
        return Err(AppError::Workspace(
            "Scan target must match the active project workspace.".into(),
        ));
    }
    request.workspace_root = requested_root.to_string_lossy().to_string();
    if request.mode == "changed" {
        request.changed_files = collect_changed_files(&request.workspace_root)?;
        if request.changed_files.is_empty() {
            return Err(AppError::InvalidInput(
                "Changed Files mode found no tracked or untracked changes.".into(),
            ));
        }
    }
    for scanner_id in &request.scanner_ids {
        state.provider(scanner_id, &request)?;
        if let Some(config) = state
            .database
            .get_scanner_config(&request.project_id, scanner_id)?
        {
            let entry = request
                .scanner_configs
                .entry(scanner_id.clone())
                .or_insert_with(|| serde_json::json!({}));
            if let Some(path) = config.executable_path {
                if let Some(object) = entry.as_object_mut() {
                    object.insert("executablePath".into(), serde_json::Value::String(path));
                }
            }
            if let (Some(configured), Some(stored)) =
                (entry.as_object_mut(), config.config.as_object())
            {
                for (key, value) in stored {
                    configured
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
            }
        }
    }
    let run = state.database.create_scan_run(
        &request.project_id,
        if request.mode == "changed" {
            "scan_changed"
        } else {
            "scan"
        },
    )?;
    let cancellation = CancellationToken::new();
    state
        .cancel_tokens
        .lock()
        .map_err(|_| AppError::Process("Cancellation registry is unavailable.".into()))?
        .insert(run.id.clone(), cancellation.clone());
    for scanner_id in &request.scanner_ids {
        let provider = state.provider(scanner_id, &request)?;
        let now = Utc::now().to_rfc3339();
        state.database.upsert_scanner_run(&ScannerRun {
            id: Uuid::new_v4().to_string(),
            scan_run_id: run.id.clone(),
            scanner_id: scanner_id.clone(),
            scanner_name: provider.display_name().into(),
            status: ScannerRunStatus::Queued,
            version: None,
            started_at: now.clone(),
            finished_at: None,
            duration_ms: None,
            error: None,
            logs: Vec::new(),
        })?;
    }
    let state_for_task = state.inner().clone();
    let run_for_task = run.clone();
    tauri::async_runtime::spawn(async move {
        let status = execute_scan(
            app.clone(),
            state_for_task.clone(),
            run_for_task.clone(),
            request,
            cancellation.clone(),
        )
        .await;
        if let Err(error) = state_for_task
            .database
            .finish_scan_run(&run_for_task.id, status.clone())
        {
            tracing::error!(run_id = %run_for_task.id, error = %error, "failed to finalize scan run");
        }
        if let Ok(mut tokens) = state_for_task.cancel_tokens.lock() {
            tokens.remove(&run_for_task.id);
        }
        if let Ok(completed) = state_for_task.database.get_scan_run(&run_for_task.id) {
            let _ = app.emit("scan://completed", &completed);
        }
    });
    state.database.get_scan_run(&run.id)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>, scan_run_id: String) -> AppResult<()> {
    let tokens = state
        .cancel_tokens
        .lock()
        .map_err(|_| AppError::Process("Cancellation registry is unavailable.".into()))?;
    let token = tokens
        .get(&scan_run_id)
        .ok_or_else(|| AppError::NotFound(format!("Active scan {scan_run_id}")))?;
    token.cancel();
    Ok(())
}

async fn execute_scan(
    app: AppHandle,
    state: AppState,
    run: ScanRun,
    request: ScanRequest,
    cancellation: CancellationToken,
) -> ScanStatus {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SCANNERS));
    let mut tasks = JoinSet::new();
    for scanner_id in request.scanner_ids.clone() {
        let app = app.clone();
        let state = state.clone();
        let run = run.clone();
        let request = request.clone();
        let cancellation = cancellation.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return false,
            };
            run_scanner(app, state, run, request, scanner_id, cancellation).await
        });
    }
    let mut successful = 0;
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        completed += 1;
        if result.unwrap_or(false) {
            successful += 1;
        }
    }
    if cancellation.is_cancelled() {
        ScanStatus::Cancelled
    } else if successful == completed && completed > 0 {
        ScanStatus::Completed
    } else if successful > 0 {
        ScanStatus::Partial
    } else {
        ScanStatus::Failed
    }
}

async fn run_scanner(
    app: AppHandle,
    state: AppState,
    run: ScanRun,
    request: ScanRequest,
    scanner_id: String,
    cancellation: CancellationToken,
) -> bool {
    let provider = match state.provider(&scanner_id, &request) {
        Ok(provider) => provider,
        Err(_) => return false,
    };
    let scanner_run_id = find_queued_scanner_run(&state, &run.id, &scanner_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let started_at = Utc::now();
    let (log_tx, mut log_rx) = mpsc::unbounded_channel::<LogEntry>();
    let log_store = Arc::new(Mutex::new(Vec::<LogEntry>::new()));
    let app_for_logs = app.clone();
    let run_for_logs = run.id.clone();
    let scanner_for_logs = scanner_id.clone();
    let log_store_for_task = log_store.clone();
    let log_task = tauri::async_runtime::spawn(async move {
        while let Some(entry) = log_rx.recv().await {
            if log_store_for_task.lock().await.len() < 10_000 {
                log_store_for_task.lock().await.push(entry.clone());
            }
            let _ = app_for_logs.emit(
                "scan://log",
                serde_json::json!({
                    "scanRunId": run_for_logs,
                    "scannerId": scanner_for_logs,
                    "entry": entry
                }),
            );
        }
    });
    let mut context = ScanContext {
        cancel: cancellation.child_token(),
        logs: Some(log_tx),
        timeout: provider.timeout(),
    };
    emit_progress(
        &app,
        &run.id,
        provider.as_ref(),
        ScannerRunStatus::Running,
        "Scanning",
        0,
        0,
    );
    let scan_started = Instant::now();
    let scan_result = {
        let future = provider.scan(&request, &context);
        tokio::pin!(future);
        tokio::select! {
            result=&mut future => Ok(result),
            _=tokio::time::sleep(context.timeout) => {
                context.cancel.cancel();
                let _=tokio::time::timeout(Duration::from_secs(5),&mut future).await;
                Err(())
            }
        }
    };
    let elapsed = scan_started.elapsed().as_millis() as u64;
    context.logs = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), log_task).await;
    let logs = log_store.lock().await.clone();
    let (status, error, finding_count) = match scan_result {
        Err(_) => {
            let _ = provider.cancel(&context).await;
            context.cancel.cancel();
            (
                ScannerRunStatus::Failed,
                Some(format!(
                    "Scanner timed out after {} seconds.",
                    context.timeout.as_secs()
                )),
                0,
            )
        }
        Ok(Err(error)) if cancellation.is_cancelled() => {
            (ScannerRunStatus::Cancelled, Some(error.to_string()), 0)
        }
        Ok(Err(error)) => (ScannerRunStatus::Failed, Some(error.to_string()), 0),
        Ok(Ok(logs)) => {
            let workspace = Path::new(&request.workspace_root);
            let changed_files = request
                .changed_files
                .iter()
                .map(|path| path.replace('\\', "/").to_ascii_lowercase())
                .collect::<std::collections::HashSet<_>>();
            let mut findings = Vec::new();
            let mut storage_error = None;
            for log in &logs {
                match crate::sarif::normalize_log_with_scanner(
                    log,
                    workspace,
                    &run.project_id,
                    &run.id,
                    &scanner_id,
                ) {
                    Ok(mut normalized) => {
                        match serde_json::to_string(log)
                            .map_err(AppError::from)
                            .and_then(|raw| {
                                state.database.insert_scan_artifact(
                                    &run.id,
                                    &scanner_id,
                                    "sarif",
                                    &raw,
                                )
                            }) {
                            Ok(artifact) => {
                                for finding in &mut normalized {
                                    if let Some(reference) = &mut finding.raw_reference {
                                        reference.artifact_id = artifact.clone();
                                        finding.raw_sarif = serde_json::Value::Null;
                                    }
                                }
                            }
                            Err(error) => storage_error = Some(error.to_string()),
                        }
                        if request.mode == "changed" {
                            normalized.retain(|finding| {
                                changed_files.contains(
                                    &finding
                                        .location
                                        .file_path
                                        .replace('\\', "/")
                                        .to_ascii_lowercase(),
                                )
                            });
                        }
                        findings.append(&mut normalized);
                    }
                    Err(error) => storage_error = Some(error.to_string()),
                }
            }
            let count = findings.len();
            if let Err(error) = state.database.insert_findings(&findings) {
                storage_error = Some(error.to_string());
            }
            if let Some(error) = storage_error {
                (ScannerRunStatus::Failed, Some(error), count)
            } else {
                (ScannerRunStatus::Completed, None, count)
            }
        }
    };
    let finished_at = Utc::now().to_rfc3339();
    let scanner_run = ScannerRun {
        id: scanner_run_id,
        scan_run_id: run.id.clone(),
        scanner_id: scanner_id.clone(),
        scanner_name: provider.display_name().into(),
        status: status.clone(),
        version: None,
        started_at: started_at.to_rfc3339(),
        finished_at: Some(finished_at),
        duration_ms: Some(elapsed),
        error: error.clone(),
        logs,
    };
    let saved = state.database.upsert_scanner_run(&scanner_run).is_ok();
    let message = error.unwrap_or_else(|| format!("Completed with {finding_count} finding(s)"));
    emit_progress(
        &app,
        &run.id,
        provider.as_ref(),
        status.clone(),
        &message,
        elapsed,
        finding_count,
    );
    saved && status == ScannerRunStatus::Completed
}

fn find_queued_scanner_run(
    state: &AppState,
    scan_run_id: &str,
    scanner_id: &str,
) -> Option<String> {
    state
        .database
        .get_scan_run(scan_run_id)
        .ok()?
        .scanners
        .into_iter()
        .find(|run| run.scanner_id == scanner_id && run.status == ScannerRunStatus::Queued)
        .map(|run| run.id)
}

fn collect_changed_files(workspace_root: &str) -> AppResult<Vec<String>> {
    let mut files = std::collections::BTreeSet::new();
    for args in [
        vec!["diff", "--name-only", "HEAD"],
        vec!["ls-files", "--others", "--exclude-standard"],
    ] {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(workspace_root)
            .args(args)
            .output()
            .map_err(|error| {
                AppError::Workspace(format!("Unable to inspect Git changes: {error}"))
            })?;
        if !output.status.success() {
            return Err(AppError::Workspace(
                "Changed Files mode requires a Git repository with a valid HEAD.".into(),
            ));
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let file = line.trim().replace('\\', "/");
            if !file.is_empty() {
                files.insert(file);
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn emit_progress(
    app: &AppHandle,
    scan_run_id: &str,
    provider: &dyn ScannerProvider,
    status: ScannerRunStatus,
    message: &str,
    elapsed_ms: u64,
    finding_count: usize,
) {
    let _ = app.emit(
        "scan://progress",
        ScanProgressEvent {
            scan_run_id: scan_run_id.into(),
            scanner_id: provider.id().into(),
            scanner_name: provider.display_name().into(),
            status,
            message: message.into(),
            elapsed_ms,
            finding_count,
        },
    );
}
