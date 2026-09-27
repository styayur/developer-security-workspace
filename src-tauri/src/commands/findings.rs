use crate::commands::blocking;
use crate::error::AppResult;
use crate::security_ir::{
    DashboardSummary, Finding, FindingFilters, FindingListItem, Rule, ScanDiff, ScanRun,
    TriageUpdate,
};
use crate::state::AppState;
use tauri::State;

#[tauri::command]
pub async fn list_findings(
    state: State<'_, AppState>,
    filters: FindingFilters,
) -> AppResult<Vec<FindingListItem>> {
    let state = state.inner().clone();
    blocking(move || Ok(state.database.finding_page(&filters, 0, 500)?.items)).await
}

#[tauri::command]
pub async fn get_finding(state: State<'_, AppState>, finding_id: String) -> AppResult<Finding> {
    let state = state.inner().clone();
    blocking(move || state.database.get_finding(&finding_id)).await
}

#[tauri::command]
pub async fn update_triage(state: State<'_, AppState>, update: TriageUpdate) -> AppResult<Finding> {
    let state = state.inner().clone();
    blocking(move || {
        state
            .database
            .update_triage(&update.finding_id, update.status, update.note)
    })
    .await
}

#[tauri::command]
pub async fn dashboard(
    state: State<'_, AppState>,
    project_id: String,
) -> AppResult<DashboardSummary> {
    let state = state.inner().clone();
    blocking(move || state.database.dashboard(&project_id)).await
}

#[tauri::command]
pub async fn list_rules(state: State<'_, AppState>, project_id: String) -> AppResult<Vec<Rule>> {
    let state = state.inner().clone();
    blocking(move || state.database.list_rules(&project_id)).await
}

#[tauri::command]
pub async fn list_scan_runs(
    state: State<'_, AppState>,
    project_id: String,
    limit: Option<usize>,
) -> AppResult<Vec<ScanRun>> {
    let state = state.inner().clone();
    blocking(move || {
        state
            .database
            .list_scan_runs(&project_id, limit.unwrap_or(100).min(500))
    })
    .await
}

#[tauri::command]
pub async fn get_scan_run(state: State<'_, AppState>, scan_run_id: String) -> AppResult<ScanRun> {
    let state = state.inner().clone();
    blocking(move || state.database.get_scan_run(&scan_run_id)).await
}

#[tauri::command]
pub async fn scan_diff(
    state: State<'_, AppState>,
    project_id: String,
    current_run_id: String,
    previous_run_id: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> AppResult<Option<ScanDiff>> {
    let state = state.inner().clone();
    blocking(move || {
        state.database.scan_diff_page(
            &project_id,
            &current_run_id,
            previous_run_id.as_deref(),
            offset.unwrap_or(0),
            limit.unwrap_or(100),
        )
    })
    .await
}

#[tauri::command]
pub async fn finding_page(
    state: State<'_, AppState>,
    filters: FindingFilters,
    offset: Option<usize>,
    limit: Option<usize>,
) -> AppResult<crate::security_ir::FindingPage> {
    let state = state.inner().clone();
    blocking(move || {
        state
            .database
            .finding_page(&filters, offset.unwrap_or(0), limit.unwrap_or(100))
    })
    .await
}
#[tauri::command]
pub async fn finding_scanners(
    state: State<'_, AppState>,
    project_id: String,
) -> AppResult<Vec<String>> {
    let state = state.inner().clone();
    blocking(move || state.database.finding_scanners(&project_id)).await
}

#[tauri::command]
pub async fn finding_navigation(
    state: State<'_, AppState>,
    finding_id: String,
) -> AppResult<serde_json::Value> {
    let state = state.inner().clone();
    blocking(move || state.database.finding_navigation(&finding_id)).await
}
