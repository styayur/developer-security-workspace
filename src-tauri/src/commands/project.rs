use crate::commands::blocking;
use crate::error::AppResult;
use crate::security_ir::{Project, RecentProject, SourceFile};
use crate::state::AppState;
use crate::workspace::{detect_project, read_source_file};
use std::path::Path;
use tauri::State;

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

#[tauri::command]
pub async fn open_project(state: State<'_, AppState>, path: String) -> AppResult<Project> {
    let state = state.inner().clone();
    blocking(move || {
        let project = detect_project(Path::new(&path))?;
        state.database.open_project(&project)
    })
    .await
}

#[tauri::command]
pub async fn get_project(state: State<'_, AppState>, project_id: String) -> AppResult<Project> {
    let state = state.inner().clone();
    blocking(move || state.database.get_project(&project_id)).await
}

#[tauri::command]
pub async fn recent_projects(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> AppResult<Vec<RecentProject>> {
    let state = state.inner().clone();
    blocking(move || state.database.recent_projects(limit.unwrap_or(12).min(50))).await
}

#[tauri::command]
pub async fn read_source(
    state: State<'_, AppState>,
    project_id: String,
    path: String,
) -> AppResult<SourceFile> {
    let state = state.inner().clone();
    blocking(move || {
        let project = state.database.get_project(&project_id)?;
        read_source_file(&project, &path, MAX_SOURCE_BYTES)
    })
    .await
}
