use crate::commands::blocking;
use crate::error::{AppError, AppResult};
use crate::security_ir::{ScannerConfig, ScannerInstallation};
use crate::state::AppState;
use std::path::{Path, PathBuf};
use tauri::State;

#[tauri::command]
pub async fn list_scanners(
    state: State<'_, AppState>,
    project_id: Option<String>,
) -> AppResult<Vec<ScannerInstallation>> {
    let state = state.inner().clone();
    let mut installations = Vec::new();
    for provider in state.scanners.all() {
        let configured = if let Some(project_id) = &project_id {
            state
                .database
                .get_scanner_config(project_id, provider.id())?
                .and_then(|config| config.executable_path)
                .map(PathBuf::from)
        } else {
            None
        };
        installations.push(provider.detect(configured.as_deref()).await);
    }
    Ok(installations)
}

#[tauri::command]
pub async fn configure_scanner(
    state: State<'_, AppState>,
    project_id: String,
    scanner_id: String,
    executable_path: Option<String>,
    config: serde_json::Value,
) -> AppResult<ScannerConfig> {
    let state = state.inner().clone();
    blocking(move || {
        let path = executable_path
            .as_deref()
            .map(Path::new)
            .map(validate_executable)
            .transpose()?;
        state
            .database
            .set_scanner_config(&project_id, &scanner_id, path.as_deref(), &config)
    })
    .await
}

#[tauri::command]
pub async fn clear_scanner_config(
    state: State<'_, AppState>,
    project_id: String,
    scanner_id: String,
) -> AppResult<ScannerConfig> {
    let state = state.inner().clone();
    blocking(move || {
        state
            .database
            .set_scanner_config(&project_id, &scanner_id, None, &serde_json::json!({}))
    })
    .await
}

fn validate_executable(path: &Path) -> AppResult<String> {
    if !path.is_file() {
        return Err(AppError::InvalidInput(format!(
            "Scanner executable does not exist: {}",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("exe") {
            return Err(AppError::InvalidInput(
                "For scanner security, Windows scanner executables must be .exe files. Shell wrappers such as .cmd, .bat, and .ps1 are rejected.".into(),
            ));
        }
    }
    Ok(path.to_string_lossy().to_string())
}
