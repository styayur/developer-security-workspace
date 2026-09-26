use crate::commands::blocking;
use crate::error::{AppError, AppResult};
use crate::extensions;
use crate::licenses;
use crate::process::run_command;
use crate::security_ir::{ComponentInfo, ExtensionManifest};
use crate::state::AppState;
use std::path::{Path, PathBuf};
use tauri::State;
use tokio_util::sync::CancellationToken;

#[tauri::command]
pub async fn list_components() -> AppResult<Vec<ComponentInfo>> {
    blocking(|| Ok(licenses::components())).await
}

#[tauri::command]
pub async fn list_extensions(state: State<'_, AppState>) -> AppResult<Vec<ExtensionManifest>> {
    let state = state.inner().clone();
    blocking(move || extensions::load_manifests(Some(&state.data_dir.join("extensions")))).await
}

#[tauri::command]
pub async fn verify_codeql(runtime_path: String) -> AppResult<serde_json::Value> {
    let path = PathBuf::from(&runtime_path);
    if !path.is_file() {
        return Err(AppError::InvalidInput(
            "CodeQL executable does not exist.".into(),
        ));
    }
    #[cfg(windows)]
    if !path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(AppError::InvalidInput(
            "Windows CodeQL runtime must be an .exe file.".into(),
        ));
    }
    let output = run_command(
        &path,
        &["version".into()],
        path.parent().unwrap_or_else(|| Path::new(".")),
        CancellationToken::new(),
        None,
    )
    .await?;
    if !output.success {
        return Err(AppError::Scanner(format!(
            "CodeQL version check failed: {}",
            output.stderr.trim()
        )));
    }
    let version = output
        .stdout
        .lines()
        .next()
        .unwrap_or("CodeQL")
        .trim()
        .to_string();
    Ok(serde_json::json!({ "path": path, "version": version }))
}
