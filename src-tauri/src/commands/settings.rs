use crate::commands::blocking;
use crate::error::AppResult;
use crate::security_ir::AppSetting;
use crate::state::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_setting(
    state: State<'_, AppState>,
    key: String,
) -> AppResult<Option<serde_json::Value>> {
    let state = state.inner().clone();
    blocking(move || state.database.get_setting(&key)).await
}

#[tauri::command]
pub async fn set_setting(state: State<'_, AppState>, setting: AppSetting) -> AppResult<()> {
    let state = state.inner().clone();
    blocking(move || state.database.set_setting(&setting.key, &setting.value)).await
}
