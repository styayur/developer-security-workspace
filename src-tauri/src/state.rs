use crate::error::AppResult;
use crate::scanners::ScannerRegistry;
use crate::storage::Database;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct AppState {
    pub database: Arc<Database>,
    pub scanners: Arc<ScannerRegistry>,
    pub data_dir: PathBuf,
    pub cancel_tokens: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

impl AppState {
    pub fn initialize(app: &AppHandle) -> AppResult<Self> {
        let data_dir = app.path().app_data_dir().map_err(|error| {
            crate::error::AppError::Workspace(format!(
                "Unable to resolve app data directory: {error}"
            ))
        })?;
        std::fs::create_dir_all(&data_dir)?;
        let database = Database::new(&data_dir.join("workspace.db"))?;
        Ok(Self {
            database: Arc::new(database),
            scanners: Arc::new(ScannerRegistry::new()),
            data_dir,
            cancel_tokens: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}
