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
    pub fn provider(
        &self,
        id: &str,
        request: &crate::security_ir::ScanRequest,
    ) -> AppResult<Arc<dyn crate::scanners::ScannerProvider>> {
        if let Some(provider) = self.scanners.get(id) {
            return Ok(provider);
        }
        let manifests = crate::extensions::load_manifests(Some(&self.data_dir.join("extensions")))?;
        let mut matching = manifests.into_iter().filter(|manifest| manifest.id == id);
        let manifest = matching.next().ok_or_else(|| {
            crate::error::AppError::InvalidInput(format!("Unsupported scanner: {id}"))
        })?;
        if matching.next().is_some() {
            return Err(crate::error::AppError::InvalidInput(
                "Duplicate extension identifiers are not executable.".into(),
            ));
        }
        let digest = request
            .scanner_configs
            .get(id)
            .and_then(|c| c.get("approvalDigest"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        Ok(Arc::new(crate::extensions::ExtensionProvider::approved(
            manifest, digest,
        )?))
    }

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
