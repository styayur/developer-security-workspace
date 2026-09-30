use crate::error::{AppError, AppResult};
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
    pub active_scans: Arc<Mutex<HashMap<String, String>>>,
}

pub struct ScanLease {
    active_scans: Arc<Mutex<HashMap<String, String>>>,
    project_id: String,
    scan_run_id: String,
}

impl Drop for ScanLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_scans.lock() {
            if active
                .get(&self.project_id)
                .is_some_and(|run_id| run_id == &self.scan_run_id)
            {
                active.remove(&self.project_id);
            }
        }
    }
}

impl AppState {
    pub fn begin_scan(&self, project_id: &str, scan_run_id: &str) -> AppResult<ScanLease> {
        let mut active = self
            .active_scans
            .lock()
            .map_err(|_| AppError::Process("Active scan registry is unavailable.".into()))?;
        if active.contains_key(project_id) {
            return Err(AppError::InvalidInput(
                "A scan is already running for this project. Wait for it to finish or cancel it before starting another.".into(),
            ));
        }
        active.insert(project_id.to_string(), scan_run_id.to_string());
        Ok(ScanLease {
            active_scans: self.active_scans.clone(),
            project_id: project_id.to_string(),
            scan_run_id: scan_run_id.to_string(),
        })
    }

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
            active_scans: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_scan_lease_blocks_concurrency_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            database: Arc::new(Database::new(&dir.path().join("db")).unwrap()),
            scanners: Arc::new(ScannerRegistry::new()),
            data_dir: dir.path().to_path_buf(),
            cancel_tokens: Arc::new(Mutex::new(HashMap::new())),
            active_scans: Arc::new(Mutex::new(HashMap::new())),
        };

        let first = state.begin_scan("project-a", "run-1").unwrap();
        assert!(state.begin_scan("project-a", "run-2").is_err());
        let other = state.begin_scan("project-b", "run-3").unwrap();
        drop(first);
        assert!(state.begin_scan("project-a", "run-4").is_ok());
        drop(other);
    }
}
