pub mod findings;
pub mod project;
pub mod sarif;
pub mod scanners;
pub mod scans;
pub mod settings;
pub mod system;

use crate::error::{AppError, AppResult};

pub async fn blocking<T, F>(work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> AppResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| AppError::Process(format!("Background task failed: {error}")))?
}
