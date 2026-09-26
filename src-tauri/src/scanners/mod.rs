mod bandit;
mod semgrep;
mod trivy;
mod trufflehog;

use crate::error::{AppError, AppResult};
use crate::process::run_command;
use crate::sarif::{parse_sarif, SarifLog};
use crate::security_ir::{LogEntry, ScanRequest, ScannerCapabilities, ScannerInstallation};
use async_trait::async_trait;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

pub use bandit::BanditProvider;
pub use semgrep::SemgrepProvider;
pub use trivy::TrivyProvider;
pub use trufflehog::TruffleHogProvider;

#[derive(Clone)]
pub struct ScanContext {
    pub cancel: CancellationToken,
    pub logs: Option<UnboundedSender<LogEntry>>,
    pub timeout: Duration,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            cancel: CancellationToken::new(),
            logs: None,
            timeout: Duration::from_secs(15 * 60),
        }
    }
}

impl ScanContext {
    pub fn log(&self, stream: &str, message: impl Into<String>) {
        if let Some(logs) = &self.logs {
            let _ = logs.send(LogEntry {
                timestamp: Utc::now().to_rfc3339(),
                stream: stream.into(),
                message: crate::secret_redaction::SecretRedactor::redact_text(&message.into()),
            });
        }
    }
}

#[async_trait]
pub trait ScannerProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn capabilities(&self) -> ScannerCapabilities;
    fn license(&self) -> &'static str;
    fn project_url(&self) -> &'static str;
    fn install_command(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn known_commands(&self) -> &'static [&'static str];
    fn version_args(&self) -> &'static [&'static str];

    async fn detect(&self, configured_path: Option<&Path>) -> ScannerInstallation {
        let executable = locate_executable(configured_path, self.known_commands(), self.id()).await;
        match executable {
            Ok(path) => {
                let version = command_version(&path, self.version_args())
                    .await
                    .ok()
                    .flatten();
                ScannerInstallation {
                    id: self.id().into(),
                    display_name: self.display_name().into(),
                    installed: true,
                    executable: Some(path.to_string_lossy().to_string()),
                    version,
                    capabilities: self.capabilities(),
                    license: self.license().into(),
                    project_url: self.project_url().into(),
                    install_command: self.install_command().into(),
                    description: self.description().into(),
                    configured_path: configured_path
                        .map(|value| value.to_string_lossy().to_string()),
                    detection_error: None,
                }
            }
            Err(error) => ScannerInstallation {
                id: self.id().into(),
                display_name: self.display_name().into(),
                installed: false,
                executable: None,
                version: None,
                capabilities: self.capabilities(),
                license: self.license().into(),
                project_url: self.project_url().into(),
                install_command: self.install_command().into(),
                description: self.description().into(),
                configured_path: configured_path.map(|value| value.to_string_lossy().to_string()),
                detection_error: Some(error.to_string()),
            },
        }
    }

    async fn scan(&self, request: &ScanRequest, context: &ScanContext) -> AppResult<Vec<SarifLog>>;

    async fn cancel(&self, context: &ScanContext) -> AppResult<()> {
        context.cancel.cancel();
        Ok(())
    }
}

pub struct ScannerRegistry {
    providers: Vec<Arc<dyn ScannerProvider>>,
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerRegistry {
    pub fn new() -> Self {
        Self {
            providers: vec![
                Arc::new(SemgrepProvider),
                Arc::new(TrivyProvider),
                Arc::new(TruffleHogProvider),
                Arc::new(BanditProvider),
            ],
        }
    }

    pub fn all(&self) -> &[Arc<dyn ScannerProvider>] {
        &self.providers
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn ScannerProvider>> {
        self.providers
            .iter()
            .find(|provider| provider.id() == id)
            .cloned()
    }
}

pub async fn locate_executable(
    configured_path: Option<&Path>,
    commands: &[&str],
    scanner_id: &str,
) -> AppResult<PathBuf> {
    if let Some(path) = configured_path {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(AppError::Scanner(format!(
            "Configured executable for {scanner_id} does not exist: {}",
            path.display()
        )));
    }
    for command in commands {
        if let Ok(path) = which::which(command) {
            return Ok(path);
        }
    }
    for candidate in known_install_paths(scanner_id, commands) {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(AppError::Scanner(format!(
        "{scanner_id} was not found in PATH or known install locations."
    )))
}

async fn command_version(executable: &Path, args: &[&str]) -> AppResult<Option<String>> {
    let args = args
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let output = run_command(
        executable,
        &args,
        executable.parent().unwrap_or_else(|| Path::new(".")),
        CancellationToken::new(),
        None,
    )
    .await?;
    let text = if output.stdout.trim().is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    Ok(parse_version(&text))
}

pub fn parse_version(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| {
            let lowered = line.to_ascii_lowercase();
            let position = lowered.find("version")?;
            let after = line[position + "version".len()..]
                .trim()
                .trim_start_matches([':', '='])
                .trim();
            let token = after
                .split_whitespace()
                .next()?
                .trim_matches(['(', ')', ',']);
            (!token.is_empty()).then(|| token.trim_start_matches('v').to_string())
        })
        .or_else(|| {
            output
                .split_whitespace()
                .find(|token| {
                    token
                        .chars()
                        .next()
                        .is_some_and(|value| value.is_ascii_digit())
                })
                .map(|token| token.trim_start_matches('v').to_string())
        })
}

fn known_install_paths(scanner_id: &str, commands: &[&str]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        let home = PathBuf::from(home);
        for command in commands {
            #[cfg(windows)]
            paths.push(
                home.join("AppData")
                    .join("Roaming")
                    .join("Python")
                    .join(format!("{command}.exe")),
            );
            paths.push(home.join(".local").join("bin").join(command));
            paths.push(home.join("bin").join(command));
        }
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let local_app_data = PathBuf::from(local_app_data);
        for command in commands {
            paths.push(
                local_app_data
                    .join("Programs")
                    .join(command)
                    .join(format!("{command}.exe")),
            );
            paths.push(
                local_app_data
                    .join("Microsoft")
                    .join("WinGet")
                    .join("Links")
                    .join(format!("{command}.exe")),
            );
        }
        let python_roots = local_app_data.join("Programs").join("Python");
        if python_roots.is_dir() {
            for entry in walkdir::WalkDir::new(python_roots)
                .max_depth(2)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_dir()
                    && entry.file_name().to_string_lossy().starts_with("Python")
                {
                    for command in commands {
                        paths.push(entry.path().join("Scripts").join(format!("{command}.exe")));
                    }
                }
            }
        }
    }
    if scanner_id == "trivy" {
        if let Some(program_data) = std::env::var_os("ProgramData") {
            paths.push(
                PathBuf::from(program_data)
                    .join("chocolatey")
                    .join("bin")
                    .join("trivy.exe"),
            );
        }
    }
    paths
}

pub fn config_string(config: &serde_json::Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

pub fn config_strings(config: &serde_json::Value, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn validate_extra_args(args: &[String]) -> AppResult<()> {
    if args.len() > 64 {
        return Err(AppError::Scanner(
            "At most 64 additional scanner arguments are allowed.".into(),
        ));
    }
    for argument in args {
        if argument.contains('\0') || argument.contains('\n') || argument.contains('\r') {
            return Err(AppError::Scanner(
                "Scanner arguments cannot contain control characters.".into(),
            ));
        }
        if !argument.starts_with('-') {
            return Err(AppError::Scanner(format!(
                "Additional scanner argument must start with '-': {argument}"
            )));
        }
    }
    Ok(())
}

pub fn parse_sarif_file(path: &Path) -> AppResult<SarifLog> {
    let text = std::fs::read_to_string(path)?;
    parse_sarif(&text)
}

pub fn scanner_config<'a>(request: &'a ScanRequest, scanner_id: &str) -> &'a serde_json::Value {
    static EMPTY: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    request
        .scanner_configs
        .get(scanner_id)
        .unwrap_or_else(|| EMPTY.get_or_init(|| serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_version_formats() {
        assert_eq!(parse_version("semgrep 1.95.0"), Some("1.95.0".into()));
        assert_eq!(parse_version("Version: v2.3.4"), Some("2.3.4".into()));
    }

    #[test]
    fn rejects_shell_like_extra_args() {
        let error = validate_extra_args(&["rm -rf /".into()]).unwrap_err();
        assert!(error.to_string().contains("must start"));
    }
}
