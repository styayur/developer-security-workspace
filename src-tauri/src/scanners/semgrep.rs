use super::{
    config_string, config_strings, locate_executable, parse_sarif_file, scan_targets,
    scanner_config, validate_extra_args, ScanContext, ScannerProvider,
};
use crate::error::{AppError, AppResult};
use crate::process::run_command;
use crate::sarif::SarifLog;
use crate::security_ir::{ScanRequest, ScannerCapabilities};
use async_trait::async_trait;
use std::path::Path;
use tempfile::Builder;

pub struct SemgrepProvider;

#[async_trait]
impl ScannerProvider for SemgrepProvider {
    fn id(&self) -> &str {
        "semgrep"
    }
    fn display_name(&self) -> &str {
        "Semgrep"
    }
    fn config_fields(&self) -> Vec<crate::security_ir::ScannerConfigField> {
        vec![
crate::security_ir::ScannerConfigField { key:"config".into(),label:"Rule source".into(),kind:"text".into(),default_value:serde_json::json!("p/default"),options:vec![],help:Some("Local path, directory, or registry identifier. Engine and rule licenses are separate.".into()) },
crate::security_ir::ScannerConfigField { key:"extraArgs".into(),label:"Additional structured args".into(),kind:"arguments".into(),default_value:serde_json::json!([]),options:vec![],help:Some("Use individual flags, for example --timeout=30.".into()) }
]
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            sast: true,
            secrets: true,
            misconfiguration: true,
            ..Default::default()
        }
    }
    fn license(&self) -> &'static str {
        "LGPL-2.1 engine; rules may be separately licensed"
    }
    fn project_url(&self) -> &'static str {
        "https://semgrep.dev/"
    }
    fn install_command(&self) -> &'static str {
        "python -m pip install semgrep"
    }
    fn description(&self) -> &'static str {
        "SAST, taint analysis, and optional secret rules"
    }
    fn known_commands(&self) -> &'static [&'static str] {
        &["semgrep"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["--version"]
    }

    async fn scan(&self, request: &ScanRequest, context: &ScanContext) -> AppResult<Vec<SarifLog>> {
        let config = scanner_config(request, self.id());
        let configured: Option<std::path::PathBuf> =
            config_string(config, "executablePath").map(Into::into);
        let executable =
            locate_executable(configured.as_deref(), self.known_commands(), self.id()).await?;
        let rule_config = config_string(config, "config").unwrap_or_else(|| "p/default".into());
        if rule_config.trim().is_empty() {
            return Err(AppError::Scanner(
                "Semgrep requires a local rule path, directory, or registry config identifier."
                    .into(),
            ));
        }
        let extra = config_strings(config, "extraArgs");
        validate_extra_args(&extra)?;
        let temp = Builder::new().prefix("dsw-semgrep-").tempdir()?;
        let output_path = temp.path().join("results.sarif");
        let mut args = vec![
            "scan".into(),
            "--sarif".into(),
            "--output".into(),
            output_path.to_string_lossy().to_string(),
            "--metrics=off".into(),
            "--config".into(),
            rule_config,
        ];
        args.extend(extra);
        args.extend(scan_targets(request)?);
        context.log("info", format!("Launching {}", executable.display()));
        let output = run_command(
            &executable,
            &args,
            Path::new(&request.workspace_root),
            context.cancel.clone(),
            context.logs.clone(),
        )
        .await?;
        if !output_path.is_file() {
            return Err(AppError::Scanner(format!(
                "Semgrep did not produce SARIF (exit {:?}). {}",
                output.status_code,
                output.stderr.trim()
            )));
        }
        Ok(vec![parse_sarif_file(&output_path)?])
    }
}
