use super::{
    config_string, config_strings, locate_executable, parse_sarif_file, scanner_config,
    validate_extra_args, ScanContext, ScannerProvider,
};
use crate::error::{AppError, AppResult};
use crate::process::run_command;
use crate::sarif::SarifLog;
use crate::security_ir::{ScanRequest, ScannerCapabilities};
use async_trait::async_trait;
use std::path::Path;
use tempfile::Builder;

pub struct TrivyProvider;

#[async_trait]
impl ScannerProvider for TrivyProvider {
    fn id(&self) -> &str {
        "trivy"
    }
    fn display_name(&self) -> &str {
        "Trivy"
    }
    fn config_fields(&self) -> Vec<crate::security_ir::ScannerConfigField> {
        vec![crate::security_ir::ScannerConfigField {
            key: "scanners".into(),
            label: "Scan categories".into(),
            kind: "multi_select".into(),
            default_value: serde_json::json!(["vuln", "misconfig", "secret", "license"]),
            options: vec![
                "vuln".into(),
                "misconfig".into(),
                "secret".into(),
                "license".into(),
            ],
            help: None,
        }]
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            sca: true,
            secrets: true,
            iac: true,
            container: true,
            licenses: true,
            vulnerabilities: true,
            misconfiguration: true,
            ..Default::default()
        }
    }
    fn license(&self) -> &'static str {
        "Apache-2.0"
    }
    fn project_url(&self) -> &'static str {
        "https://trivy.dev/"
    }
    fn install_command(&self) -> &'static str {
        "winget install AquaSecurity.Trivy"
    }
    fn description(&self) -> &'static str {
        "Filesystem vulnerabilities, secrets, misconfiguration, and licenses"
    }
    fn known_commands(&self) -> &'static [&'static str] {
        &["trivy"]
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
        let mut scanners = config
            .get("scanners")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "vuln".into(),
                    "misconfig".into(),
                    "secret".into(),
                    "license".into(),
                ]
            });
        if scanners.is_empty() {
            return Err(AppError::Scanner(
                "Select at least one Trivy scanner category.".into(),
            ));
        }
        scanners.sort();
        scanners.dedup();
        let extra = config_strings(config, "extraArgs");
        validate_extra_args(&extra)?;
        let temp = Builder::new().prefix("dsw-trivy-").tempdir()?;
        let output_path = temp.path().join("results.sarif");
        let mut args = vec![
            "fs".into(),
            "--format".into(),
            "sarif".into(),
            "--output".into(),
            output_path.to_string_lossy().to_string(),
            "--scanners".into(),
            scanners.join(","),
            "--quiet".into(),
        ];
        if config
            .get("skipDbUpdate")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            args.push("--skip-db-update".into());
        }
        args.extend(extra);
        args.push(request.workspace_root.clone());
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
                "Trivy did not produce SARIF (exit {:?}). {}",
                output.status_code,
                output.stderr.trim()
            )));
        }
        Ok(vec![parse_sarif_file(&output_path)?])
    }
}
