use super::{
    config_string, config_strings, locate_executable, parse_sarif_file, scanner_config,
    validate_extra_args, ScanContext, ScannerProvider,
};
use crate::error::{AppError, AppResult};
use crate::process::run_command;
use crate::sarif::model::{
    SarifArtifactLocation, SarifLocation, SarifLog, SarifMessage, SarifPhysicalLocation,
    SarifRegion, SarifReportingDescriptor, SarifResult, SarifRun, SarifTool, SarifToolComponent,
};
use crate::security_ir::{ScanRequest, ScannerCapabilities};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;
use tempfile::Builder;

pub struct BanditProvider;

#[async_trait]
impl ScannerProvider for BanditProvider {
    fn id(&self) -> &'static str {
        "bandit"
    }
    fn display_name(&self) -> &'static str {
        "Bandit"
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            sast: true,
            ..Default::default()
        }
    }
    fn license(&self) -> &'static str {
        "Apache-2.0"
    }
    fn project_url(&self) -> &'static str {
        "https://bandit.readthedocs.io/"
    }
    fn install_command(&self) -> &'static str {
        "python -m pip install 'bandit[sarif]'"
    }
    fn description(&self) -> &'static str {
        "Python static application security testing"
    }
    fn known_commands(&self) -> &'static [&'static str] {
        &["bandit", "bandit.exe"]
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
        let extra = config_strings(config, "extraArgs");
        validate_extra_args(&extra)?;
        let temp = Builder::new().prefix("dsw-bandit-").tempdir()?;
        let output_path = temp.path().join("results.sarif");
        let mut sarif_args = vec![
            "-r".into(),
            request.workspace_root.clone(),
            "-f".into(),
            "sarif".into(),
            "-o".into(),
            output_path.to_string_lossy().to_string(),
        ];
        sarif_args.extend(extra.clone());
        context.log("info", format!("Launching {}", executable.display()));
        let primary = run_command(
            &executable,
            &sarif_args,
            Path::new(&request.workspace_root),
            context.cancel.clone(),
            context.logs.clone(),
        )
        .await;
        if primary.is_ok() && output_path.is_file() {
            if let Ok(log) = parse_sarif_file(&output_path) {
                return Ok(vec![log]);
            }
        }
        context.log(
            "stderr",
            "SARIF formatter unavailable. Using Bandit JSON compatibility adapter.",
        );
        let mut json_args = vec![
            "-r".into(),
            request.workspace_root.clone(),
            "-f".into(),
            "json".into(),
        ];
        json_args.extend(extra);
        let output = run_command(
            &executable,
            &json_args,
            Path::new(&request.workspace_root),
            context.cancel.clone(),
            context.logs.clone(),
        )
        .await?;
        if output.stdout.trim().is_empty() {
            return Err(AppError::Scanner(format!(
                "Bandit did not produce JSON output. {}",
                output.stderr.trim()
            )));
        }
        Ok(vec![adapt_bandit_json(&output.stdout)?])
    }
}

pub fn adapt_bandit_json(input: &str) -> AppResult<SarifLog> {
    let value: Value = serde_json::from_str(input)
        .map_err(|error| AppError::Scanner(format!("Bandit JSON is invalid: {error}")))?;
    let issues = value
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut results = Vec::new();
    let mut rules = Vec::new();
    let mut rule_indexes = std::collections::HashMap::new();
    for issue in issues {
        let test_id = issue
            .get("test_id")
            .and_then(Value::as_str)
            .unwrap_or("B000");
        let index = if let Some(index) = rule_indexes.get(test_id) {
            *index
        } else {
            let index = rules.len();
            rule_indexes.insert(test_id.to_string(), index);
            rules.push(SarifReportingDescriptor {
                id: test_id.into(),
                name: issue.get("test_name").and_then(Value::as_str).map(ToOwned::to_owned),
                short_description: issue.get("issue_text").and_then(Value::as_str).map(|text| SarifMessage { text: Some(text.into()), ..Default::default() }),
                help_uri: issue.get("more_info").and_then(Value::as_str).map(ToOwned::to_owned),
                properties: json!({"confidence": issue.get("issue_confidence"), "cwe": issue.get("issue_cwe")}),
                ..Default::default()
            });
            index
        };
        let severity = issue
            .get("issue_severity")
            .and_then(Value::as_str)
            .unwrap_or("LOW");
        let level = match severity.to_ascii_uppercase().as_str() {
            "HIGH" => "error",
            "MEDIUM" => "warning",
            _ => "note",
        };
        let filename = issue
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let line = issue
            .get("line_number")
            .and_then(Value::as_u64)
            .unwrap_or(1) as u32;
        let column = issue
            .get("col_offset")
            .and_then(Value::as_u64)
            .map(|value| value as u32 + 1)
            .unwrap_or(1);
        let end_column = issue
            .get("end_col_offset")
            .and_then(Value::as_u64)
            .map(|value| value as u32 + 1)
            .unwrap_or(column);
        let cwe_id = issue
            .get("issue_cwe")
            .and_then(|cwe| cwe.get("id"))
            .and_then(Value::as_u64);
        results.push(SarifResult {
            rule_id: Some(test_id.into()),
            rule_index: Some(index),
            level: Some(level.into()),
            message: SarifMessage { text: issue.get("issue_text").and_then(Value::as_str).map(ToOwned::to_owned), ..Default::default() },
            locations: vec![SarifLocation {
                physical_location: Some(SarifPhysicalLocation {
                    artifact_location: Some(SarifArtifactLocation { uri: Some(filename.replace('\\', "/")), ..Default::default() }),
                    region: Some(SarifRegion { start_line: Some(line), start_column: Some(column), end_line: Some(line), end_column: Some(end_column), ..Default::default() }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            properties: json!({
                "security-severity": if severity.eq_ignore_ascii_case("HIGH") { "8.0" } else if severity.eq_ignore_ascii_case("MEDIUM") { "5.0" } else { "2.0" },
                "issue_confidence": issue.get("issue_confidence"),
                "issue_cwe": issue.get("issue_cwe"),
                "cwe": cwe_id.map(|id| format!("CWE-{id}")),
                "source": "Bandit JSON compatibility adapter"
            }),
            ..Default::default()
        });
    }
    Ok(SarifLog {
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "Bandit".into(),
                    rules,
                    ..Default::default()
                },
                ..Default::default()
            },
            results,
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapts_bandit_json() {
        let input = r#"{"results":[{"test_id":"B602","test_name":"subprocess_popen_with_shell_equals_true","issue_severity":"HIGH","issue_confidence":"HIGH","issue_text":"subprocess call with shell=True","filename":"scripts/task.py","line_number":7,"col_offset":12,"end_col_offset":30,"issue_cwe":{"id":78},"more_info":"https://example.invalid/B602"}]}"#;
        let log = adapt_bandit_json(input).expect("adapted");
        assert_eq!(log.runs[0].results[0].rule_id.as_deref(), Some("B602"));
        assert_eq!(log.runs[0].results[0].level.as_deref(), Some("error"));
    }
}
