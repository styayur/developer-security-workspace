use super::{
    config_string, config_strings, locate_executable, scan_targets, scanner_config,
    validate_extra_args, ScanContext, ScannerProvider,
};
use crate::error::{AppError, AppResult};
use crate::process::run_command_data;
use crate::sarif::model::{
    SarifArtifactLocation, SarifLocation, SarifLog, SarifMessage, SarifPhysicalLocation,
    SarifRegion, SarifReportingDescriptor, SarifResult, SarifRun, SarifTool, SarifToolComponent,
};
use crate::security_ir::{ScanRequest, ScannerCapabilities};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;

pub struct TruffleHogProvider;

#[async_trait]
impl ScannerProvider for TruffleHogProvider {
    fn id(&self) -> &str {
        "trufflehog"
    }
    fn display_name(&self) -> &str {
        "TruffleHog"
    }
    fn config_fields(&self) -> Vec<crate::security_ir::ScannerConfigField> {
        vec![crate::security_ir::ScannerConfigField { key:"verifiedOnly".into(),label:"Only show verified credentials".into(),kind:"boolean".into(),default_value:serde_json::json!(false),options:vec![],help:Some("Raw candidates are removed by the adapter. Verification may contact the credential issuer.".into()) }]
    }
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            secrets: true,
            ..Default::default()
        }
    }
    fn license(&self) -> &'static str {
        "AGPL-3.0-only"
    }
    fn project_url(&self) -> &'static str {
        "https://github.com/trufflesecurity/trufflehog"
    }
    fn install_command(&self) -> &'static str {
        "winget install TruffleSecurity.TruffleHog"
    }
    fn description(&self) -> &'static str {
        "Verified and unverified filesystem secret detection"
    }
    fn known_commands(&self) -> &'static [&'static str] {
        &["trufflehog", "trufflehog.exe"]
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
        let mut args = vec![
            "filesystem".into(),
            "--json".into(),
            "--no-update".into(),
            "--results=verified,unverified,unknown,filtered_unverified".into(),
        ];
        if config
            .get("verifiedOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            args.push("--only-verified".into());
        }
        if config
            .get("noVerification")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            args.push("--no-verification".into());
        }
        args.extend(extra);
        args.extend(scan_targets(request)?);
        context.log("info", format!("Launching {}", executable.display()));
        let output = run_command_data(
            &executable,
            &args,
            Path::new(&request.workspace_root),
            context.cancel.clone(),
            context.logs.clone(),
        )
        .await?;
        if !output.success && output.stdout.trim().is_empty() {
            return Err(AppError::Scanner(format!(
                "TruffleHog failed (exit {:?}). {}",
                output.status_code,
                output.stderr.trim()
            )));
        }
        Ok(vec![adapt_trufflehog_json(&output.stdout)?])
    }
}

pub fn adapt_trufflehog_json(input: &str) -> AppResult<SarifLog> {
    let mut results = Vec::new();
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|error| {
            AppError::Scanner(format!(
                "TruffleHog JSON line {} is invalid: {error}",
                line_index + 1
            ))
        })?;
        let detector = value
            .get("DetectorName")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        let verified = value
            .get("Verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let redacted = value
            .get("Redacted")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let file = nested_str(&value, &["SourceMetadata", "Data", "Filesystem", "file"])
            .or_else(|| nested_str(&value, &["SourceMetadata", "Data", "Git", "file"]))
            .unwrap_or("unknown");
        let line_number = nested_u32(&value, &["SourceMetadata", "Data", "Filesystem", "line"])
            .or_else(|| nested_u32(&value, &["SourceMetadata", "Data", "Git", "line"]))
            .unwrap_or(1);
        let rule_id = format!("trufflehog.{}", slug(detector));
        if seen.insert(rule_id.clone()) {
            rules.push(SarifReportingDescriptor {
                id: rule_id.clone(),
                name: Some(detector.into()),
                short_description: Some(SarifMessage {
                    text: Some(format!("{detector} credential detected")),
                    ..Default::default()
                }),
                properties: json!({"tags": ["secret"], "detector": detector}),
                ..Default::default()
            });
        }
        let properties = json!({
            "detector": detector,
            "verified": verified,
            "redacted": redacted,
            "source": "TruffleHog JSON compatibility adapter"
        });
        results.push(SarifResult {
            rule_id: Some(rule_id),
            level: Some(if verified { "error" } else { "warning" }.into()),
            message: SarifMessage {
                text: Some(format!("{} credential detected", detector)),
                ..Default::default()
            },
            locations: vec![SarifLocation {
                physical_location: Some(SarifPhysicalLocation {
                    artifact_location: Some(SarifArtifactLocation {
                        uri: Some(file.replace('\\', "/")),
                        ..Default::default()
                    }),
                    region: Some(SarifRegion {
                        start_line: Some(line_number),
                        start_column: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            properties,
            ..Default::default()
        });
    }
    Ok(SarifLog {
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "TruffleHog".into(),
                    version: None,
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

fn nested_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))?
        .as_str()
}

fn nested_u32(value: &Value, path: &[&str]) -> Option<u32> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))?
        .as_u64()
        .map(|value| value as u32)
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapts_and_redacts_trufflehog_json() {
        let input = r#"{"DetectorName":"AWS","Verified":true,"Raw":"EXAMPLE_NOT_A_REAL_SECRET","Redacted":"AKIA••••","SourceMetadata":{"Data":{"Filesystem":{"file":"src/.env","line":4}}}}"#;
        let log = adapt_trufflehog_json(input).expect("adapted");
        assert_eq!(log.runs[0].results.len(), 1);
        assert!(!log.runs[0].results[0]
            .properties
            .to_string()
            .contains("EXAMPLE_NOT_A_REAL_SECRET"));
        assert_eq!(
            log.runs[0].results[0].locations[0]
                .physical_location
                .as_ref()
                .unwrap()
                .region
                .as_ref()
                .unwrap()
                .start_line,
            Some(4)
        );
    }
}
