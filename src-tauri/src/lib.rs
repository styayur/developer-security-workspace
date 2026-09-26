#![cfg_attr(
    not(feature = "desktop"),
    allow(dead_code, unused_imports, unexpected_cfgs)
)]

#[cfg(feature = "desktop")]
mod commands;
mod error;
mod extensions;
mod fingerprint;
mod licenses;
mod process;
mod sarif;
mod scanners;
mod secret_redaction;
mod security_ir;
#[cfg(feature = "desktop")]
mod state;
mod storage;
mod workspace;

#[cfg(feature = "desktop")]
use state::AppState;
#[cfg(feature = "desktop")]
use tauri::Manager;

#[cfg_attr(all(feature = "desktop", mobile), tauri::mobile_entry_point)]
#[cfg(feature = "desktop")]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "developer_security_workspace_lib=info".into()),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let state = AppState::initialize(app.handle())?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::project::open_project,
            commands::project::get_project,
            commands::project::recent_projects,
            commands::project::read_source,
            commands::findings::list_findings,
            commands::findings::get_finding,
            commands::findings::update_triage,
            commands::findings::dashboard,
            commands::findings::list_rules,
            commands::findings::list_scan_runs,
            commands::findings::get_scan_run,
            commands::findings::scan_diff,
            commands::sarif::import_sarif,
            commands::sarif::open_demo_workspace,
            commands::sarif::export_sarif,
            commands::sarif::full_sarif,
            commands::scanners::list_scanners,
            commands::scanners::configure_scanner,
            commands::scanners::clear_scanner_config,
            commands::scans::start_scan,
            commands::scans::cancel_scan,
            commands::settings::get_setting,
            commands::settings::set_setting,
            commands::system::list_components,
            commands::system::list_extensions,
            commands::system::verify_codeql
        ])
        .run(tauri::generate_context!())
        .expect("error while running Developer Security Workspace");
}

#[cfg(not(feature = "desktop"))]
pub fn run() {}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::security_ir::{FindingFilters, Project, ScanStatus};
    use chrono::Utc;
    use std::path::Path;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "requires locally installed Semgrep, Trivy, TruffleHog, and Bandit"]
    async fn installed_scanners_execute_through_providers() {
        use crate::scanners::{ScanContext, ScannerRegistry};
        use crate::security_ir::{ScanRequest, ScannerRunStatus};
        use std::collections::HashMap;

        let workspace = std::fs::canonicalize(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/scanner-smoke"),
        )
        .expect("scanner smoke workspace");
        let semgrep_rule = workspace.join("rules/semgrep.yml");
        let registry = ScannerRegistry::new();
        let context = ScanContext::default();
        let mut expected = HashMap::new();
        expected.insert("semgrep", 1usize);
        expected.insert("trivy", 1usize);
        expected.insert("trufflehog", 2usize);
        expected.insert("bandit", 1usize);

        let mut temporary_workspaces = Vec::<tempfile::TempDir>::new();
        for (scanner_id, minimum_findings) in expected {
            let scan_workspace = if scanner_id == "trufflehog" {
                let temp = tempfile::tempdir().expect("trufflehog temp workspace");
                let github = ["ghp", "_", "1234567890abcdefghijklmnopqrstuvwxyz"].concat();
                let slack = [
                    "xoxb",
                    "-",
                    "123456789012-123456789012-abcdefghijklmnopqrstuvwx",
                ]
                .concat();
                std::fs::write(
                    temp.path().join("synthetic-secrets.txt"),
                    format!("github_token={github}\nslack_token={slack}\n"),
                )
                .expect("write synthetic secrets");
                trufflehog_temp = Some(temp);
                trufflehog_temp
                    .as_ref()
                    .expect("temp dir")
                    .path()
                    .to_path_buf()
            } else {
                workspace.clone()
            };
            let mut scanner_configs = HashMap::new();
            match scanner_id {
                "semgrep" => {
                    scanner_configs.insert(
                        scanner_id.to_string(),
                        serde_json::json!({ "config": semgrep_rule }),
                    );
                }
                "trivy" => {
                    scanner_configs.insert(
                        scanner_id.to_string(),
                        serde_json::json!({
                            "scanners": ["vuln", "misconfig", "secret", "license"],
                            "skipDbUpdate": true
                        }),
                    );
                }
                "trufflehog" => {
                    scanner_configs.insert(
                        scanner_id.to_string(),
                        serde_json::json!({ "verifiedOnly": false }),
                    );
                }
                "bandit" => {
                    scanner_configs.insert(scanner_id.to_string(), serde_json::json!({}));
                }
                _ => unreachable!(),
            }
            let request = ScanRequest {
                project_id: "scanner-smoke".into(),
                scanner_ids: vec![scanner_id.into()],
                workspace_root: scan_workspace.to_string_lossy().to_string(),
                mode: "full".into(),
                scanner_configs,
                changed_files: Vec::new(),
            };
            let provider = registry.get(scanner_id).expect("provider");
            let installation = provider.detect(None).await;
            assert!(
                installation.installed,
                "{scanner_id} must be installed for this ignored test: {:?}",
                installation.detection_error
            );
            let logs = provider
                .scan(&request, &context)
                .await
                .unwrap_or_else(|error| panic!("{scanner_id} provider scan failed: {error}"));
            let findings = logs
                .iter()
                .flat_map(|log| {
                    crate::sarif::normalize_log(log, &scan_workspace, "scanner-smoke", "run")
                        .expect("normalized provider output")
                })
                .collect::<Vec<_>>();
            assert!(
                findings.len() >= minimum_findings,
                "{scanner_id} returned {} findings",
                findings.len()
            );
            if scanner_id == "trufflehog" {
                let rendered = serde_json::to_string(&findings).expect("serialize findings");
                assert!(!rendered.contains("\"Raw\""));
                assert!(!rendered.contains("\"RawV2\""));
                assert!(!rendered.contains("\"SecretParts\""));
            }
            println!(
                "{scanner_id}: status={:?} findings={}",
                ScannerRunStatus::Completed,
                findings.len()
            );
        }
    }

    #[test]
    fn sarif_fixture_pipeline_persists_through_security_ir() {
        let directory = tempfile::tempdir().expect("temp dir");
        let project = Project {
            id: Uuid::new_v4().to_string(),
            name: "fixture-pipeline".into(),
            path: directory.path().to_string_lossy().to_string(),
            primary_language: "TypeScript".into(),
            last_opened_at: Utc::now().to_rfc3339(),
            created_at: Utc::now().to_rfc3339(),
            ..Default::default()
        };
        let database = storage::Database::new(&directory.path().join("app.db")).expect("database");
        let project = database.open_project(&project).expect("project");
        let run = database
            .create_scan_run(&project.id, "integration_test")
            .expect("run");
        let fixture = include_str!("../../fixtures/sarif/codeflow-example.sarif");
        let log = sarif::parse_sarif(fixture).expect("parse");
        let findings = sarif::normalize_log(&log, Path::new(&project.path), &project.id, &run.id)
            .expect("normalize");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code_flows[0].thread_flows[0].steps.len(), 3);
        database
            .insert_findings(&findings)
            .expect("persist findings");
        let completed = database
            .finish_scan_run(&run.id, ScanStatus::Completed)
            .expect("finish");
        assert_eq!(completed.finding_count, 1);
        let listed = database
            .list_findings(&FindingFilters {
                project_id: Some(project.id.clone()),
                ..Default::default()
            })
            .expect("list");
        assert_eq!(listed.len(), 1);
        let detail = database.get_finding(&listed[0].id).expect("detail");
        assert_eq!(detail.cwe, vec!["CWE-89"]);
        assert_eq!(detail.location.region.start_line, 8);
    }
}
