mod protocol;
pub use protocol::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Sast,
    Secrets,
    Sca,
    Iac,
    Container,
    License,
    Misconfiguration,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    #[default]
    New,
    Existing,
    Fixed,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Ignored,
    Reopened,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    #[default]
    Running,
    Completed,
    Failed,
    Cancelled,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScannerRunStatus {
    Queued,
    #[default]
    Running,
    Completed,
    Failed,
    Cancelled,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    pub path: String,
    pub is_git: bool,
    pub branch: Option<String>,
    pub commit_hash: Option<String>,
    pub primary_language: String,
    pub file_count: u64,
    pub last_opened_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RecentProject {
    pub id: String,
    pub name: String,
    pub path: String,
    pub primary_language: String,
    pub last_opened_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub file_path: String,
    pub absolute_path: Option<String>,
    pub message: Option<String>,
    pub region: Region,
    pub logical_locations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraceStep {
    #[serde(default)]
    pub kind: TraceStepKind,
    pub index: usize,
    pub label: String,
    pub message: Option<String>,
    pub location: Location,
    pub nesting_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ThreadFlow {
    pub id: Option<String>,
    pub message: Option<String>,
    pub steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CodeFlow {
    pub message: Option<String>,
    pub thread_flows: Vec<ThreadFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub description: Option<String>,
    pub replacements: Vec<FixReplacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FixReplacement {
    pub file_path: String,
    pub deleted_region: Region,
    pub inserted_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Taxonomy {
    pub id: String,
    pub name: Option<String>,
    pub short_description: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub uri: String,
    pub file_path: String,
    pub mime_type: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: Option<String>,
    pub scanner_id: String,
    pub description: Option<String>,
    pub help: Option<String>,
    pub help_uri: Option<String>,
    pub severity: Severity,
    pub cwe: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(default)]
    pub provenance: FindingProvenance,
    #[serde(default)]
    pub fingerprints: FindingFingerprints,
    #[serde(default)]
    pub lifecycle: FindingLifecycle,
    #[serde(default)]
    pub raw_reference: Option<RawReference>,
    pub id: String,
    pub scan_run_id: String,
    pub project_id: String,
    pub scanner_id: String,
    pub scanner_name: String,
    pub rule_id: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub location: Location,
    pub related_locations: Vec<Location>,
    pub code_flows: Vec<CodeFlow>,
    pub fixes: Vec<Fix>,
    pub taxa: Vec<Taxonomy>,
    pub cwe: Vec<String>,
    pub status: FindingStatus,
    pub triage_note: Option<String>,
    pub native_fingerprint: Option<String>,
    pub workspace_fingerprint: String,
    pub raw_sarif: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingListItem {
    #[serde(default)]
    pub identity_id: String,
    #[serde(default)]
    pub diff_class: DiffClass,
    pub id: String,
    pub scan_run_id: String,
    pub scanner_id: String,
    pub scanner_name: String,
    pub rule_id: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub file_path: String,
    pub start_line: u32,
    pub cwe: Vec<String>,
    pub status: FindingStatus,
    pub triage_note: Option<String>,
    pub workspace_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingFilters {
    pub project_id: Option<String>,
    pub scan_run_id: Option<String>,
    pub search: Option<String>,
    pub severities: Vec<Severity>,
    pub scanners: Vec<String>,
    pub categories: Vec<FindingCategory>,
    pub statuses: Vec<FindingStatus>,
    pub file_path: Option<String>,
    pub cwe: Option<String>,
    pub rule_id: Option<String>,
    pub diff_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScannerRun {
    pub id: String,
    pub scan_run_id: String,
    pub scanner_id: String,
    pub scanner_name: String,
    pub status: ScannerRunStatus,
    pub version: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub timestamp: String,
    pub stream: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRun {
    #[serde(default = "security_ir_version")]
    pub security_ir_version: u32,
    pub id: String,
    pub project_id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub git_branch: Option<String>,
    pub git_commit: Option<String>,
    pub status: ScanStatus,
    pub scanners: Vec<ScannerRun>,
    pub finding_count: usize,
    pub duration_ms: Option<u64>,
    pub source: String,
}

impl Default for ScanRun {
    fn default() -> Self {
        Self {
            security_ir_version: SECURITY_IR_VERSION,
            id: String::new(),
            project_id: String::new(),
            started_at: String::new(),
            finished_at: None,
            git_branch: None,
            git_commit: None,
            status: ScanStatus::default(),
            scanners: Vec::new(),
            finding_count: 0,
            duration_ms: None,
            source: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScannerCapabilities {
    pub sast: bool,
    pub secrets: bool,
    pub sca: bool,
    pub iac: bool,
    pub container: bool,
    pub licenses: bool,
    pub vulnerabilities: bool,
    pub misconfiguration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScannerInstallation {
    pub config_fields: Vec<ScannerConfigField>,
    pub id: String,
    pub display_name: String,
    pub installed: bool,
    pub executable: Option<String>,
    pub version: Option<String>,
    pub capabilities: ScannerCapabilities,
    pub license: String,
    pub project_url: String,
    pub install_command: String,
    pub description: String,
    pub configured_path: Option<String>,
    pub detection_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScannerConfig {
    pub scanner_id: String,
    pub executable_path: Option<String>,
    pub config: serde_json::Value,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub project_id: String,
    pub scanner_ids: Vec<String>,
    pub workspace_root: String,
    pub mode: String,
    pub scanner_configs: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub changed_files: Vec<String>,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            scanner_ids: Vec::new(),
            workspace_root: String::new(),
            mode: "full".into(),
            scanner_configs: Default::default(),
            changed_files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    pub changed: Vec<FindingListItem>,
    pub reopened: Vec<FindingListItem>,
    pub changed_count: usize,
    pub reopened_count: usize,
    pub offset: usize,
    pub limit: usize,
    pub current_run_id: String,
    pub previous_run_id: String,
    pub new: Vec<FindingListItem>,
    pub fixed: Vec<FindingListItem>,
    pub existing: Vec<FindingListItem>,
    pub new_count: usize,
    pub fixed_count: usize,
    pub existing_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSummary {
    pub project: Project,
    pub last_scan: Option<ScanRun>,
    pub total_findings: usize,
    pub new_findings: usize,
    pub existing_findings: usize,
    pub fixed_findings: usize,
    pub severity: SeverityCounts,
    pub categories: std::collections::HashMap<String, usize>,
    pub scanner_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceFile {
    pub path: String,
    pub absolute_path: String,
    pub language: String,
    pub content: String,
    pub size: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TriageUpdate {
    pub finding_id: String,
    pub status: FindingStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppSetting {
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionManifest {
    pub scan: ExtensionScan,
    pub permissions: ExtensionPermissions,
    pub approval_digest: String,
    pub resolved_executable: Option<String>,
    pub runnable: bool,
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub scanner: ExtensionScanner,
    pub output: ExtensionOutput,
    pub capabilities: ScannerCapabilities,
    pub license: ExtensionLicense,
    pub trusted: bool,
    pub source_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionScanner {
    pub executable: String,
    pub version_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionOutput {
    pub format: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionLicense {
    pub spdx: String,
    pub bundled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ComponentInfo {
    pub name: String,
    pub version: String,
    pub license: String,
    pub purpose: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub scan_run: ScanRun,
    pub imported_findings: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressEvent {
    pub project_id: String,
    pub scan_run_id: String,
    pub scanner_id: String,
    pub scanner_name: String,
    pub status: ScannerRunStatus,
    pub message: String,
    pub elapsed_ms: u64,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionScan {
    pub args: Vec<String>,
    pub timeout_seconds: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionPermissions {
    pub workspace_read: bool,
    pub workspace_write: bool,
    pub network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerConfigField {
    pub key: String,
    pub label: String,
    pub kind: String,
    pub default_value: serde_json::Value,
    pub options: Vec<String>,
    pub help: Option<String>,
}
