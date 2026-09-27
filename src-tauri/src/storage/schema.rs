pub const SCHEMA_VERSION: i64 = 2;

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  is_git INTEGER NOT NULL DEFAULT 0,
  branch TEXT,
  commit_hash TEXT,
  primary_language TEXT NOT NULL DEFAULT 'Other',
  file_count INTEGER NOT NULL DEFAULT 0,
  last_opened_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_last_opened ON projects(last_opened_at DESC);
CREATE TABLE IF NOT EXISTS recent_projects (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  opened_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  git_branch TEXT,
  git_commit TEXT,
  status TEXT NOT NULL,
  finding_count INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER,
  source TEXT NOT NULL DEFAULT 'scan'
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_project_started ON scan_runs(project_id, started_at DESC);
CREATE TABLE IF NOT EXISTS scanner_runs (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  scanner_id TEXT NOT NULL,
  scanner_name TEXT NOT NULL,
  status TEXT NOT NULL,
  version TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER,
  error TEXT,
  logs_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scanner_runs_scan ON scanner_runs(scan_run_id);
CREATE TABLE IF NOT EXISTS scan_artifacts (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  scanner_id TEXT NOT NULL,
  format TEXT NOT NULL,
  raw_sarif TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scanner_id TEXT NOT NULL,
  scanner_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL DEFAULT 1,
  start_column INTEGER NOT NULL DEFAULT 1,
  end_line INTEGER NOT NULL DEFAULT 1,
  end_column INTEGER NOT NULL DEFAULT 1,
  cwe_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  triage_note TEXT,
  native_fingerprint TEXT,
  workspace_fingerprint TEXT NOT NULL,
  location_json TEXT NOT NULL,
  related_locations_json TEXT NOT NULL DEFAULT '[]',
  code_flows_json TEXT NOT NULL DEFAULT '[]',
  fixes_json TEXT NOT NULL DEFAULT '[]',
  taxa_json TEXT NOT NULL DEFAULT '[]',
  raw_sarif_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(workspace_fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner_id);
CREATE TABLE IF NOT EXISTS finding_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  relation TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  end_column INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_fingerprints_value ON finding_fingerprints(value);
CREATE TABLE IF NOT EXISTS finding_triage (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  workspace_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(project_id, workspace_fingerprint)
);
CREATE TABLE IF NOT EXISTS scanner_configs (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scanner_id TEXT NOT NULL,
  executable_path TEXT,
  config_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY(project_id, scanner_id)
);
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scanner_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  name TEXT,
  description TEXT,
  help TEXT,
  help_uri TEXT,
  severity TEXT NOT NULL,
  cwe_json TEXT NOT NULL DEFAULT '[]',
  tags_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(project_id, scanner_id, rule_id)
);
PRAGMA foreign_keys = ON;
"#;
