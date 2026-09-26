mod schema;

use crate::error::{AppError, AppResult};
use crate::security_ir::*;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

pub struct Database {
    connection: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(schema::SCHEMA_SQL)?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![schema::SCHEMA_VERSION, Utc::now().to_rfc3339()],
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open_project(&self, project: &Project) -> AppResult<Project> {
        let connection = self.lock()?;
        let existing = connection
            .query_row(
                "SELECT id, created_at FROM projects WHERE path = ?1",
                params![project.path],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (id, created_at) =
            existing.unwrap_or_else(|| (project.id.clone(), project.created_at.clone()));
        connection.execute(
            r#"INSERT INTO projects(id, name, path, is_git, branch, commit_hash, primary_language, file_count, last_opened_at, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
               ON CONFLICT(path) DO UPDATE SET
                 name=excluded.name, is_git=excluded.is_git, branch=excluded.branch,
                 commit_hash=excluded.commit_hash, primary_language=excluded.primary_language,
                 file_count=excluded.file_count, last_opened_at=excluded.last_opened_at"#,
            params![
                id,
                project.name,
                project.path,
                project.is_git as i64,
                project.branch,
                project.commit_hash,
                project.primary_language,
                project.file_count as i64,
                project.last_opened_at,
                created_at
            ],
        )?;
        connection.execute(
            "INSERT INTO recent_projects(project_id, opened_at) VALUES (?1, ?2) ON CONFLICT(project_id) DO UPDATE SET opened_at=excluded.opened_at",
            params![id, Utc::now().to_rfc3339()],
        )?;
        Ok(Project {
            id,
            created_at,
            ..project.clone()
        })
    }

    pub fn get_project(&self, project_id: &str) -> AppResult<Project> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT id,name,path,is_git,branch,commit_hash,primary_language,file_count,last_opened_at,created_at FROM projects WHERE id=?1",
                params![project_id],
                project_from_row,
            )
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("Project {project_id}")))
    }

    pub fn recent_projects(&self, limit: usize) -> AppResult<Vec<RecentProject>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT p.id,p.name,p.path,p.primary_language,p.last_opened_at
               FROM recent_projects r JOIN projects p ON p.id=r.project_id
               ORDER BY r.opened_at DESC LIMIT ?1"#,
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            Ok(RecentProject {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                primary_language: row.get(3)?,
                last_opened_at: row.get(4)?,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn create_scan_run(&self, project_id: &str, source: &str) -> AppResult<ScanRun> {
        let project = self.get_project(project_id)?;
        let run = ScanRun {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.to_string(),
            started_at: Utc::now().to_rfc3339(),
            finished_at: None,
            git_branch: project.branch,
            git_commit: project.commit_hash,
            status: ScanStatus::Running,
            scanners: Vec::new(),
            finding_count: 0,
            duration_ms: None,
            source: source.to_string(),
        };
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO scan_runs(id,project_id,started_at,finished_at,git_branch,git_commit,status,finding_count,duration_ms,source) VALUES (?1,?2,?3,NULL,?4,?5,?6,0,NULL,?7)",
            params![run.id, run.project_id, run.started_at, run.git_branch, run.git_commit, enum_string(&run.status)?, source],
        )?;
        Ok(run)
    }

    pub fn upsert_scanner_run(&self, scanner_run: &ScannerRun) -> AppResult<()> {
        let logs = serde_json::to_string(&scanner_run.logs)?;
        let connection = self.lock()?;
        connection.execute(
            r#"INSERT INTO scanner_runs(id,scan_run_id,scanner_id,scanner_name,status,version,started_at,finished_at,duration_ms,error,logs_json)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
               ON CONFLICT(id) DO UPDATE SET status=excluded.status,version=excluded.version,finished_at=excluded.finished_at,
                 duration_ms=excluded.duration_ms,error=excluded.error,logs_json=excluded.logs_json"#,
            params![
                scanner_run.id,
                scanner_run.scan_run_id,
                scanner_run.scanner_id,
                scanner_run.scanner_name,
                enum_string(&scanner_run.status)?,
                scanner_run.version,
                scanner_run.started_at,
                scanner_run.finished_at,
                scanner_run.duration_ms.map(|value| value as i64),
                scanner_run.error,
                logs
            ],
        )?;
        Ok(())
    }

    pub fn finish_scan_run(&self, scan_run_id: &str, status: ScanStatus) -> AppResult<ScanRun> {
        let started = {
            let connection = self.lock()?;
            connection
                .query_row(
                    "SELECT started_at FROM scan_runs WHERE id=?1",
                    params![scan_run_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("Scan run {scan_run_id}")))?
        };
        let finished = Utc::now();
        let duration = chrono::DateTime::parse_from_rfc3339(&started)
            .ok()
            .map(|value| {
                (finished - value.with_timezone(&Utc))
                    .num_milliseconds()
                    .max(0) as u64
            });
        let count = self
            .list_findings(&FindingFilters {
                scan_run_id: Some(scan_run_id.to_string()),
                ..Default::default()
            })?
            .len();
        {
            let connection = self.lock()?;
            connection.execute(
                "UPDATE scan_runs SET finished_at=?1,status=?2,finding_count=?3,duration_ms=?4 WHERE id=?5",
                params![finished.to_rfc3339(), enum_string(&status)?, count as i64, duration.map(|value| value as i64), scan_run_id],
            )?;
        }
        self.get_scan_run(scan_run_id)
    }

    pub fn get_scan_run(&self, scan_run_id: &str) -> AppResult<ScanRun> {
        let mut run = {
            let connection = self.lock()?;
            connection
                .query_row(
                    "SELECT id,project_id,started_at,finished_at,git_branch,git_commit,status,finding_count,duration_ms,source FROM scan_runs WHERE id=?1",
                    params![scan_run_id],
                    scan_run_from_row,
                )
                .optional()?
                .ok_or_else(|| AppError::NotFound(format!("Scan run {scan_run_id}")))?
        };
        run.scanners = self.scanner_runs(scan_run_id)?;
        Ok(run)
    }

    pub fn list_scan_runs(&self, project_id: &str, limit: usize) -> AppResult<Vec<ScanRun>> {
        let mut runs = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT id,project_id,started_at,finished_at,git_branch,git_commit,status,finding_count,duration_ms,source FROM scan_runs WHERE project_id=?1 ORDER BY started_at DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![project_id, limit as i64], scan_run_from_row)?;
            rows.filter_map(Result::ok).collect::<Vec<_>>()
        };
        for run in &mut runs {
            run.scanners = self.scanner_runs(&run.id)?;
        }
        Ok(runs)
    }

    pub fn latest_scan_run(&self, project_id: &str) -> AppResult<Option<ScanRun>> {
        let id = {
            let connection = self.lock()?;
            connection
                .query_row(
                    "SELECT id FROM scan_runs WHERE project_id=?1 ORDER BY started_at DESC LIMIT 1",
                    params![project_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
        };
        id.map(|value| self.get_scan_run(&value)).transpose()
    }

    pub fn previous_scan_run(
        &self,
        project_id: &str,
        current_run_id: &str,
    ) -> AppResult<Option<ScanRun>> {
        let current_started = self.get_scan_run(current_run_id)?.started_at;
        let id = {
            let connection = self.lock()?;
            connection
                .query_row(
                    "SELECT id FROM scan_runs WHERE project_id=?1 AND started_at < ?2 ORDER BY started_at DESC LIMIT 1",
                    params![project_id, current_started],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
        };
        id.map(|value| self.get_scan_run(&value)).transpose()
    }

    pub fn insert_findings(&self, findings: &[Finding]) -> AppResult<usize> {
        if findings.is_empty() {
            return Ok(0);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for original in findings {
            let mut finding = original.clone();
            let triage = transaction
                .query_row(
                    "SELECT status,note FROM finding_triage WHERE project_id=?1 AND workspace_fingerprint=?2",
                    params![finding.project_id, finding.workspace_fingerprint],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            if let Some((status, note)) = triage {
                finding.status = parse_enum(&status);
                finding.triage_note = note;
            } else {
                let previous_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM findings WHERE project_id=?1 AND workspace_fingerprint=?2 AND scan_run_id<>?3",
                    params![finding.project_id, finding.workspace_fingerprint, finding.scan_run_id],
                    |row| row.get(0),
                )?;
                finding.status = if previous_count > 0 {
                    FindingStatus::Existing
                } else {
                    FindingStatus::New
                };
            }
            transaction.execute(
                r#"INSERT OR REPLACE INTO findings(
                    id,scan_run_id,project_id,scanner_id,scanner_name,rule_id,title,message,severity,category,
                    file_path,start_line,start_column,end_line,end_column,cwe_json,status,triage_note,
                    native_fingerprint,workspace_fingerprint,location_json,related_locations_json,code_flows_json,
                    fixes_json,taxa_json,raw_sarif_json
                  ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)"#,
                params![
                    finding.id, finding.scan_run_id, finding.project_id, finding.scanner_id,
                    finding.scanner_name, finding.rule_id, finding.title, finding.message,
                    enum_string(&finding.severity)?, enum_string(&finding.category)?,
                    finding.location.file_path, finding.location.region.start_line as i64,
                    finding.location.region.start_column as i64, finding.location.region.end_line as i64,
                    finding.location.region.end_column as i64, serde_json::to_string(&finding.cwe)?,
                    enum_string(&finding.status)?, finding.triage_note, finding.native_fingerprint,
                    finding.workspace_fingerprint, serde_json::to_string(&finding.location)?,
                    serde_json::to_string(&finding.related_locations)?, serde_json::to_string(&finding.code_flows)?,
                    serde_json::to_string(&finding.fixes)?, serde_json::to_string(&finding.taxa)?,
                    serde_json::to_string(&finding.raw_sarif)?
                ],
            )?;
            for location in
                std::iter::once(&finding.location).chain(finding.related_locations.iter())
            {
                transaction.execute(
                    "INSERT INTO finding_locations(finding_id,relation,file_path,start_line,start_column,end_line,end_column) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![finding.id, "related", location.file_path, location.region.start_line as i64, location.region.start_column as i64, location.region.end_line as i64, location.region.end_column as i64],
                )?;
            }
            if let Some(native) = &finding.native_fingerprint {
                transaction.execute(
                    "INSERT INTO finding_fingerprints(finding_id,kind,value) VALUES (?1,'native',?2)",
                    params![finding.id, native],
                )?;
            }
            transaction.execute(
                "INSERT INTO finding_fingerprints(finding_id,kind,value) VALUES (?1,'workspace',?2)",
                params![finding.id, finding.workspace_fingerprint],
            )?;
            transaction.execute(
                r#"INSERT INTO rules(project_id,scanner_id,rule_id,name,description,help,help_uri,severity,cwe_json,tags_json)
                   VALUES (?1,?2,?3,?4,NULL,NULL,NULL,?5,?6,'[]')
                   ON CONFLICT(project_id,scanner_id,rule_id) DO UPDATE SET severity=excluded.severity,cwe_json=excluded.cwe_json"#,
                params![finding.project_id, finding.scanner_id, finding.rule_id, finding.title, enum_string(&finding.severity)?, serde_json::to_string(&finding.cwe)?],
            )?;
        }
        transaction.commit()?;
        Ok(findings.len())
    }

    pub fn list_findings(&self, filters: &FindingFilters) -> AppResult<Vec<FindingListItem>> {
        let rows = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                r#"SELECT id,scan_run_id,scanner_id,scanner_name,rule_id,title,message,severity,category,
                          file_path,start_line,cwe_json,status,triage_note,workspace_fingerprint
                   FROM findings
                   WHERE (?1 IS NULL OR project_id=?1) AND (?2 IS NULL OR scan_run_id=?2)
                   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, file_path, start_line"#,
            )?;
            let mapped = statement.query_map(
                params![filters.project_id, filters.scan_run_id],
                finding_list_from_row,
            )?;
            mapped.filter_map(Result::ok).collect::<Vec<_>>()
        };
        let search = filters
            .search
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        Ok(rows
            .into_iter()
            .filter(|item| {
                filters.severities.is_empty() || filters.severities.contains(&item.severity)
            })
            .filter(|item| {
                filters.scanners.is_empty() || filters.scanners.contains(&item.scanner_id)
            })
            .filter(|item| {
                filters.categories.is_empty() || filters.categories.contains(&item.category)
            })
            .filter(|item| filters.statuses.is_empty() || filters.statuses.contains(&item.status))
            .filter(|item| {
                filters
                    .cwe
                    .as_ref()
                    .is_none_or(|cwe| item.cwe.iter().any(|value| value.eq_ignore_ascii_case(cwe)))
            })
            .filter(|item| {
                filters
                    .rule_id
                    .as_ref()
                    .is_none_or(|rule| item.rule_id.eq_ignore_ascii_case(rule))
            })
            .filter(|item| {
                filters.file_path.as_ref().is_none_or(|path| {
                    item.file_path
                        .to_ascii_lowercase()
                        .contains(&path.to_ascii_lowercase())
                })
            })
            .filter(|item| {
                search.as_ref().is_none_or(|query| {
                    item.title.to_ascii_lowercase().contains(query)
                        || item.message.to_ascii_lowercase().contains(query)
                        || item.rule_id.to_ascii_lowercase().contains(query)
                        || item.file_path.to_ascii_lowercase().contains(query)
                        || item.scanner_name.to_ascii_lowercase().contains(query)
                        || item
                            .cwe
                            .iter()
                            .any(|cwe| cwe.to_ascii_lowercase().contains(query))
                })
            })
            .collect())
    }

    pub fn get_finding(&self, finding_id: &str) -> AppResult<Finding> {
        let connection = self.lock()?;
        connection
            .query_row(
                r#"SELECT id,scan_run_id,project_id,scanner_id,scanner_name,rule_id,title,message,severity,category,
                          status,triage_note,native_fingerprint,workspace_fingerprint,location_json,related_locations_json,
                          code_flows_json,fixes_json,taxa_json,raw_sarif_json,cwe_json
                   FROM findings WHERE id=?1"#,
                params![finding_id],
                finding_from_row,
            )
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("Finding {finding_id}")))
    }

    pub fn update_triage(
        &self,
        finding_id: &str,
        status: FindingStatus,
        note: Option<String>,
    ) -> AppResult<Finding> {
        let finding = self.get_finding(finding_id)?;
        let now = Utc::now().to_rfc3339();
        let connection = self.lock()?;
        connection.execute(
            r#"INSERT INTO finding_triage(project_id,workspace_fingerprint,status,note,updated_at)
               VALUES (?1,?2,?3,?4,?5)
               ON CONFLICT(project_id,workspace_fingerprint) DO UPDATE SET status=excluded.status,note=excluded.note,updated_at=excluded.updated_at"#,
            params![finding.project_id, finding.workspace_fingerprint, enum_string(&status)?, note, now],
        )?;
        connection.execute(
            "UPDATE findings SET status=?1,triage_note=?2 WHERE workspace_fingerprint=?3 AND project_id=?4",
            params![enum_string(&status)?, note, finding.workspace_fingerprint, finding.project_id],
        )?;
        drop(connection);
        self.get_finding(finding_id)
    }

    pub fn dashboard(&self, project_id: &str) -> AppResult<DashboardSummary> {
        let project = self.get_project(project_id)?;
        let last_scan = self.latest_scan_run(project_id)?;
        let findings = if let Some(run) = &last_scan {
            self.list_findings(&FindingFilters {
                project_id: Some(project_id.to_string()),
                scan_run_id: Some(run.id.clone()),
                ..Default::default()
            })?
        } else {
            Vec::new()
        };
        let fixed = if let Some(run) = &last_scan {
            self.scan_diff(project_id, &run.id, None)?
                .map(|diff| diff.fixed_count)
                .unwrap_or(0)
        } else {
            0
        };
        let mut severity = SeverityCounts::default();
        let mut categories = HashMap::new();
        let mut scanners = HashSet::new();
        for finding in &findings {
            match finding.severity {
                Severity::Critical => severity.critical += 1,
                Severity::High => severity.high += 1,
                Severity::Medium => severity.medium += 1,
                Severity::Low => severity.low += 1,
                Severity::Info => severity.info += 1,
            }
            *categories
                .entry(format!("{:?}", finding.category).to_ascii_lowercase())
                .or_insert(0) += 1;
            scanners.insert(finding.scanner_id.clone());
        }
        Ok(DashboardSummary {
            project,
            last_scan,
            total_findings: findings.len(),
            new_findings: findings
                .iter()
                .filter(|item| item.status == FindingStatus::New)
                .count(),
            existing_findings: findings
                .iter()
                .filter(|item| item.status == FindingStatus::Existing)
                .count(),
            fixed_findings: fixed,
            severity,
            categories,
            scanner_count: scanners.len(),
        })
    }

    pub fn scan_diff(
        &self,
        project_id: &str,
        current_run_id: &str,
        previous_run_id: Option<&str>,
    ) -> AppResult<Option<ScanDiff>> {
        let previous = if let Some(id) = previous_run_id {
            Some(self.get_scan_run(id)?)
        } else {
            self.previous_scan_run(project_id, current_run_id)?
        };
        let Some(previous) = previous else {
            return Ok(None);
        };
        let current = self.list_findings(&FindingFilters {
            project_id: Some(project_id.to_string()),
            scan_run_id: Some(current_run_id.to_string()),
            ..Default::default()
        })?;
        let previous_items = self.list_findings(&FindingFilters {
            project_id: Some(project_id.to_string()),
            scan_run_id: Some(previous.id.clone()),
            ..Default::default()
        })?;
        let previous_by_fingerprint = previous_items
            .iter()
            .map(|item| (&item.workspace_fingerprint, item))
            .collect::<HashMap<_, _>>();
        let current_by_fingerprint = current
            .iter()
            .map(|item| (&item.workspace_fingerprint, item))
            .collect::<HashMap<_, _>>();
        let new = current
            .iter()
            .filter(|item| !previous_by_fingerprint.contains_key(&item.workspace_fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        let fixed = previous_items
            .iter()
            .filter(|item| !current_by_fingerprint.contains_key(&item.workspace_fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        let existing = current
            .iter()
            .filter(|item| previous_by_fingerprint.contains_key(&item.workspace_fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        Ok(Some(ScanDiff {
            current_run_id: current_run_id.to_string(),
            previous_run_id: previous.id,
            new_count: new.len(),
            fixed_count: fixed.len(),
            existing_count: existing.len(),
            new,
            fixed,
            existing,
        }))
    }

    pub fn list_rules(&self, project_id: &str) -> AppResult<Vec<Rule>> {
        let findings = self.list_findings(&FindingFilters {
            project_id: Some(project_id.to_string()),
            ..Default::default()
        })?;
        let mut rules = HashMap::new();
        for finding in findings {
            rules
                .entry((finding.scanner_id.clone(), finding.rule_id.clone()))
                .or_insert_with(|| Rule {
                    id: finding.rule_id,
                    name: Some(finding.title),
                    scanner_id: finding.scanner_id,
                    description: None,
                    help: None,
                    help_uri: None,
                    severity: finding.severity,
                    cwe: finding.cwe,
                    tags: Vec::new(),
                });
        }
        let mut values = rules.into_values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(values)
    }

    pub fn get_setting(&self, key: &str) -> AppResult<Option<serde_json::Value>> {
        let connection = self.lock()?;
        let value = connection
            .query_row(
                "SELECT value_json FROM app_settings WHERE key=?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> AppResult<()> {
        let connection = self.lock()?;
        connection.execute(
            r#"INSERT INTO app_settings(key,value_json,updated_at) VALUES (?1,?2,?3)
               ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at"#,
            params![key, serde_json::to_string(value)?, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn set_scanner_config(
        &self,
        project_id: &str,
        scanner_id: &str,
        path: Option<&str>,
        config: &serde_json::Value,
    ) -> AppResult<ScannerConfig> {
        let now = Utc::now().to_rfc3339();
        let connection = self.lock()?;
        connection.execute(
            r#"INSERT INTO scanner_configs(project_id,scanner_id,executable_path,config_json,updated_at) VALUES (?1,?2,?3,?4,?5)
               ON CONFLICT(project_id,scanner_id) DO UPDATE SET executable_path=excluded.executable_path,config_json=excluded.config_json,updated_at=excluded.updated_at"#,
            params![project_id, scanner_id, path, serde_json::to_string(config)?, now],
        )?;
        Ok(ScannerConfig {
            scanner_id: scanner_id.to_string(),
            executable_path: path.map(ToOwned::to_owned),
            config: config.clone(),
            updated_at: now,
        })
    }

    pub fn get_scanner_config(
        &self,
        project_id: &str,
        scanner_id: &str,
    ) -> AppResult<Option<ScannerConfig>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT scanner_id,executable_path,config_json,updated_at FROM scanner_configs WHERE project_id=?1 AND scanner_id=?2",
                params![project_id, scanner_id],
                |row| {
                    let config: String = row.get(2)?;
                    Ok(ScannerConfig {
                        scanner_id: row.get(0)?,
                        executable_path: row.get(1)?,
                        config: serde_json::from_str(&config).unwrap_or(serde_json::json!({})),
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(AppError::from)
    }

    pub fn insert_scan_artifact(
        &self,
        scan_run_id: &str,
        scanner_id: &str,
        format: &str,
        raw_sarif: &str,
    ) -> AppResult<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO scan_artifacts(id,scan_run_id,scanner_id,format,raw_sarif,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![Uuid::new_v4().to_string(), scan_run_id, scanner_id, format, raw_sarif, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn scan_artifacts(&self, scan_run_id: &str) -> AppResult<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT raw_sarif FROM scan_artifacts WHERE scan_run_id=?1 ORDER BY created_at",
        )?;
        let rows = statement.query_map(params![scan_run_id], |row| row.get::<_, String>(0))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    fn scanner_runs(&self, scan_run_id: &str) -> AppResult<Vec<ScannerRun>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id,scan_run_id,scanner_id,scanner_name,status,version,started_at,finished_at,duration_ms,error,logs_json FROM scanner_runs WHERE scan_run_id=?1 ORDER BY started_at",
        )?;
        let rows = statement.query_map(params![scan_run_id], |row| {
            let logs: String = row.get(10)?;
            Ok(ScannerRun {
                id: row.get(0)?,
                scan_run_id: row.get(1)?,
                scanner_id: row.get(2)?,
                scanner_name: row.get(3)?,
                status: parse_enum(&row.get::<_, String>(4)?),
                version: row.get(5)?,
                started_at: row.get(6)?,
                finished_at: row.get(7)?,
                duration_ms: row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
                error: row.get(9)?,
                logs: serde_json::from_str(&logs).unwrap_or_default(),
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    fn lock(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| AppError::Database(rusqlite::Error::InvalidQuery))
    }
}

fn project_from_row(row: &Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        path: row.get(2)?,
        is_git: row.get::<_, i64>(3)? != 0,
        branch: row.get(4)?,
        commit_hash: row.get(5)?,
        primary_language: row.get(6)?,
        file_count: row.get::<_, i64>(7)? as u64,
        last_opened_at: row.get(8)?,
        created_at: row.get(9)?,
    })
}

fn scan_run_from_row(row: &Row<'_>) -> rusqlite::Result<ScanRun> {
    Ok(ScanRun {
        id: row.get(0)?,
        project_id: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        git_branch: row.get(4)?,
        git_commit: row.get(5)?,
        status: parse_enum(&row.get::<_, String>(6)?),
        finding_count: row.get::<_, i64>(7)? as usize,
        duration_ms: row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
        source: row.get(9)?,
        scanners: Vec::new(),
    })
}

fn finding_list_from_row(row: &Row<'_>) -> rusqlite::Result<FindingListItem> {
    let cwe: String = row.get(11)?;
    Ok(FindingListItem {
        id: row.get(0)?,
        scan_run_id: row.get(1)?,
        scanner_id: row.get(2)?,
        scanner_name: row.get(3)?,
        rule_id: row.get(4)?,
        title: row.get(5)?,
        message: row.get(6)?,
        severity: parse_enum(&row.get::<_, String>(7)?),
        category: parse_enum(&row.get::<_, String>(8)?),
        file_path: row.get(9)?,
        start_line: row.get::<_, i64>(10)? as u32,
        cwe: serde_json::from_str(&cwe).unwrap_or_default(),
        status: parse_enum(&row.get::<_, String>(12)?),
        triage_note: row.get(13)?,
        workspace_fingerprint: row.get(14)?,
    })
}

fn finding_from_row(row: &Row<'_>) -> rusqlite::Result<Finding> {
    let location: String = row.get(14)?;
    let related: String = row.get(15)?;
    let flows: String = row.get(16)?;
    let fixes: String = row.get(17)?;
    let taxa: String = row.get(18)?;
    let raw: String = row.get(19)?;
    let cwe: String = row.get(20)?;
    Ok(Finding {
        id: row.get(0)?,
        scan_run_id: row.get(1)?,
        project_id: row.get(2)?,
        scanner_id: row.get(3)?,
        scanner_name: row.get(4)?,
        rule_id: row.get(5)?,
        title: row.get(6)?,
        message: row.get(7)?,
        severity: parse_enum(&row.get::<_, String>(8)?),
        category: parse_enum(&row.get::<_, String>(9)?),
        status: parse_enum(&row.get::<_, String>(10)?),
        triage_note: row.get(11)?,
        native_fingerprint: row.get(12)?,
        workspace_fingerprint: row.get(13)?,
        location: serde_json::from_str(&location).unwrap_or_default(),
        related_locations: serde_json::from_str(&related).unwrap_or_default(),
        code_flows: serde_json::from_str(&flows).unwrap_or_default(),
        fixes: serde_json::from_str(&fixes).unwrap_or_default(),
        taxa: serde_json::from_str(&taxa).unwrap_or_default(),
        raw_sarif: serde_json::from_str(&raw).unwrap_or_default(),
        cwe: serde_json::from_str(&cwe).unwrap_or_default(),
    })
}

fn enum_string<T: Serialize>(value: &T) -> AppResult<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .unwrap_or_default()
        .to_string())
}

fn parse_enum<T: DeserializeOwned + Default>(value: &str) -> T {
    serde_json::from_value(serde_json::Value::String(value.to_string())).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn project(path: &Path) -> Project {
        Project {
            id: Uuid::new_v4().to_string(),
            name: "test".into(),
            path: path.to_string_lossy().to_string(),
            primary_language: "Rust".into(),
            last_opened_at: Utc::now().to_rfc3339(),
            created_at: Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }

    fn finding(project: &Project, run_id: &str, line: u32) -> Finding {
        Finding {
            id: Uuid::new_v4().to_string(),
            scan_run_id: run_id.into(),
            project_id: project.id.clone(),
            scanner_id: "demo".into(),
            scanner_name: "Demo".into(),
            rule_id: "rule.one".into(),
            title: "Demo finding".into(),
            message: "message".into(),
            severity: Severity::High,
            category: FindingCategory::Sast,
            status: FindingStatus::New,
            workspace_fingerprint: crate::fingerprint::FingerprintEngine::workspace_fingerprint(
                "demo",
                "rule.one",
                "src/main.rs",
                "message",
                line,
            ),
            raw_sarif: serde_json::json!({}),
            location: Location {
                file_path: "src/main.rs".into(),
                region: Region {
                    start_line: line,
                    start_column: 1,
                    end_line: line,
                    end_column: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn persists_projects_and_recent() {
        let dir = tempdir().expect("temp");
        let database = Database::new(&dir.path().join("app.db")).expect("db");
        let value = database.open_project(&project(dir.path())).expect("open");
        assert_eq!(
            database.recent_projects(10).expect("recent")[0].id,
            value.id
        );
    }

    #[test]
    fn persists_findings_and_triage() {
        let dir = tempdir().expect("temp");
        let database = Database::new(&dir.path().join("app.db")).expect("db");
        let value = database.open_project(&project(dir.path())).expect("open");
        let run = database.create_scan_run(&value.id, "test").expect("run");
        database
            .insert_findings(&[finding(&value, &run.id, 10)])
            .expect("findings");
        let items = database
            .list_findings(&FindingFilters {
                project_id: Some(value.id.clone()),
                ..Default::default()
            })
            .expect("list");
        assert_eq!(items.len(), 1);
        let updated = database
            .update_triage(
                &items[0].id,
                FindingStatus::Confirmed,
                Some("reviewed".into()),
            )
            .expect("triage");
        assert_eq!(updated.status, FindingStatus::Confirmed);
    }

    #[test]
    fn computes_new_and_fixed_by_fingerprint() {
        let dir = tempdir().expect("temp");
        let database = Database::new(&dir.path().join("app.db")).expect("db");
        let value = database.open_project(&project(dir.path())).expect("open");
        let first = database.create_scan_run(&value.id, "scan").expect("run");
        let old = finding(&value, &first.id, 10);
        database.insert_findings(&[old]).expect("findings");
        let second = database.create_scan_run(&value.id, "scan").expect("run");
        database
            .insert_findings(&[finding(&value, &second.id, 50)])
            .expect("findings");
        let diff = database
            .scan_diff(&value.id, &second.id, Some(&first.id))
            .expect("diff")
            .expect("previous");
        assert_eq!(diff.existing_count, 1);
        assert_eq!(diff.new_count, 0);
    }
}
