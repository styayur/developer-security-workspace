mod lifecycle;
mod migrations;
mod persist;
mod query;
mod schema;
pub mod streaming;
use lifecycle::decode;

use crate::error::{AppError, AppResult};
use crate::security_ir::*;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
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
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migrations::migrate(&mut connection)?;
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
            security_ir_version: SECURITY_IR_VERSION,
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
        let count: i64 = self.lock()?.query_row(
            "SELECT COUNT(*) FROM findings WHERE scan_run_id=?1",
            [scan_run_id],
            |row| row.get(0),
        )?;
        {
            let mut connection = self.lock()?;
            let tx = connection.transaction()?;
            tx.execute(
                "UPDATE scan_runs SET finished_at=?1,status=?2,finding_count=?3,duration_ms=?4 WHERE id=?5",
                params![finished.to_rfc3339(), enum_string(&status)?, count, duration.map(|value| value as i64), scan_run_id],
            )?;
            lifecycle::finalize(&tx, scan_run_id, &status)?;
            tx.commit()?;
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
        let prepared = lifecycle::assign(&transaction, findings)?;
        for (finding, assigned) in findings.iter().zip(&prepared) {
            persist::finding(&transaction, finding, assigned)?;
        }
        transaction.commit()?;
        Ok(findings.len())
    }

    pub fn list_findings(&self, filters: &FindingFilters) -> AppResult<Vec<FindingListItem>> {
        query::list(&*self.lock()?, filters, None, 0)
    }
    pub fn finding_page(
        &self,
        filters: &FindingFilters,
        offset: usize,
        limit: usize,
    ) -> AppResult<FindingPage> {
        let connection = self.lock()?;
        let limit = limit.clamp(1, 500);
        Ok(FindingPage {
            items: query::list(&connection, filters, Some(limit), offset)?,
            total: query::count(&connection, filters)?,
            offset,
            limit,
        })
    }
    pub fn finding_scanners(&self, project: &str) -> AppResult<Vec<String>> {
        let connection = self.lock()?;
        let mut stmt = connection.prepare(
            "SELECT DISTINCT scanner_id FROM findings WHERE project_id=?1 ORDER BY scanner_id",
        )?;
        let rows = stmt
            .query_map([project], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn finding_navigation(&self, finding_id: &str) -> AppResult<serde_json::Value> {
        let connection = self.lock()?;
        let project: String = connection.query_row(
            "SELECT project_id FROM findings WHERE id=?1",
            [finding_id],
            |row| row.get(0),
        )?;
        Ok(connection.query_row("WITH ordered AS (SELECT id,LAG(id) OVER w AS previous,LEAD(id) OVER w AS next,ROW_NUMBER() OVER w AS position,COUNT(*) OVER () AS total FROM findings WHERE project_id=?1 WINDOW w AS (ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,file_path,start_line,id)) SELECT previous,next,position,total FROM ordered WHERE id=?2",params![project,finding_id],|row|Ok(serde_json::json!({"previous":row.get::<_,Option<String>>(0)?,"next":row.get::<_,Option<String>>(1)?,"position":row.get::<_,usize>(2)?,"total":row.get::<_,usize>(3)?})))?)
    }

    pub fn get_finding(&self, finding_id: &str) -> AppResult<Finding> {
        let connection = self.lock()?;
        let mut finding = connection
            .query_row(
                &format!("{DETAIL_SELECT} WHERE id=?1"),
                params![finding_id],
                finding_from_row,
            )
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("Finding {finding_id}")))?;
        if let Some(reference) = &finding.raw_reference {
            if !reference.artifact_id.is_empty() {
                let raw: String = connection.query_row("SELECT raw_json FROM scan_artifact_results WHERE artifact_id=?1 AND run_index=?2 AND result_index=?3",
                    params![reference.artifact_id,reference.run_index as i64,reference.result_index as i64], |row| row.get(0))?;
                finding.raw_sarif = serde_json::from_str(&raw)?;
            }
        }
        let identity = connection.query_row("SELECT first_seen,last_seen,occurrence_count,fixed_at,reopened_at,state FROM finding_identities WHERE id=?1", [&finding.lifecycle.identity_id], |row| {
            Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,String>(5)?))
        }).optional()?;
        if let Some((first, last, count, fixed, reopened, state)) = identity {
            finding.lifecycle.first_seen = first;
            finding.lifecycle.last_seen = last;
            finding.lifecycle.occurrence_count = count as usize;
            finding.lifecycle.fixed_at = fixed;
            finding.lifecycle.reopened_at = reopened;
            finding.lifecycle.state = parse_enum(&state);
        }
        Ok(finding)
    }

    pub fn update_triage(
        &self,
        finding_id: &str,
        status: FindingStatus,
        note: Option<String>,
    ) -> AppResult<Finding> {
        let finding = self.get_finding(finding_id)?;
        let note = note.map(|value| crate::secret_redaction::SecretRedactor::redact_text(&value));
        let mut connection = self.lock()?;
        let tx = connection.transaction()?;
        tx.execute(
            "UPDATE finding_identities SET status=?1,note=?2 WHERE id=?3",
            params![enum_string(&status)?, note, finding.lifecycle.identity_id],
        )?;
        tx.execute(
            "UPDATE findings SET status=?1,triage_note=?2 WHERE identity_id=?3",
            params![enum_string(&status)?, note, finding.lifecycle.identity_id],
        )?;
        tx.commit()?;
        drop(connection);
        self.get_finding(finding_id)
    }

    pub fn dashboard(&self, project_id: &str) -> AppResult<DashboardSummary> {
        let project = self.get_project(project_id)?;
        let last_scan = self.latest_scan_run(project_id)?;
        let mut summary = DashboardSummary {
            project,
            last_scan: last_scan.clone(),
            ..Default::default()
        };
        if let Some(run) = last_scan {
            summary.fixed_findings = self
                .scan_diff(project_id, &run.id, None)?
                .map_or(0, |d| d.fixed_count);
            let connection = self.lock()?;
            let mut stmt = connection.prepare("SELECT severity,category,diff_class,COUNT(*) FROM findings WHERE scan_run_id=?1 GROUP BY severity,category,diff_class")?;
            let rows = stmt.query_map([&run.id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, usize>(3)?,
                ))
            })?;
            for row in rows {
                let (severity, category, class, count) = row?;
                summary.total_findings += count;
                match severity.as_str() {
                    "critical" => summary.severity.critical += count,
                    "high" => summary.severity.high += count,
                    "medium" => summary.severity.medium += count,
                    "low" => summary.severity.low += count,
                    _ => summary.severity.info += count,
                }
                *summary.categories.entry(category).or_default() += count;
                if class == "new" || class == "reopened" {
                    summary.new_findings += count;
                } else {
                    summary.existing_findings += count;
                }
            }
            summary.scanner_count = connection.query_row(
                "SELECT COUNT(DISTINCT scanner_id) FROM findings WHERE scan_run_id=?1",
                [&run.id],
                |row| row.get(0),
            )?;
        }
        Ok(summary)
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
        let current = self.get_scan_run(current_run_id)?;
        if current.project_id != project_id || previous.project_id != project_id {
            return Err(AppError::InvalidInput(
                "Diff runs must belong to the same project.".into(),
            ));
        }
        Ok(Some(query::diff(
            &*self.lock()?,
            current_run_id,
            &previous.id,
            0,
            100,
        )?))
    }
    pub fn scan_diff_page(
        &self,
        project: &str,
        current: &str,
        previous: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> AppResult<Option<ScanDiff>> {
        let Some(diff) = self.scan_diff(project, current, previous)? else {
            return Ok(None);
        };
        Ok(Some(query::diff(
            &*self.lock()?,
            current,
            &diff.previous_run_id,
            offset,
            limit,
        )?))
    }

    pub fn list_rules(&self, project_id: &str) -> AppResult<Vec<Rule>> {
        let connection = self.lock()?;
        let mut stmt=connection.prepare("SELECT rule_id,name,scanner_id,severity,cwe_json FROM rules WHERE project_id=?1 ORDER BY rule_id")?;
        let values = stmt
            .query_map([project_id], |row| {
                Ok(Rule {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    scanner_id: row.get(2)?,
                    severity: parse_enum(&row.get::<_, String>(3)?),
                    cwe: decode(row.get(4)?)?,
                    ..Default::default()
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
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
    ) -> AppResult<String> {
        let value: serde_json::Value = serde_json::from_str(raw_sarif)?;
        let mut value = crate::secret_redaction::SecretRedactor::redact_json(&value);
        let id = Uuid::new_v4().to_string();
        let mut connection = self.lock()?;
        let tx = connection.transaction()?;
        // Store run metadata once, and each result once. Finding details resolve this reference lazily.
        tx.execute("INSERT INTO scan_artifacts(id,scan_run_id,scanner_id,format,raw_sarif,created_at) VALUES (?1,?2,?3,?4,'{}',?5)",
            params![id,scan_run_id,scanner_id,format,Utc::now().to_rfc3339()])?;
        if let Some(runs) = value
            .get_mut("runs")
            .and_then(serde_json::Value::as_array_mut)
        {
            for (ri, run) in runs.iter_mut().enumerate() {
                if let Some(results) = run
                    .get_mut("results")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for (index, result) in results.drain(..).enumerate() {
                        tx.execute(
                            "INSERT INTO scan_artifact_results VALUES (?1,?2,?3,?4)",
                            params![id, ri as i64, index as i64, serde_json::to_string(&result)?],
                        )?;
                    }
                }
            }
        }
        tx.execute(
            "UPDATE scan_artifacts SET raw_sarif=?1 WHERE id=?2",
            params![serde_json::to_string(&value)?, id],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn scan_artifacts(&self, scan_run_id: &str) -> AppResult<Vec<String>> {
        let connection = self.lock()?;
        let size: i64 = connection.query_row("SELECT COALESCE(SUM(length(raw_sarif)),0)+(SELECT COALESCE(SUM(length(raw_json)),0) FROM scan_artifact_results WHERE artifact_id IN (SELECT id FROM scan_artifacts WHERE scan_run_id=?1)) FROM scan_artifacts WHERE scan_run_id=?1",[scan_run_id],|row|row.get(0))?;
        if size > 8 * 1024 * 1024 {
            return Err(AppError::InvalidInput("Full SARIF exceeds the 8 MiB inspector limit. Inspect individual results or export the scan.".into()));
        }
        let mut statement = connection.prepare(
            "SELECT id,raw_sarif FROM scan_artifacts WHERE scan_run_id=?1 ORDER BY created_at",
        )?;
        let artifacts = statement
            .query_map([scan_run_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut output = Vec::new();
        for (id, raw) in artifacts {
            let mut value: serde_json::Value = serde_json::from_str(&raw)?;
            let mut stmt = connection.prepare("SELECT run_index,raw_json FROM scan_artifact_results WHERE artifact_id=?1 ORDER BY run_index,result_index")?;
            let rows = stmt.query_map([id], |r| {
                Ok((r.get::<_, usize>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (ri, json) = row?;
                if let Some(results) = value["runs"][ri]["results"].as_array_mut() {
                    results.push(serde_json::from_str(&json)?);
                }
            }
            output.push(serde_json::to_string(&value)?);
        }
        Ok(output)
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
        security_ir_version: SECURITY_IR_VERSION,
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
        identity_id: row.get(15)?,
        diff_class: parse_enum(&row.get::<_, String>(16)?),
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
        cwe: decode(cwe)?,
        provenance: decode(row.get(21)?)?,
        fingerprints: decode(row.get(22)?)?,
        lifecycle: {
            let mut lifecycle: FindingLifecycle = decode(row.get(23)?)?;
            lifecycle.identity_id = row.get(25)?;
            lifecycle
        },
        raw_reference: row.get::<_, Option<String>>(24)?.map(decode).transpose()?,
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

    pub(super) fn project(path: &Path) -> Project {
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

    pub(super) fn finding(project: &Project, run_id: &str, line: u32) -> Finding {
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

const DETAIL_SELECT: &str = "SELECT id,scan_run_id,project_id,scanner_id,scanner_name,rule_id,title,message,severity,category,
status,triage_note,native_fingerprint,workspace_fingerprint,location_json,related_locations_json,code_flows_json,fixes_json,taxa_json,raw_sarif_json,cwe_json,
provenance_json,fingerprints_json,lifecycle_json,raw_reference_json,identity_id FROM findings";

#[cfg(test)]
mod regression_tests;

#[cfg(test)]
mod streaming_tests;
