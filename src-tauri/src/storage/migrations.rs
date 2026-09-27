use super::*;

pub fn migrate(connection: &mut Connection) -> AppResult<()> {
    let tx = connection.transaction()?;
    tx.execute_batch(schema::SCHEMA_SQL)?;
    tx.execute(
        "INSERT OR IGNORE INTO schema_migrations VALUES (1,?1)",
        [Utc::now().to_rfc3339()],
    )?;
    let version: i64 = tx.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
        row.get(0)
    })?;
    if version > schema::SCHEMA_VERSION {
        return Err(AppError::InvalidInput(
            "Database was written by a newer DSW version; refusing to modify it.".into(),
        ));
    }
    if version < 2 {
        tx.execute_batch(r#"
            ALTER TABLE findings ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}';
            ALTER TABLE findings ADD COLUMN fingerprints_json TEXT NOT NULL DEFAULT '{}';
            ALTER TABLE findings ADD COLUMN lifecycle_json TEXT NOT NULL DEFAULT '{}';
            ALTER TABLE findings ADD COLUMN raw_reference_json TEXT;
            ALTER TABLE findings ADD COLUMN identity_id TEXT NOT NULL DEFAULT '';
            ALTER TABLE findings ADD COLUMN diff_class TEXT NOT NULL DEFAULT 'new';
            ALTER TABLE findings ADD COLUMN candidate_json TEXT NOT NULL DEFAULT '{}';
            ALTER TABLE scan_runs ADD COLUMN security_ir_version INTEGER NOT NULL DEFAULT 1;
            CREATE TABLE finding_identities (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                scanner_id TEXT NOT NULL, latest_finding_id TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrence_count INTEGER NOT NULL,
                fixed_at TEXT, reopened_at TEXT, state TEXT NOT NULL, status TEXT NOT NULL,
                note TEXT, candidate_json TEXT NOT NULL
            );
            CREATE TABLE scan_artifact_results (
                artifact_id TEXT NOT NULL REFERENCES scan_artifacts(id) ON DELETE CASCADE,
                run_index INTEGER NOT NULL,result_index INTEGER NOT NULL,raw_json TEXT NOT NULL,
                PRIMARY KEY(artifact_id,run_index,result_index)
            );
            CREATE INDEX idx_identity_project_scanner ON finding_identities(project_id,scanner_id);
            CREATE INDEX idx_findings_identity_scan ON findings(identity_id,scan_run_id);
            CREATE INDEX idx_findings_project_scan_filter ON findings(project_id,scan_run_id,severity,scanner_id);
            CREATE INDEX idx_findings_project_status ON findings(project_id,status);
            CREATE INDEX idx_findings_project_category ON findings(project_id,category);
            CREATE INDEX idx_findings_project_rule ON findings(project_id,rule_id);
            CREATE INDEX idx_findings_run_diff ON findings(scan_run_id,diff_class);
            CREATE INDEX idx_findings_project_exact ON findings(project_id,workspace_fingerprint);
            CREATE INDEX idx_artifacts_scan ON scan_artifacts(scan_run_id);
        "#)?;
        // Legacy hashes are safe to group only when no scan contains a collision.
        tx.execute_batch(r#"
            CREATE TEMP TABLE legacy_identity AS
            SELECT project_id,workspace_fingerprint,MIN(id) AS identity_id,
              (SELECT MAX(n) FROM (SELECT COUNT(*) n FROM findings b
                 WHERE b.project_id=a.project_id AND b.workspace_fingerprint=a.workspace_fingerprint GROUP BY scan_run_id)) AS collisions
            FROM findings a GROUP BY project_id,workspace_fingerprint;
            UPDATE findings SET identity_id=COALESCE((SELECT identity_id FROM legacy_identity l
                WHERE l.project_id=findings.project_id AND l.workspace_fingerprint=findings.workspace_fingerprint AND l.collisions=1),id);
        "#)?;
        let mut offset = 0;
        loop {
            let batch = {
                let mut stmt = tx.prepare(&format!(
                    "{} ORDER BY rowid LIMIT 256 OFFSET ?1",
                    super::DETAIL_SELECT
                ))?;
                let values = stmt
                    .query_map([offset], super::finding_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                values
            };
            if batch.is_empty() {
                break;
            }
            offset += batch.len() as i64;
            for mut f in batch {
                f.fingerprints = crate::fingerprint::structured(&f);
                f.provenance.scanner_id = f.scanner_id.clone();
                f.provenance.scanner_name = f.scanner_name.clone();
                f.provenance.scan_run_id = f.scan_run_id.clone();
                let candidate =
                    serde_json::to_string(&crate::matching::Candidate::from_finding(&f))?;
                tx.execute("UPDATE findings SET provenance_json=?1,fingerprints_json=?2,candidate_json=?3,raw_sarif_json=?4 WHERE id=?5",
                    params![serde_json::to_string(&f.provenance)?,serde_json::to_string(&f.fingerprints)?,candidate,
                    serde_json::to_string(&crate::secret_redaction::SecretRedactor::redact_json(&f.raw_sarif))?,f.id])?;
            }
        }
        tx.execute_batch(r#"
            INSERT INTO finding_identities(id,project_id,scanner_id,latest_finding_id,first_seen,last_seen,occurrence_count,state,status,note,candidate_json)
            SELECT f.identity_id,f.project_id,f.scanner_id,f.id,
                (SELECT MIN(s.started_at) FROM findings b JOIN scan_runs s ON s.id=b.scan_run_id WHERE b.identity_id=f.identity_id),
                r.started_at,(SELECT COUNT(*) FROM findings b WHERE b.identity_id=f.identity_id),
                'existing',f.status,f.triage_note,f.candidate_json
            FROM findings f JOIN scan_runs r ON r.id=f.scan_run_id
            WHERE f.id=(SELECT b.id FROM findings b JOIN scan_runs s ON s.id=b.scan_run_id
                WHERE b.identity_id=f.identity_id ORDER BY s.started_at DESC,b.rowid DESC LIMIT 1);
            UPDATE findings SET diff_class=CASE WHEN status='new' THEN 'new' ELSE 'existing' END;
        "#)?;
        // Earlier preview artifacts were not consistently redacted. Repair them transactionally.
        let ids = {
            let mut stmt = tx.prepare("SELECT id FROM scan_artifacts")?;
            let values = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            values
        };
        for id in ids {
            let raw: String = tx.query_row(
                "SELECT raw_sarif FROM scan_artifacts WHERE id=?1",
                [&id],
                |row| row.get(0),
            )?;
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            tx.execute(
                "UPDATE scan_artifacts SET raw_sarif=?1 WHERE id=?2",
                params![
                    serde_json::to_string(&crate::secret_redaction::SecretRedactor::redact_json(
                        &value
                    ))?,
                    id
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO schema_migrations VALUES (2,?1)",
            [Utc::now().to_rfc3339()],
        )?;
    }
    tx.commit()?;
    Ok(())
}
