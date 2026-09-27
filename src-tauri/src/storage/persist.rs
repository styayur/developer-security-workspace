use super::*;

pub(super) fn finding(
    connection: &Connection,
    finding: &Finding,
    assigned: &lifecycle::AssignedFinding,
) -> AppResult<()> {
    connection.prepare_cached(
                r#"INSERT INTO findings(
                    id,scan_run_id,project_id,scanner_id,scanner_name,rule_id,title,message,severity,category,
                    file_path,start_line,start_column,end_line,end_column,cwe_json,status,triage_note,
                    native_fingerprint,workspace_fingerprint,location_json,related_locations_json,code_flows_json,
                    fixes_json,taxa_json,raw_sarif_json,provenance_json,fingerprints_json,lifecycle_json,raw_reference_json,identity_id,diff_class,candidate_json
                  ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33)"#)?.execute(
                params![
                    finding.id, finding.scan_run_id, finding.project_id, finding.scanner_id,
                    finding.scanner_name, finding.rule_id, finding.title, finding.message,
                    enum_string(&finding.severity)?, enum_string(&finding.category)?,
                    finding.location.file_path, finding.location.region.start_line as i64,
                    finding.location.region.start_column as i64, finding.location.region.end_line as i64,
                    finding.location.region.end_column as i64, serde_json::to_string(&finding.cwe)?,
                    enum_string(&assigned.status)?, assigned.triage_note, finding.native_fingerprint,
                    finding.workspace_fingerprint, serde_json::to_string(&finding.location)?,
                    serde_json::to_string(&finding.related_locations)?, serde_json::to_string(&finding.code_flows)?,
                    serde_json::to_string(&finding.fixes)?, serde_json::to_string(&finding.taxa)?,
                    if finding.raw_reference.as_ref().is_some_and(|r| !r.artifact_id.is_empty()) { "null".into() } else { serde_json::to_string(&crate::secret_redaction::SecretRedactor::redact_json(&finding.raw_sarif))? },
                    serde_json::to_string(&finding.provenance)?, serde_json::to_string(&assigned.fingerprints)?,
                    serde_json::to_string(&assigned.lifecycle)?, finding.raw_reference.as_ref().map(serde_json::to_string).transpose()?,
                    assigned.lifecycle.identity_id, enum_string(&assigned.lifecycle.state)?, serde_json::to_string(&crate::matching::Candidate::from_finding(finding))?
                ],
            )?;
    for location in std::iter::once(&finding.location).chain(finding.related_locations.iter()) {
        connection.execute(
                    "INSERT INTO finding_locations(finding_id,relation,file_path,start_line,start_column,end_line,end_column) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![finding.id, "related", location.file_path, location.region.start_line as i64, location.region.start_column as i64, location.region.end_line as i64, location.region.end_column as i64],
                )?;
    }
    if let Some(native) = &finding.native_fingerprint {
        connection.execute(
            "INSERT INTO finding_fingerprints(finding_id,kind,value) VALUES (?1,'native',?2)",
            params![finding.id, native],
        )?;
    }
    connection.execute(
        "INSERT INTO finding_fingerprints(finding_id,kind,value) VALUES (?1,'workspace',?2)",
        params![finding.id, finding.workspace_fingerprint],
    )?;
    connection.execute(
                r#"INSERT INTO rules(project_id,scanner_id,rule_id,name,description,help,help_uri,severity,cwe_json,tags_json)
                   VALUES (?1,?2,?3,?4,NULL,NULL,NULL,?5,?6,'[]')
                   ON CONFLICT(project_id,scanner_id,rule_id) DO UPDATE SET severity=excluded.severity,cwe_json=excluded.cwe_json"#,
                params![finding.project_id, finding.scanner_id, finding.rule_id, finding.title, enum_string(&finding.severity)?, serde_json::to_string(&finding.cwe)?],
            )?;

    Ok(())
}
