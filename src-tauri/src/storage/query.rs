use super::*;
use rusqlite::{params_from_iter, types::Value};

pub const LIST_COLUMNS: &str = "id,scan_run_id,scanner_id,scanner_name,rule_id,title,message,severity,category,file_path,start_line,cwe_json,status,triage_note,workspace_fingerprint,identity_id,diff_class";
const CURRENT_LIST_COLUMNS: &str = "f.id,f.scan_run_id,f.scanner_id,f.scanner_name,f.rule_id,f.title,f.message,f.severity,f.category,f.file_path,f.start_line,f.cwe_json,f.status,f.triage_note,f.workspace_fingerprint,f.identity_id,f.diff_class";

fn predicate(filters: &FindingFilters) -> AppResult<(String, Vec<Value>)> {
    let mut clauses = vec!["1=1".to_string()];
    let mut values = Vec::new();
    for (column, value) in [
        ("project_id", &filters.project_id),
        ("scan_run_id", &filters.scan_run_id),
        ("rule_id", &filters.rule_id),
        ("diff_class", &filters.diff_class),
    ] {
        if let Some(value) = value {
            clauses.push(format!("{column}=?"));
            values.push(Value::Text(value.clone()));
        }
    }
    for (column, items) in [
        (
            "severity",
            filters
                .severities
                .iter()
                .map(enum_string)
                .collect::<AppResult<Vec<_>>>()?,
        ),
        ("scanner_id", filters.scanners.clone()),
        (
            "category",
            filters
                .categories
                .iter()
                .map(enum_string)
                .collect::<AppResult<Vec<_>>>()?,
        ),
        (
            "status",
            filters
                .statuses
                .iter()
                .map(enum_string)
                .collect::<AppResult<Vec<_>>>()?,
        ),
    ] {
        if !items.is_empty() {
            clauses.push(format!(
                "{column} IN ({})",
                vec!["?"; items.len()].join(",")
            ));
            values.extend(items.into_iter().map(Value::Text));
        }
    }
    if let Some(path) = &filters.file_path {
        clauses.push("instr(lower(file_path),lower(?))>0".into());
        values.push(Value::Text(path.clone()));
    }
    if let Some(cwe) = &filters.cwe {
        clauses
            .push("EXISTS(SELECT 1 FROM json_each(cwe_json) WHERE lower(value)=lower(?))".into());
        values.push(Value::Text(cwe.clone()));
    }
    if let Some(search) = &filters.search {
        if !search.trim().is_empty() {
            clauses.push("instr(lower(title||' '||message||' '||rule_id||' '||file_path||' '||scanner_name||' '||cwe_json),lower(?))>0".into());
            values.push(Value::Text(search.trim().into()));
        }
    }
    Ok((clauses.join(" AND "), values))
}

pub fn list(
    connection: &Connection,
    filters: &FindingFilters,
    limit: Option<usize>,
    offset: usize,
) -> AppResult<Vec<FindingListItem>> {
    let (where_sql, mut values) = predicate(filters)?;
    let mut sql = format!("SELECT {LIST_COLUMNS} FROM findings WHERE {where_sql} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,file_path,start_line,id");
    if let Some(limit) = limit {
        sql.push_str(" LIMIT ? OFFSET ?");
        values.push(Value::Integer(limit as i64));
        values.push(Value::Integer(offset as i64));
    }
    let mut stmt = connection.prepare(&sql)?;
    let result = stmt
        .query_map(params_from_iter(values), finding_list_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(result)
}
pub fn count(connection: &Connection, filters: &FindingFilters) -> AppResult<usize> {
    let (where_sql, values) = predicate(filters)?;
    Ok(connection.query_row(
        &format!("SELECT COUNT(*) FROM findings WHERE {where_sql}"),
        params_from_iter(values),
        |row| row.get::<_, i64>(0),
    )? as usize)
}

pub fn current(connection: &Connection, project_id: &str) -> AppResult<Vec<FindingListItem>> {
    let mut statement = connection.prepare(&format!(
        r#"SELECT {CURRENT_LIST_COLUMNS}
           FROM findings f
           JOIN finding_identities i ON i.id=f.identity_id
           WHERE f.project_id=?1 AND i.latest_finding_id=f.id AND i.state<>'fixed'
           ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,f.file_path,f.start_line,f.id"#
    ))?;
    let result = statement
        .query_map([project_id], finding_list_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(result)
}

pub fn diff(
    connection: &Connection,
    current: &str,
    previous: &str,
    offset: usize,
    limit: usize,
) -> AppResult<ScanDiff> {
    let limit = limit.clamp(1, 500);
    let mut result = ScanDiff {
        current_run_id: current.into(),
        previous_run_id: previous.into(),
        offset,
        limit,
        ..Default::default()
    };
    // Identity correspondence is one-to-one, unlike the old lossy hash-set comparison.
    for class in ["new", "existing", "changed", "reopened", "fixed"] {
        let condition = match class {
            "existing" => "scan_run_id=?1 AND EXISTS(SELECT 1 FROM findings p WHERE p.scan_run_id=?2 AND p.identity_id=f.identity_id AND json_extract(p.candidate_json,'$.signature')=json_extract(f.candidate_json,'$.signature'))",
            "changed" => "scan_run_id=?1 AND EXISTS(SELECT 1 FROM findings p WHERE p.scan_run_id=?2 AND p.identity_id=f.identity_id AND json_extract(p.candidate_json,'$.signature')<>json_extract(f.candidate_json,'$.signature'))",
            "fixed" => "scan_run_id=?2 AND NOT EXISTS(SELECT 1 FROM findings c WHERE c.scan_run_id=?1 AND c.identity_id=f.identity_id) AND (SELECT status='completed' AND source<>'scan_changed' FROM scan_runs WHERE id=?1) AND scanner_id IN (SELECT scanner_id FROM scanner_runs WHERE scan_run_id=?1 AND status='completed')",
            "reopened" => "scan_run_id=?1 AND diff_class='reopened' AND NOT EXISTS(SELECT 1 FROM findings p WHERE p.scan_run_id=?2 AND p.identity_id=f.identity_id)",
            _ => "scan_run_id=?1 AND diff_class<>'reopened' AND NOT EXISTS(SELECT 1 FROM findings p WHERE p.scan_run_id=?2 AND p.identity_id=f.identity_id)",
        };
        let count = connection.query_row(
            &format!("SELECT COUNT(*) FROM findings f WHERE {condition}"),
            params![current, previous],
            |r| r.get::<_, i64>(0),
        )? as usize;
        let mut stmt = connection.prepare(&format!("SELECT {LIST_COLUMNS} FROM findings f WHERE {condition} ORDER BY file_path,start_line,id LIMIT ?3 OFFSET ?4"))?;
        let rows = stmt
            .query_map(
                params![current, previous, limit as i64, offset as i64],
                finding_list_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        match class {
            "new" => {
                result.new = rows;
                result.new_count = count;
            }
            "existing" => {
                result.existing = rows;
                result.existing_count = count;
            }
            "changed" => {
                result.changed = rows;
                result.changed_count = count;
            }
            "reopened" => {
                result.reopened = rows;
                result.reopened_count = count;
            }
            _ => {
                result.fixed = rows;
                result.fixed_count = count;
            }
        }
    }
    Ok(result)
}
