use super::*;
use crate::matching::{Candidate, FindingMatcher};

pub struct AssignedFinding {
    pub lifecycle: FindingLifecycle,
    pub fingerprints: FindingFingerprints,
    pub status: FindingStatus,
    pub triage_note: Option<String>,
}

pub fn assign(tx: &Connection, findings: &[Finding]) -> AppResult<Vec<AssignedFinding>> {
    let first = &findings[0];
    if findings
        .iter()
        .any(|f| f.project_id != first.project_id || f.scan_run_id != first.scan_run_id)
    {
        return Err(AppError::InvalidInput(
            "A finding batch must belong to one project and scan.".into(),
        ));
    }
    let previous = {
        let mut stmt = tx.prepare("SELECT candidate_json,id,first_seen,last_seen,occurrence_count,fixed_at,reopened_at,state,status,note FROM finding_identities WHERE project_id=?1 AND latest_finding_id NOT IN (SELECT id FROM findings WHERE scan_run_id=?2)")?;
        let values = stmt
            .query_map(params![first.project_id, first.scan_run_id], |row| {
                let candidate: Candidate = decode(row.get(0)?)?;
                Ok((
                    candidate,
                    FindingLifecycle {
                        identity_id: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        occurrence_count: row.get::<_, i64>(4)? as usize,
                        fixed_at: row.get(5)?,
                        reopened_at: row.get(6)?,
                        state: parse_enum(&row.get::<_, String>(7)?),
                        matched_by: None,
                    },
                    parse_enum::<FindingStatus>(&row.get::<_, String>(8)?),
                    row.get::<_, Option<String>>(9)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        values
    };
    let candidates = findings
        .iter()
        .map(Candidate::from_finding)
        .collect::<Vec<_>>();
    let matches = FindingMatcher::match_findings(
        &previous.iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
        &candidates,
    );
    let by_id: HashMap<_, _> = previous.iter().map(|p| (p.0.id.as_str(), p)).collect();
    let matches: HashMap<_, _> = matches
        .into_iter()
        .map(|m| (m.current_finding_id.clone(), m))
        .collect();
    let now: String = tx.query_row(
        "SELECT started_at FROM scan_runs WHERE id=?1",
        [&first.scan_run_id],
        |row| row.get(0),
    )?;
    let mut assigned = Vec::with_capacity(findings.len());
    for (original, candidate) in findings.iter().zip(candidates) {
        let matched = matches.get(&original.id);
        let previous = matched.and_then(|m| by_id.get(m.previous_finding_id.as_str()).copied());
        let f = assign_one(tx, original, &candidate, previous, matched, &now)?;
        assigned.push(f);
    }
    Ok(assigned)
}

pub type Previous = (Candidate, FindingLifecycle, FindingStatus, Option<String>);

pub fn assign_one(
    tx: &Connection,
    original: &Finding,
    candidate: &Candidate,
    previous: Option<&Previous>,
    matched: Option<&FindingMatch>,
    now: &str,
) -> AppResult<AssignedFinding> {
    let mut f = AssignedFinding {
        lifecycle: FindingLifecycle::default(),
        fingerprints: candidate.fingerprints.clone(),
        status: original.status.clone(),
        triage_note: original.triage_note.clone(),
    };
    if let (Some(matched), Some((old, lifecycle, status, note))) = (matched, previous) {
        f.lifecycle = lifecycle.clone();
        f.lifecycle.state = if lifecycle.state == DiffClass::Fixed {
            DiffClass::Reopened
        } else if old.signature != candidate.signature {
            DiffClass::Changed
        } else {
            DiffClass::Existing
        };
        if f.lifecycle.state == DiffClass::Reopened {
            f.lifecycle.reopened_at = Some(now.to_string());
        }
        f.lifecycle.fixed_at = None;
        f.lifecycle.occurrence_count += 1;
        f.lifecycle.matched_by = Some(matched.clone());
        f.status = if is_triage(status) {
            status.clone()
        } else if f.lifecycle.state == DiffClass::Reopened {
            FindingStatus::Reopened
        } else {
            FindingStatus::Existing
        };
        f.triage_note = note.clone();
    } else {
        f.lifecycle = FindingLifecycle {
            identity_id: Uuid::new_v4().to_string(),
            first_seen: now.to_string(),
            occurrence_count: 1,
            ..Default::default()
        };
    }
    f.lifecycle.last_seen = now.to_string();
    tx.execute(r#"INSERT INTO finding_identities(id,project_id,scanner_id,latest_finding_id,first_seen,last_seen,occurrence_count,fixed_at,reopened_at,state,status,note,candidate_json)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
            ON CONFLICT(id) DO UPDATE SET latest_finding_id=excluded.latest_finding_id,last_seen=excluded.last_seen,
              occurrence_count=excluded.occurrence_count,fixed_at=excluded.fixed_at,reopened_at=excluded.reopened_at,
              state=excluded.state,status=excluded.status,note=excluded.note,candidate_json=excluded.candidate_json"#,
            params![f.lifecycle.identity_id,original.project_id,original.scanner_id,original.id,f.lifecycle.first_seen,now,
                f.lifecycle.occurrence_count as i64,f.lifecycle.fixed_at,f.lifecycle.reopened_at,enum_string(&f.lifecycle.state)?,
                enum_string(&f.status)?,f.triage_note,serde_json::to_string(&candidate)?])?;
    Ok(f)
}

pub fn is_triage(status: &FindingStatus) -> bool {
    matches!(
        status,
        FindingStatus::Confirmed
            | FindingStatus::FalsePositive
            | FindingStatus::AcceptedRisk
            | FindingStatus::Ignored
    )
}

/// Absence only has meaning in a completed full scan and for covered scanners.
pub fn finalize(tx: &Connection, run: &str, status: &ScanStatus) -> AppResult<()> {
    if *status != ScanStatus::Completed {
        return Ok(());
    }
    tx.execute(r#"UPDATE finding_identities SET state='fixed',fixed_at=(SELECT finished_at FROM scan_runs WHERE id=?1)
        WHERE project_id=(SELECT project_id FROM scan_runs WHERE id=?1)
        AND (SELECT source FROM scan_runs WHERE id=?1)<>'scan_changed'
        AND scanner_id IN (SELECT scanner_id FROM scanner_runs WHERE scan_run_id=?1 AND status='completed')
        AND last_seen <= (SELECT started_at FROM scan_runs WHERE id=?1)
        AND state<>'fixed' AND id NOT IN (SELECT identity_id FROM findings WHERE scan_run_id=?1)"#, [run])?;
    Ok(())
}

pub fn decode<T: DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}
