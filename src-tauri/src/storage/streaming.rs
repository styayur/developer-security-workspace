//! Disk-backed import and global SQL matching; cancellation rolls back all durable changes.
use super::*;
use crate::matching::Candidate;
use crate::sarif::streaming::{check_cancel, ImportProgress, Staged};
use tokio_util::sync::CancellationToken;

pub fn import(
    database: &Database,
    path: &Path,
    project: &Project,
    run: &ScanRun,
    cancel: &CancellationToken,
    progress: &dyn Fn(ImportProgress),
) -> AppResult<usize> {
    let emit = |phase: &str, processed, total| {
        progress(ImportProgress {
            import_id: run.id.clone(),
            phase: phase.into(),
            processed,
            total,
        })
    };
    let mut staged = crate::sarif::streaming::stage(path, cancel, &|n| emit("parsing", n, None))?;
    emit("normalizing", 0, Some(staged.count));
    let count = staged.count;
    normalize(&mut staged, project, run, cancel, &|n| {
        emit("normalizing", n, Some(count))
    })?;
    check_cancel(cancel)?;
    emit("matching", 0, Some(staged.count));
    commit(database, &staged, project, run, cancel, &|n| {
        emit("committing", n, Some(staged.count))
    })?;
    emit("completed", staged.count, Some(staged.count));
    Ok(staged.count)
}

fn normalize(
    staged: &mut Staged,
    project: &Project,
    run: &ScanRun,
    cancel: &CancellationToken,
    progress: &dyn Fn(usize),
) -> AppResult<()> {
    let tx = staged.connection.transaction()?;
    let mut total = 0usize;
    for ri in 0..staged.runs {
        let header: String =
            tx.query_row("SELECT header FROM runs WHERE idx=?1", [ri], |r| r.get(0))?;
        let producer = serde_json::from_str(&header)?;
        let mut log = crate::sarif::SarifLog {
            version: "2.1.0".into(),
            runs: vec![producer],
            ..Default::default()
        };
        let mut statement =
            tx.prepare("SELECT idx,raw,native FROM results WHERE run=?1 ORDER BY idx")?;
        let mut rows = statement.query([ri])?;
        while let Some(row) = rows.next()? {
            check_cancel(cancel)?;
            let index: usize = row.get(0)?;
            let raw: String = row.get(1)?;
            log.runs[0].results = vec![serde_json::from_str(&raw)?];
            let mut findings =
                crate::sarif::normalize_log(&log, Path::new(&project.path), &project.id, &run.id)?;
            let f = &mut findings[0];
            f.native_fingerprint = row.get(2)?;
            f.fingerprints.native = f.native_fingerprint.clone();
            if let Some(reference) = &mut f.raw_reference {
                reference.run_index = ri;
                reference.result_index = index;
            }
            f.raw_sarif = serde_json::Value::Null;
            let candidate = Candidate::from_finding(f);
            tx.prepare_cached("INSERT INTO normalized(id,finding,candidate) VALUES(?1,?2,?3)")?
                .execute(params![
                    f.id,
                    serde_json::to_string(f)?,
                    serde_json::to_string(&candidate)?
                ])?;
            total += 1;
            if total.is_multiple_of(256) {
                progress(total);
            }
        }
    }
    check_cancel(cancel)?;
    tx.commit()?;
    Ok(())
}

fn commit(
    database: &Database,
    staged: &Staged,
    project: &Project,
    run: &ScanRun,
    cancel: &CancellationToken,
    progress: &dyn Fn(usize),
) -> AppResult<()> {
    let mut connection = database.lock()?;
    connection.execute(
        "ATTACH DATABASE ?1 AS import_stage",
        [staged.path().to_string_lossy().as_ref()],
    )?;
    // Temporary tables spill to disk; cap the main page cache for large identity histories.
    connection.execute_batch("PRAGMA temp_store=FILE; PRAGMA cache_size=-8192;")?;
    let interrupt = cancel.clone();
    connection.progress_handler(10_000, Some(move || interrupt.is_cancelled()));
    let result = (|| -> AppResult<()> {
        let tx = connection.transaction()?;
        tx.execute_batch("CREATE TEMP TABLE import_matches(current_id TEXT PRIMARY KEY,previous_id TEXT UNIQUE,method TEXT);")?;
        for (table, source) in [
            (
                "import_current",
                "SELECT id,candidate FROM import_stage.normalized",
            ),
            (
                "import_previous",
                "SELECT id,candidate_json AS candidate FROM finding_identities WHERE project_id=?1",
            ),
        ] {
            let sql=format!("CREATE TEMP TABLE {table} AS SELECT id,candidate,
                CASE WHEN COALESCE(json_extract(candidate,'$.fingerprints.native'),'')<>'' THEN json_array(json_extract(candidate,'$.scannerId'),json_extract(candidate,'$.ruleId'),json_extract(candidate,'$.fingerprints.native')) END AS native,
                CASE WHEN COALESCE(json_extract(candidate,'$.fingerprints.exact'),'')<>'' THEN json_array(json_extract(candidate,'$.scannerId'),json_extract(candidate,'$.ruleId'),json_extract(candidate,'$.fingerprints.exact')) END AS exact,
                CASE WHEN COALESCE(json_extract(candidate,'$.fingerprints.context'),'')<>'' THEN json_array(json_extract(candidate,'$.scannerId'),json_extract(candidate,'$.ruleId'),json_extract(candidate,'$.fingerprints.context')) END AS context,
                CASE WHEN COALESCE(json_extract(candidate,'$.fingerprints.semantic'),'')<>'' THEN json_array(json_extract(candidate,'$.scannerId'),json_extract(candidate,'$.ruleId'),json_extract(candidate,'$.fingerprints.semantic')) END AS semantic,
                json_extract(candidate,'$.symbols') AS symbols FROM ({source})");
            if table == "import_previous" {
                tx.execute(&sql, [&project.id])?;
            } else {
                tx.execute(&sql, [])?;
            }
            tx.execute_batch(&format!("CREATE UNIQUE INDEX {table}_id ON {table}(id);"))?;
        }
        for (key, method) in [
            ("native", "native"),
            ("exact", "exact"),
            ("context", "context"),
            ("semantic", "relocated"),
        ] {
            check_cancel(cancel)?;
            // Count the entire unmatched scan at every stage, never a page/batch in isolation.
            tx.execute(&format!("INSERT INTO import_matches
                WITH c AS (SELECT MIN(id) id,{key} k FROM import_current WHERE {key} IS NOT NULL AND id NOT IN(SELECT current_id FROM import_matches) GROUP BY {key} HAVING COUNT(*)=1),
                p AS (SELECT MIN(id) id,{key} k FROM import_previous WHERE {key} IS NOT NULL AND id NOT IN(SELECT previous_id FROM import_matches) GROUP BY {key} HAVING COUNT(*)=1)
                SELECT c.id,p.id,?1 FROM c JOIN p USING(k) JOIN import_current cc ON cc.id=c.id JOIN import_previous pp ON pp.id=p.id
                WHERE cc.symbols='[]' OR pp.symbols='[]' OR cc.symbols=pp.symbols"),[method])?;
        }
        check_cancel(cancel)?;
        let artifact = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO scan_artifacts(id,scan_run_id,scanner_id,format,raw_sarif,created_at) VALUES(?1,?2,'import','sarif',?3,?4)",params![artifact,run.id,staged.header.to_string(),Utc::now().to_rfc3339()])?;
        let mut count = 0usize;
        let mut statement=tx.prepare("SELECT n.finding,n.candidate,m.previous_id,m.method,p.candidate FROM import_stage.normalized n LEFT JOIN import_matches m ON m.current_id=n.id LEFT JOIN import_previous p ON p.id=m.previous_id ORDER BY n.seq")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            check_cancel(cancel)?;
            let mut finding: Finding = serde_json::from_str(&row.get::<_, String>(0)?)?;
            let candidate: Candidate = serde_json::from_str(&row.get::<_, String>(1)?)?;
            let identity: Option<String> = row.get(2)?;
            let previous = if let Some(id) = identity {
                let old: Candidate = serde_json::from_str(&row.get::<_, String>(4)?)?;
                Some(tx.query_row("SELECT id,first_seen,last_seen,occurrence_count,fixed_at,reopened_at,state,status,note FROM finding_identities WHERE id=?1",[id],|r|Ok((old,
                    FindingLifecycle {identity_id:r.get(0)?,first_seen:r.get(1)?,last_seen:r.get(2)?,occurrence_count:r.get(3)?,fixed_at:r.get(4)?,reopened_at:r.get(5)?,state:parse_enum(&r.get::<_,String>(6)?),matched_by:None},
                    parse_enum(&r.get::<_,String>(7)?),r.get(8)?)))?)
            } else {
                None
            };
            let matched = if let Some(old) = &previous {
                let method: MatchMethod =
                    serde_json::from_value(serde_json::Value::String(row.get(3)?))?;
                Some(FindingMatch {
                    previous_finding_id: old.0.id.clone(),
                    previous_scan_run_id: old.0.scan_run_id.clone(),
                    current_finding_id: finding.id.clone(),
                    confidence: match method {
                        MatchMethod::Native | MatchMethod::Exact => MatchConfidence::Exact,
                        MatchMethod::Context => MatchConfidence::Strong,
                        MatchMethod::Relocated => MatchConfidence::Weak,
                    },
                    method,
                })
            } else {
                None
            };
            let reference = finding
                .raw_reference
                .as_mut()
                .ok_or_else(|| AppError::Sarif("Missing result reference".into()))?;
            reference.artifact_id = artifact.clone();
            tx.execute("INSERT INTO scan_artifact_results(artifact_id,run_index,result_index,raw_json) SELECT ?1,run,idx,raw FROM import_stage.results WHERE run=?2 AND idx=?3",params![artifact,reference.run_index,reference.result_index])?;
            let assigned = lifecycle::assign_one(
                &tx,
                &finding,
                &candidate,
                previous.as_ref(),
                matched.as_ref(),
                &run.started_at,
            )?;
            persist::finding(&tx, &finding, &assigned)?;
            count += 1;
            if count.is_multiple_of(256) {
                progress(count);
            }
        }
        drop(rows);
        drop(statement);
        for header in staged.header["runs"].as_array().into_iter().flatten() {
            let driver = &header["tool"]["driver"];
            let name = driver["name"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("Unknown scanner");
            let scanner = crate::sarif::normalize::slugify(name);
            tx.execute("INSERT INTO scanner_runs(id,scan_run_id,scanner_id,scanner_name,status,started_at,finished_at,logs_json) VALUES(?1,?2,?3,?4,'completed',?5,?6,'[]')",params![Uuid::new_v4().to_string(),run.id,scanner,name,run.started_at,Utc::now().to_rfc3339()])?;
        }
        let now = Utc::now();
        let duration = chrono::DateTime::parse_from_rfc3339(&run.started_at)
            .map(|s| (now - s.with_timezone(&Utc)).num_milliseconds().max(0))
            .unwrap_or_default();
        tx.execute("UPDATE scan_runs SET status='completed',finished_at=?1,finding_count=?2,duration_ms=?3 WHERE id=?4",params![now.to_rfc3339(),count,duration,run.id])?;
        lifecycle::finalize(&tx, &run.id, &ScanStatus::Completed)?;
        check_cancel(cancel)?;
        tx.commit()?;
        Ok(())
    })();
    connection.progress_handler(0, None::<fn() -> bool>);
    // Drop only this import's temporary working tables; never application tables.
    let cleanup=connection.execute_batch("DROP TABLE IF EXISTS temp.import_matches; DROP TABLE IF EXISTS temp.import_current; DROP TABLE IF EXISTS temp.import_previous; DETACH DATABASE import_stage;");
    result.and(cleanup.map_err(AppError::from))
}
