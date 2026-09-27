use crate::error::AppResult;
use crate::fingerprint::FingerprintEngine;
use crate::sarif::model::{
    SarifArtifactLocation, SarifCodeFlow, SarifFix, SarifLocation, SarifLog, SarifRegion,
    SarifReportingDescriptor, SarifResult, SarifRun,
};
use crate::sarif::path_mapper::{map_artifact_uri, relative_display};
use crate::secret_redaction::SecretRedactor;
use crate::security_ir::{
    CodeFlow, Finding, FindingCategory, FindingProvenance, FindingStatus, Fix, FixReplacement,
    Location, RawReference, Region, Severity, Taxonomy, ThreadFlow, TraceStep, TraceStepKind,
};
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn normalize_log(
    log: &SarifLog,
    workspace_root: &Path,
    project_id: &str,
    scan_run_id: &str,
) -> AppResult<Vec<Finding>> {
    normalize_inner(log, workspace_root, project_id, scan_run_id, None)
}

pub fn normalize_log_with_scanner(
    log: &SarifLog,
    workspace_root: &Path,
    project_id: &str,
    scan_run_id: &str,
    scanner_id: &str,
) -> AppResult<Vec<Finding>> {
    normalize_inner(
        log,
        workspace_root,
        project_id,
        scan_run_id,
        Some(scanner_id),
    )
}

fn normalize_inner(
    log: &SarifLog,
    workspace_root: &Path,
    project_id: &str,
    scan_run_id: &str,
    scanner_override: Option<&str>,
) -> AppResult<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut sources = std::collections::HashMap::new();
    for (run_index, run) in log.runs.iter().enumerate() {
        let scanner_name = if run.tool.driver.name.trim().is_empty() {
            "Unknown scanner".to_string()
        } else {
            run.tool.driver.name.clone()
        };
        let scanner_id = scanner_override
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| slugify(&scanner_name));
        for (result_index, result) in run.results.iter().enumerate() {
            let descriptor = descriptor_for(run, result_index, result);
            let rule_id = result
                .rule_id
                .clone()
                .or_else(|| result.rule.as_ref().and_then(|rule| rule.id.clone()))
                .or_else(|| descriptor.and_then(|item| non_empty(&item.id)))
                .unwrap_or_else(|| "unknown-rule".to_string());
            let severity = result_severity(result, descriptor);
            let message_text = result.message.as_text().unwrap_or_else(|| rule_id.clone());
            let message = SecretRedactor::redact_text(&message_text);
            let title = descriptor
                .and_then(|item| {
                    item.short_description
                        .as_ref()
                        .and_then(|message| message.as_text())
                })
                .or_else(|| descriptor.and_then(|item| item.name.clone()))
                .unwrap_or_else(|| first_line(&message));
            let location = result
                .locations
                .first()
                .map(|location| parse_location(run, workspace_root, location))
                .unwrap_or_else(unknown_location);
            let related_locations = result
                .related_locations
                .iter()
                .map(|location| parse_location(run, workspace_root, location))
                .collect::<Vec<_>>();
            let code_flows = result
                .code_flows
                .iter()
                .map(|flow| parse_code_flow(run, workspace_root, flow))
                .collect::<Vec<_>>();
            let fixes = result
                .fixes
                .iter()
                .map(|fix| parse_fix(run, workspace_root, fix))
                .collect::<Vec<_>>();
            let mut cwe = extract_cwes(result, descriptor);
            for taxon in &result.taxa {
                if let Some(id) = &taxon.id {
                    collect_cwes_from_text(id, &mut cwe);
                }
            }
            cwe.sort();
            cwe.dedup();
            let taxa = parse_taxa(result);
            let native_fingerprint = native_fingerprint(result);
            let raw_sarif =
                SecretRedactor::redact_json(&serde_json::to_value(result).unwrap_or(Value::Null));
            let category = classify(&scanner_id, &rule_id, &message, descriptor);
            let mut finding = Finding {
                id: Uuid::new_v4().to_string(),
                scan_run_id: scan_run_id.to_string(),
                project_id: project_id.to_string(),
                scanner_id: scanner_id.clone(),
                scanner_name: scanner_name.clone(),
                rule_id,
                title: SecretRedactor::redact_text(&title),
                message,
                severity,
                category,
                location,
                related_locations,
                code_flows,
                fixes,
                taxa,
                cwe,
                status: FindingStatus::New,
                triage_note: None,
                native_fingerprint,
                workspace_fingerprint: String::new(),
                raw_sarif,
                provenance: FindingProvenance {
                    scanner_id: scanner_id.clone(),
                    scanner_name: scanner_name.clone(),
                    scanner_version: run
                        .tool
                        .driver
                        .semantic_version
                        .clone()
                        .or_else(|| run.tool.driver.version.clone()),
                    source: if scanner_override.is_some() {
                        "generated"
                    } else {
                        "imported"
                    }
                    .into(),
                    source_format: if result
                        .properties
                        .get("source")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.contains("JSON compatibility"))
                    {
                        "json-adapter"
                    } else {
                        "sarif-2.1.0"
                    }
                    .into(),
                    scan_run_id: scan_run_id.into(),
                    result_metadata_hash: crate::fingerprint::hash_parts(&[
                        &SecretRedactor::redact_json(&result.properties).to_string(),
                    ]),
                    rule_metadata_hash: crate::fingerprint::hash_parts(&[&serde_json::to_string(
                        &descriptor,
                    )?]),
                    ..Default::default()
                },
                raw_reference: Some(RawReference {
                    artifact_id: String::new(),
                    run_index,
                    result_index,
                }),
                ..Default::default()
            };
            let fingerprints = FingerprintEngine::for_finding(&finding);
            finding.native_fingerprint = fingerprints.native;
            finding.workspace_fingerprint = fingerprints.workspace;
            finding.fingerprints = crate::fingerprint::structured(&finding);
            if !sources.contains_key(&finding.location.file_path) {
                if sources.len() >= 16 {
                    sources.clear();
                }
                let project = crate::security_ir::Project {
                    path: workspace_root.to_string_lossy().into(),
                    ..Default::default()
                };
                let source = crate::workspace::read_source_file(
                    &project,
                    &finding.location.file_path,
                    2 * 1024 * 1024,
                )
                .ok();
                sources.insert(
                    finding.location.file_path.clone(),
                    source.map(|source| {
                        source
                            .content
                            .lines()
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    }),
                );
            }
            if let Some(Some(source)) = sources.get(&finding.location.file_path) {
                finding.fingerprints.context =
                    crate::fingerprint::context_from_lines(&finding, source);
            }
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn descriptor_for<'a>(
    run: &'a SarifRun,
    _result_index: usize,
    result: &SarifResult,
) -> Option<&'a SarifReportingDescriptor> {
    let index = result
        .rule_index
        .or_else(|| result.rule.as_ref().and_then(|rule| rule.index));
    if let Some(index) = index {
        if let Some(rule) = run.tool.driver.rules.get(index) {
            return Some(rule);
        }
    }
    result
        .rule_id
        .as_ref()
        .or_else(|| result.rule.as_ref().and_then(|rule| rule.id.as_ref()))
        .and_then(|id| run.tool.driver.rules.iter().find(|rule| &rule.id == id))
}

fn parse_location(run: &SarifRun, workspace_root: &Path, location: &SarifLocation) -> Location {
    let physical = location.physical_location.as_ref();
    let artifact_uri = physical
        .and_then(|item| item.artifact_location.as_ref())
        .map(|artifact| resolve_artifact_uri(run, artifact))
        .unwrap_or_else(|| "unknown".to_string());
    let mapped = map_artifact_uri(workspace_root, &artifact_uri);
    let (file_path, absolute_path) = match mapped {
        Ok(path) => (
            relative_display(workspace_root, &path),
            Some(path.to_string_lossy().to_string()),
        ),
        Err(_) => (artifact_uri.replace('\\', "/"), None),
    };
    let region = physical
        .and_then(|item| item.region.as_ref())
        .map(parse_region)
        .unwrap_or_else(|| parse_region(&SarifRegion::default()));
    Location {
        file_path,
        absolute_path,
        message: location
            .message
            .as_ref()
            .and_then(|message| message.as_text())
            .map(|text| SecretRedactor::redact_text(&text)),
        region,
        logical_locations: location
            .logical_locations
            .iter()
            .filter_map(|logical| {
                logical
                    .fully_qualified_name
                    .clone()
                    .or_else(|| logical.name.clone())
                    .or_else(|| logical.decorated_name.clone())
            })
            .collect(),
    }
}

fn resolve_artifact_uri(run: &SarifRun, artifact: &SarifArtifactLocation) -> String {
    let direct = if let Some(index) = artifact.index {
        run.artifacts
            .get(index)
            .and_then(|item| item.location.as_ref())
            .and_then(|location| location.uri.clone())
    } else {
        None
    };
    let uri = artifact
        .uri
        .clone()
        .or(direct)
        .unwrap_or_else(|| "unknown".into());
    if uri == "unknown" {
        return uri;
    }
    if let Some(base_id) = &artifact.uri_base_id {
        if let Some(base) = run.original_uri_base_ids.get(base_id) {
            if let Some(base_uri) = &base.uri {
                if !base_uri.trim().is_empty() {
                    return PathBuf::from(base_uri)
                        .join(uri)
                        .to_string_lossy()
                        .replace('\\', "/");
                }
            }
        }
    }
    uri
}

fn parse_region(region: &SarifRegion) -> Region {
    let start_line = region.start_line.unwrap_or(1).max(1);
    Region {
        start_line,
        start_column: region.start_column.unwrap_or(1).max(1),
        end_line: region.end_line.unwrap_or(start_line).max(start_line),
        end_column: region.end_column.unwrap_or(1).max(1),
        snippet: region
            .snippet
            .as_ref()
            .and_then(|snippet| snippet.text.clone())
            .map(|text| SecretRedactor::redact_text(&text)),
    }
}

// SARIF kinds are a set, not a priority list. Conflicting roles stay unknown.
fn trace_kind(kinds: &[String]) -> TraceStepKind {
    let mut role = TraceStepKind::Unknown;
    for kind in kinds {
        let next = match kind.as_str() {
            "source" => TraceStepKind::Source,
            "propagation" => TraceStepKind::Propagation,
            "sanitizer" => TraceStepKind::Sanitizer,
            "sink" => TraceStepKind::Sink,
            "call" => TraceStepKind::Call,
            "return" => TraceStepKind::Return,
            _ => continue,
        };
        if role != TraceStepKind::Unknown && role != next {
            return TraceStepKind::Unknown;
        }
        role = next;
    }
    role
}

fn parse_code_flow(run: &SarifRun, workspace_root: &Path, flow: &SarifCodeFlow) -> CodeFlow {
    CodeFlow {
        message: flow
            .message
            .as_ref()
            .and_then(|message| message.as_text())
            .map(|text| SecretRedactor::redact_text(&text)),
        thread_flows: flow
            .thread_flows
            .iter()
            .map(|thread| ThreadFlow {
                id: thread.id.clone(),
                message: thread
                    .message
                    .as_ref()
                    .and_then(|message| message.as_text())
                    .map(|text| SecretRedactor::redact_text(&text)),
                steps: thread
                    .locations
                    .iter()
                    .enumerate()
                    .map(|(index, step)| {
                        let location = step
                            .location
                            .as_ref()
                            .map(|value| parse_location(run, workspace_root, value))
                            .unwrap_or_else(unknown_location);
                        let label = step
                            .kinds
                            .first()
                            .cloned()
                            .or_else(|| {
                                step.location
                                    .as_ref()
                                    .and_then(|value| value.message.as_ref())
                                    .and_then(|message| message.as_text())
                            })
                            .unwrap_or_else(|| format!("Step {}", index + 1));
                        TraceStep {
                            kind: trace_kind(&step.kinds),
                            index: index + 1,
                            label: humanize_label(&label),
                            message: location.message.clone(),
                            location,
                            nesting_level: step.nesting_level.unwrap_or_default(),
                        }
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn parse_fix(run: &SarifRun, workspace_root: &Path, fix: &SarifFix) -> Fix {
    Fix {
        description: fix
            .description
            .as_ref()
            .and_then(|message| message.as_text())
            .map(|text| SecretRedactor::redact_text(&text)),
        replacements: fix
            .artifact_changes
            .iter()
            .flat_map(|change| {
                let location = resolve_artifact_uri(run, &change.artifact_location);
                let mapped = map_artifact_uri(workspace_root, &location)
                    .map(|path| relative_display(workspace_root, &path))
                    .unwrap_or_else(|_| location.replace('\\', "/"));
                change
                    .replacements
                    .iter()
                    .map(move |replacement| FixReplacement {
                        file_path: mapped.clone(),
                        deleted_region: parse_region(&replacement.deleted_region),
                        inserted_content: replacement
                            .inserted_content
                            .as_ref()
                            .and_then(|content| content.text.clone())
                            .map(|text| SecretRedactor::redact_text(&text)),
                    })
            })
            .collect(),
    }
}

fn parse_taxa(result: &SarifResult) -> Vec<Taxonomy> {
    result
        .taxa
        .iter()
        .filter_map(|taxon| {
            taxon.id.as_ref().map(|id| Taxonomy {
                id: id.clone(),
                name: None,
                short_description: None,
            })
        })
        .collect()
}

fn extract_cwes(
    result: &SarifResult,
    descriptor: Option<&SarifReportingDescriptor>,
) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(properties) = result.properties.as_object() {
        collect_cwes_from_value(&Value::Object(properties.clone()), &mut values);
    }
    if let Some(descriptor) = descriptor {
        collect_cwes_from_value(&descriptor.properties, &mut values);
        if let Some(tags) = descriptor.properties.get("tags").and_then(Value::as_array) {
            for tag in tags {
                if let Some(tag) = tag.as_str() {
                    collect_cwes_from_text(tag, &mut values);
                }
            }
        }
    }
    collect_cwes_from_text(
        &result.message.text.clone().unwrap_or_default(),
        &mut values,
    );
    values.sort();
    values.dedup();
    values
}

fn collect_cwes_from_value(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(text) => collect_cwes_from_text(text, output),
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_cwes_from_value(item, output)),
        Value::Object(map) => map
            .values()
            .for_each(|item| collect_cwes_from_value(item, output)),
        _ => {}
    }
}

fn collect_cwes_from_text(text: &str, output: &mut Vec<String>) {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pattern =
        PATTERN.get_or_init(|| Regex::new(r"(?i)CWE[-_: ]?(\d{1,5})").expect("CWE regex"));
    for captures in pattern.captures_iter(text) {
        if let Some(number) = captures.get(1) {
            output.push(format!("CWE-{}", number.as_str()));
        }
    }
}

fn result_severity(
    result: &SarifResult,
    descriptor: Option<&SarifReportingDescriptor>,
) -> Severity {
    let security_severity = result
        .properties
        .get("security-severity")
        .or_else(|| result.properties.get("securitySeverity"))
        .or_else(|| {
            descriptor.and_then(|rule| {
                rule.properties
                    .get("security-severity")
                    .or_else(|| rule.properties.get("securitySeverity"))
            })
        });
    if let Some(value) = security_severity {
        let score = value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()));
        if let Some(score) = score {
            return match score {
                score if score >= 9.0 => Severity::Critical,
                score if score >= 7.0 => Severity::High,
                score if score >= 4.0 => Severity::Medium,
                score if score > 0.0 => Severity::Low,
                _ => Severity::Info,
            };
        }
    }
    match result
        .level
        .as_deref()
        .or_else(|| {
            descriptor.and_then(|rule| rule.default_configuration.as_ref()?.level.as_deref())
        })
        .unwrap_or("warning")
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" | "none" => Severity::Low,
        _ => Severity::Info,
    }
}

fn classify(
    scanner_id: &str,
    rule_id: &str,
    message: &str,
    descriptor: Option<&SarifReportingDescriptor>,
) -> FindingCategory {
    let mut haystack = format!("{scanner_id} {rule_id} {message}").to_ascii_lowercase();
    if let Some(descriptor) = descriptor {
        haystack.push(' ');
        haystack.push_str(&descriptor.properties.to_string().to_ascii_lowercase());
    }
    if contains_any(
        &haystack,
        &["secret", "credential", "trufflehog", "api key"],
    ) {
        FindingCategory::Secrets
    } else if contains_any(&haystack, &["license", "spdx"]) {
        FindingCategory::License
    } else if contains_any(&haystack, &["container", "docker", "image"]) {
        FindingCategory::Container
    } else if contains_any(
        &haystack,
        &[
            "iac",
            "terraform",
            "kubernetes",
            "misconfig",
            "configuration",
        ],
    ) {
        FindingCategory::Iac
    } else if contains_any(
        &haystack,
        &["dependency", "vulnerab", "package", "cve", "trivy"],
    ) {
        FindingCategory::Sca
    } else if contains_any(
        &haystack,
        &[
            "injection",
            "xss",
            "sast",
            "semgrep",
            "bandit",
            "deserial",
            "path traversal",
        ],
    ) {
        FindingCategory::Sast
    } else if contains_any(&haystack, &["misconfiguration"]) {
        FindingCategory::Misconfiguration
    } else {
        FindingCategory::Unknown
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn unknown_location() -> Location {
    Location {
        file_path: "unknown".into(),
        absolute_path: None,
        message: None,
        region: Region {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            snippet: None,
        },
        logical_locations: Vec::new(),
    }
}

pub(crate) fn slugify(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn non_empty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.to_string())
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .next()
        .unwrap_or(value)
        .chars()
        .take(180)
        .collect()
}

fn humanize_label(value: &str) -> String {
    value
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn native_fingerprint(result: &SarifResult) -> Option<String> {
    // HashMap iteration must never decide identity. Prefer full fingerprints and sort keys.
    let native_map = if result.fingerprints.is_empty() {
        &result.partial_fingerprints
    } else {
        &result.fingerprints
    };
    let mut native_entries = native_map.iter().collect::<Vec<_>>();
    native_entries.sort_by_key(|(key, _)| *key);
    if native_entries.is_empty() {
        None
    } else {
        Some(crate::fingerprint::hash_parts(
            &native_entries
                .iter()
                .flat_map(|(key, value)| [key.as_str(), value.as_str()])
                .collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::parse_sarif;

    fn parse(input: &str) -> SarifLog {
        parse_sarif(input).expect("valid fixture")
    }

    #[test]
    fn trace_kind_requires_unambiguous_explicit_evidence() {
        assert_eq!(
            trace_kind(&["taint".into(), "source".into()]),
            TraceStepKind::Source
        );
        assert_eq!(
            trace_kind(&["source".into(), "sink".into()]),
            TraceStepKind::Unknown
        );
        assert_eq!(
            trace_kind(&["user input reaches sink".into()]),
            TraceStepKind::Unknown
        );
    }

    #[test]
    fn resolves_rule_by_index_and_location() {
        let log = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","rules":[{"id":"js.sql","shortDescription":{"text":"SQL injection"},"properties":{"tags":["CWE-89","security"]}}]}},"results":[{"ruleIndex":0,"level":"error","message":{"text":"Unsanitized input"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/api/user.ts"},"region":{"startLine":82,"startColumn":3,"endLine":82,"endColumn":20}}}]}]}]}"#,
        );
        let findings = normalize_log(&log, Path::new("."), "project", "run").expect("normalized");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "js.sql");
        assert_eq!(findings[0].title, "SQL injection");
        assert_eq!(findings[0].cwe, vec!["CWE-89"]);
        assert_eq!(findings[0].location.file_path, "src/api/user.ts");
        assert_eq!(findings[0].location.region.start_line, 82);
    }

    #[test]
    fn parses_code_flow_steps() {
        let log = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Demo"}},"results":[{"ruleId":"flow.rule","message":{"text":"Flow"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.ts"},"region":{"startLine":5}}}],"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/a.ts"},"region":{"startLine":1}}},"kinds":["source"]},{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/a.ts"},"region":{"startLine":5}}},"kinds":["sink"]}]}]}]}]}]}"#,
        );
        let findings = normalize_log(&log, Path::new("."), "project", "run").expect("normalized");
        assert_eq!(findings[0].code_flows[0].thread_flows[0].steps.len(), 2);
        assert_eq!(
            findings[0].code_flows[0].thread_flows[0].steps[0].label,
            "Source"
        );
    }

    #[test]
    fn handles_multiple_runs() {
        let log = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"One"}},"results":[{"ruleId":"a","message":{"text":"a"}}]},{"tool":{"driver":{"name":"Two"}},"results":[{"ruleId":"b","message":{"text":"b"}}]}]}"#,
        );
        let findings = normalize_log(&log, Path::new("."), "project", "run").expect("normalized");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].scanner_name, "One");
        assert_eq!(findings[1].scanner_name, "Two");
    }

    #[test]
    fn redacts_imported_secret_content() {
        let log = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"TruffleHog"}},"results":[{"ruleId":"secret","message":{"text":"Found token AKIA1234567890ABCDEF"},"properties":{"api_token":"ABC123"}}]}]}"#,
        );
        let findings = normalize_log(&log, Path::new("."), "project", "run").expect("normalized");
        assert!(!findings[0].message.contains("AKIA1234567890ABCDEF"));
        let masked = findings[0].raw_sarif["properties"]["api_token"]
            .as_str()
            .expect("masked string");
        assert!(masked.starts_with("••••••••"));
        assert!(!masked.contains("ABC123"));
    }
}
