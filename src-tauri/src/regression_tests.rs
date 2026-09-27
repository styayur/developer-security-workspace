use crate::{
    fingerprint,
    matching::{Candidate, FindingMatcher},
    sarif,
    security_ir::*,
};
use serde_json::{json, Value};
use std::path::Path;

#[test]
fn ir_golden_normalization_is_deterministic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    let mut snapshots = serde_json::Map::new();
    for name in [
        "sarif/codeflow-example.sarif",
        "sarif/multi-run-example.sarif",
        "sarif/semgrep-example.sarif",
        "sarif/trivy-example.sarif",
        "sarif/trufflehog-example.sarif",
        "ir/partial.sarif",
        "ir/rich.sarif",
        "ir/bandit.json",
        "ir/trufflehog.jsonl",
    ] {
        let source = std::fs::read_to_string(root.join(name)).unwrap();
        let log = match name {
            "ir/bandit.json" => crate::scanners::bandit::adapt_bandit_json(&source).unwrap(),
            "ir/trufflehog.jsonl" => {
                crate::scanners::trufflehog::adapt_trufflehog_json(&source).unwrap()
            }
            _ => sarif::parse_sarif(&source).unwrap(),
        };
        let normalize = || {
            let findings = sarif::normalize_log(&log, Path::new("."), "project", "run").unwrap();
            findings
                .into_iter()
                .map(|mut f| {
                    f.id = "occurrence".into();
                    f.location.absolute_path = None;
                    for l in &mut f.related_locations {
                        l.absolute_path = None;
                    }
                    for flow in &mut f.code_flows {
                        for thread in &mut flow.thread_flows {
                            for step in &mut thread.steps {
                                step.location.absolute_path = None;
                            }
                        }
                    }
                    f.fingerprints.context = None;
                    serde_json::to_value(f).unwrap()
                })
                .collect::<Vec<_>>()
        };
        let first = normalize();
        assert_eq!(first, normalize(), "{name}");
        snapshots.insert(name.into(), Value::Array(first));
    }
    let actual = Value::Object(snapshots);
    let golden = root.join("ir/normalized.golden.json");
    if std::env::var_os("DSW_UPDATE_GOLDENS").is_some() {
        std::fs::write(
            &golden,
            format!("{}\n", serde_json::to_string_pretty(&actual).unwrap()),
        )
        .unwrap();
    }
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(golden).unwrap()).unwrap();
    assert_eq!(actual, expected);
    assert!(sarif::parse_sarif(include_str!("../../fixtures/ir/malformed.sarif")).is_err());
}

fn finding() -> Finding {
    Finding {
        id: "before".into(),
        scanner_id: "scanner".into(),
        rule_id: "rule".into(),
        message: "Problem on line 10".into(),
        cwe: vec!["CWE-89".into()],
        location: Location {
            file_path: "src/a.ts".into(),
            logical_locations: vec!["handler".into()],
            region: Region {
                start_line: 10,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn identity_regression_corpus() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../fixtures/fingerprint/cases.json")).unwrap();
    for case in cases {
        let mut before = finding();
        before.fingerprints = fingerprint::structured(&before);
        before.fingerprints.context = Some("context".into());
        let mut after = before.clone();
        after.id = "after".into();
        if let Some(delta) = case["lineDelta"].as_i64() {
            after.location.region.start_line = (10 + delta) as u32;
        }
        if let Some(path) = case["path"].as_str() {
            after.location.file_path = path.into();
        }
        if let Some(symbol) = case["symbol"].as_str() {
            after.location.logical_locations = vec![symbol.into()];
        }
        if let Some(rule) = case["rule"].as_str() {
            after.rule_id = rule.into();
        }
        if let Some(message) = case["message"].as_str() {
            after.message = message.into();
        }
        after.fingerprints = fingerprint::structured(&after);
        after.fingerprints.context = Some(case["context"].as_str().unwrap_or("context").into());
        let matches = FindingMatcher::match_findings(
            &[Candidate::from_finding(&before)],
            &[Candidate::from_finding(&after)],
        );
        assert_eq!(
            matches
                .first()
                .map(|m| serde_json::to_value(&m.method).unwrap())
                .unwrap_or(Value::Null),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn windows_slashes_and_unix_case_are_not_conflated() {
    assert_eq!(
        fingerprint::normalize_path("C:\\Repo\\src\\a.ts"),
        fingerprint::normalize_path("c:/repo/src/a.ts")
    );
    assert_eq!(
        fingerprint::normalize_path("src\\a.ts"),
        fingerprint::normalize_path("./src/a.ts")
    );
    assert_ne!(
        fingerprint::normalize_path("src/A.ts"),
        fingerprint::normalize_path("src/a.ts")
    );
    assert_ne!(
        fingerprint::normalize_path("../src/a.ts"),
        fingerprint::normalize_path("src/a.ts")
    );
}

#[test]
fn source_context_is_stable_after_prefix_insertions_and_crlf() {
    let source = (0..20)
        .map(|i| format!("let value{i} = input;\n"))
        .collect::<String>();
    let before = finding();
    let mut after = before.clone();
    after.location.region.start_line += 40;
    let shifted = format!(
        "{}{}",
        "// inserted\r\n".repeat(40),
        source.replace('\n', "\r\n")
    );
    let hash = fingerprint::context_fingerprint(&before, &source);
    assert_eq!(hash, fingerprint::context_fingerprint(&after, &shifted));
    assert!(hash.unwrap().len() == 64);
}

#[test]
fn redaction_never_retains_entire_captured_token() {
    for token in [
        ["ghp_", "a".repeat(30).as_str()].concat(),
        ["xoxb-", "a".repeat(30).as_str()].concat(),
    ] {
        assert!(!crate::secret_redaction::SecretRedactor::redact_text(&token).contains(&token));
        assert!(
            !crate::secret_redaction::SecretRedactor::redact_json(&json!({"message":token}))
                .to_string()
                .contains(&token)
        );
    }
}
