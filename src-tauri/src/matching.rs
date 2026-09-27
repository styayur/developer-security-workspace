//! Conservative, one-to-one matching. Ambiguity is evidence against automatic inheritance.
use crate::security_ir::*;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Candidate {
    pub id: String,
    pub scan_run_id: String,
    pub scanner_id: String,
    pub rule_id: String,
    pub fingerprints: FindingFingerprints,
    pub symbols: Vec<String>,
    pub signature: String,
}
impl Candidate {
    pub fn from_finding(f: &Finding) -> Self {
        let flows = f
            .code_flows
            .iter()
            .flat_map(|flow| &flow.thread_flows)
            .map(|thread| {
                thread
                    .steps
                    .iter()
                    .map(|step| {
                        (
                            &step.kind,
                            &step.location.file_path,
                            &step.location.logical_locations,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let signature = serde_json::json!([
            f.severity,
            crate::fingerprint::normalize_message(&f.message),
            crate::fingerprint::normalize_message(&f.title),
            f.category,
            f.location.file_path,
            f.location.logical_locations,
            f.cwe,
            flows,
            f.provenance.rule_metadata_hash,
            f.provenance.scanner_version,
            f.provenance.result_metadata_hash
        ]);
        Self {
            id: f.id.clone(),
            scan_run_id: f.scan_run_id.clone(),
            scanner_id: f.scanner_id.clone(),
            rule_id: f.rule_id.clone(),
            fingerprints: if f.fingerprints.exact.is_empty() {
                crate::fingerprint::structured(f)
            } else {
                f.fingerprints.clone()
            },
            symbols: f.location.logical_locations.clone(),
            signature: crate::fingerprint::hash_parts(&[&signature.to_string()]),
        }
    }
}

pub struct FindingMatcher;
impl FindingMatcher {
    pub fn match_findings(previous: &[Candidate], current: &[Candidate]) -> Vec<FindingMatch> {
        let mut matches = Vec::new();
        let mut used_previous = HashSet::new();
        let mut used_current = HashSet::new();
        for method in [
            MatchMethod::Native,
            MatchMethod::Exact,
            MatchMethod::Context,
            MatchMethod::Relocated,
        ] {
            let mut before: HashMap<String, Vec<usize>> = HashMap::new();
            let mut after: HashMap<String, Vec<usize>> = HashMap::new();
            for (index, candidate) in previous.iter().enumerate() {
                if !used_previous.contains(&index) {
                    if let Some(key) = key(candidate, &method) {
                        before.entry(key).or_default().push(index);
                    }
                }
            }
            for (index, candidate) in current.iter().enumerate() {
                if !used_current.contains(&index) {
                    if let Some(key) = key(candidate, &method) {
                        after.entry(key).or_default().push(index);
                    }
                }
            }
            // Iterate in input order for a deterministic explanation order.
            for (ci, candidate) in current.iter().enumerate() {
                let Some(key) = key(candidate, &method) else {
                    continue;
                };
                let Some(old) = before.get(&key) else {
                    continue;
                };
                if old.len() != 1 || after.get(&key).is_none_or(|items| items.len() != 1) {
                    continue;
                }
                let pi = old[0];
                if used_current.contains(&ci) || used_previous.contains(&pi) {
                    continue;
                }
                let p = &previous[pi];
                if !p.symbols.is_empty()
                    && !candidate.symbols.is_empty()
                    && p.symbols != candidate.symbols
                {
                    continue;
                }
                used_previous.insert(pi);
                used_current.insert(ci);
                matches.push(FindingMatch {
                    previous_finding_id: p.id.clone(),
                    previous_scan_run_id: p.scan_run_id.clone(),
                    current_finding_id: candidate.id.clone(),
                    method: method.clone(),
                    confidence: match method {
                        MatchMethod::Native | MatchMethod::Exact => MatchConfidence::Exact,
                        MatchMethod::Context => MatchConfidence::Strong,
                        MatchMethod::Relocated => MatchConfidence::Weak,
                    },
                });
            }
        }
        matches
    }
}

fn key(candidate: &Candidate, method: &MatchMethod) -> Option<String> {
    let value = match method {
        MatchMethod::Native => candidate.fingerprints.native.as_deref(),
        MatchMethod::Exact => Some(candidate.fingerprints.exact.as_str()),
        MatchMethod::Context => candidate.fingerprints.context.as_deref(),
        MatchMethod::Relocated => candidate.fingerprints.semantic.as_deref(),
    }?;
    if value.is_empty() {
        return None;
    }
    Some(crate::fingerprint::hash_parts(&[
        &candidate.scanner_id,
        &candidate.rule_id,
        value,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(id: &str, context: &str) -> Candidate {
        Candidate {
            id: id.into(),
            scanner_id: "test".into(),
            rule_id: "rule".into(),
            fingerprints: FindingFingerprints {
                exact: "same".into(),
                context: Some(context.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
    #[test]
    fn collisions_are_never_merged_and_context_disambiguates() {
        let old = [candidate("a", "first"), candidate("b", "second")];
        let new = [candidate("c", "second"), candidate("d", "first")];
        let matched = FindingMatcher::match_findings(&old, &new);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].previous_finding_id, "b");
        assert_eq!(matched[0].method, MatchMethod::Context);
        assert!(FindingMatcher::match_findings(
            &[candidate("a", "same"), candidate("b", "same")],
            &[candidate("c", "same")]
        )
        .is_empty());
    }
    #[test]
    fn different_rule_or_function_is_not_identity() {
        let old = candidate("a", "same");
        let mut new = candidate("b", "same");
        new.rule_id = "other".into();
        assert!(FindingMatcher::match_findings(std::slice::from_ref(&old), &[new]).is_empty());
        let mut old = old;
        old.symbols = vec!["first".into()];
        let mut new = candidate("c", "same");
        new.symbols = vec!["second".into()];
        assert!(FindingMatcher::match_findings(&[old], &[new]).is_empty());
    }
}
