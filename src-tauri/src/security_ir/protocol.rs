use serde::{Deserialize, Serialize};

pub const SECURITY_IR_VERSION: u32 = 1;
pub fn security_ir_version() -> u32 {
    SECURITY_IR_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FindingProvenance {
    pub scanner_id: String,
    pub scanner_name: String,
    pub scanner_version: Option<String>,
    pub adapter_version: String,
    pub source_format: String,
    pub security_ir_version: u32,
    pub source: String,
    pub scan_run_id: String,
    pub rule_metadata_hash: String,
    pub result_metadata_hash: String,
}
impl Default for FindingProvenance {
    fn default() -> Self {
        Self {
            scanner_id: String::new(),
            scanner_name: String::new(),
            scanner_version: None,
            adapter_version: "1".into(),
            source_format: "sarif-2.1.0".into(),
            security_ir_version: SECURITY_IR_VERSION,
            source: "imported".into(),
            scan_run_id: String::new(),
            rule_metadata_hash: String::new(),
            result_metadata_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FindingFingerprints {
    pub native: Option<String>,
    pub exact: String,
    pub context: Option<String>,
    pub semantic: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceStepKind {
    Source,
    Propagation,
    Sanitizer,
    Sink,
    Call,
    Return,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    #[default]
    New,
    Existing,
    Fixed,
    Reopened,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMethod {
    Native,
    Exact,
    Context,
    Relocated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchConfidence {
    Exact,
    Strong,
    Weak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingMatch {
    pub previous_finding_id: String,
    pub previous_scan_run_id: String,
    pub current_finding_id: String,
    pub method: MatchMethod,
    pub confidence: MatchConfidence,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FindingLifecycle {
    pub identity_id: String,
    pub first_seen: String,
    pub last_seen: String,
    pub occurrence_count: usize,
    pub fixed_at: Option<String>,
    pub reopened_at: Option<String>,
    pub state: DiffClass,
    pub matched_by: Option<FindingMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawReference {
    pub artifact_id: String,
    pub run_index: usize,
    pub result_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingPage {
    pub items: Vec<super::FindingListItem>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_defaults_and_roundtrip() {
        assert_eq!(
            super::super::ScanRun::default().security_ir_version,
            SECURITY_IR_VERSION
        );
        let provenance: FindingProvenance = serde_json::from_str("{}").unwrap();
        assert_eq!(provenance.security_ir_version, SECURITY_IR_VERSION);
        let finding = super::super::Finding {
            provenance,
            ..Default::default()
        };
        let value = serde_json::to_value(&finding).unwrap();
        let roundtrip: super::super::Finding = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
        assert_eq!(
            serde_json::to_string(&TraceStepKind::Unknown).unwrap(),
            "\"unknown\""
        );
    }
}
