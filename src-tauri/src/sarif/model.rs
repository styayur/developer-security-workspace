use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema", default)]
    pub schema: Option<String>,
    pub version: String,
    #[serde(default)]
    pub runs: Vec<SarifRun>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    #[serde(default)]
    pub artifacts: Vec<SarifArtifact>,
    #[serde(default)]
    pub results: Vec<SarifResult>,
    #[serde(default)]
    pub original_uri_base_ids: std::collections::HashMap<String, SarifArtifactLocation>,
    #[serde(default)]
    pub taxonomies: Vec<SarifToolComponent>,
    #[serde(default)]
    pub column_kind: Option<String>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifToolComponent,
    #[serde(default)]
    pub extensions: Vec<SarifToolComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponent {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub guid: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub semantic_version: Option<String>,
    #[serde(default)]
    pub information_uri: Option<String>,
    #[serde(default)]
    pub rules: Vec<SarifReportingDescriptor>,
    #[serde(default)]
    pub taxa: Vec<SarifReportingDescriptor>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptor {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub short_description: Option<SarifMessage>,
    #[serde(default)]
    pub full_description: Option<SarifMessage>,
    #[serde(default)]
    pub help: Option<SarifMessage>,
    #[serde(default)]
    pub help_uri: Option<String>,
    #[serde(default)]
    pub default_configuration: Option<SarifReportingConfiguration>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingConfiguration {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub rank: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifact {
    #[serde(default)]
    pub location: Option<SarifArtifactLocation>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub description: Option<SarifMessage>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub contents: Option<SarifArtifactContent>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub uri_base_id: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub description: Option<SarifMessage>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactContent {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub binary: Option<String>,
    #[serde(default)]
    pub rendered: Option<SarifMessage>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule_index: Option<usize>,
    #[serde(default)]
    pub rule: Option<SarifReportingDescriptorReference>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub message: SarifMessage,
    #[serde(default)]
    pub locations: Vec<SarifLocation>,
    #[serde(default)]
    pub related_locations: Vec<SarifLocation>,
    #[serde(default)]
    pub code_flows: Vec<SarifCodeFlow>,
    #[serde(default)]
    pub stacks: Vec<SarifStack>,
    #[serde(default)]
    pub fixes: Vec<SarifFix>,
    #[serde(default)]
    pub suppressions: Vec<SarifSuppression>,
    #[serde(default)]
    pub partial_fingerprints: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub fingerprints: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub taxa: Vec<SarifReportingDescriptorReference>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptorReference {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub guid: Option<String>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub properties: Value,
}

impl SarifMessage {
    pub fn as_text(&self) -> Option<String> {
        self.text
            .clone()
            .or_else(|| self.markdown.clone())
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    #[serde(default)]
    pub physical_location: Option<SarifPhysicalLocation>,
    #[serde(default)]
    pub logical_locations: Vec<SarifLogicalLocation>,
    #[serde(default)]
    pub message: Option<SarifMessage>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    #[serde(default)]
    pub artifact_location: Option<SarifArtifactLocation>,
    #[serde(default)]
    pub region: Option<SarifRegion>,
    #[serde(default)]
    pub context_region: Option<SarifRegion>,
    #[serde(default)]
    pub address: Option<SarifAddress>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    #[serde(default)]
    pub start_line: Option<u32>,
    #[serde(default)]
    pub start_column: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub end_column: Option<u32>,
    #[serde(default)]
    pub char_offset: Option<u32>,
    #[serde(default)]
    pub char_length: Option<u32>,
    #[serde(default)]
    pub byte_offset: Option<u32>,
    #[serde(default)]
    pub byte_length: Option<u32>,
    #[serde(default)]
    pub snippet: Option<SarifArtifactContent>,
    #[serde(default)]
    pub message: Option<SarifMessage>,
    #[serde(default)]
    pub source_language: Option<String>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifAddress {
    #[serde(default)]
    pub absolute_address: Option<i64>,
    #[serde(default)]
    pub relative_address: Option<i64>,
    #[serde(default)]
    pub length: Option<i64>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifLogicalLocation {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fully_qualified_name: Option<String>,
    #[serde(default)]
    pub decorated_name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    #[serde(default)]
    pub message: Option<SarifMessage>,
    #[serde(default)]
    pub thread_flows: Vec<SarifThreadFlow>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlow {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub message: Option<SarifMessage>,
    #[serde(default)]
    pub locations: Vec<SarifThreadFlowLocation>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlowLocation {
    #[serde(default)]
    pub location: Option<SarifLocation>,
    #[serde(default)]
    pub stack: Option<SarifStack>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub nesting_level: Option<u32>,
    #[serde(default)]
    pub execution_order: Option<u32>,
    #[serde(default)]
    pub importance: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub state: Value,
    #[serde(default)]
    pub taxa: Vec<SarifReportingDescriptorReference>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifStack {
    #[serde(default)]
    pub message: Option<SarifMessage>,
    #[serde(default)]
    pub frames: Vec<SarifStackFrame>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifStackFrame {
    #[serde(default)]
    pub location: Option<SarifLocation>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub thread_id: Option<i64>,
    #[serde(default)]
    pub parameters: Vec<String>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifFix {
    #[serde(default)]
    pub description: Option<SarifMessage>,
    #[serde(default)]
    pub artifact_changes: Vec<SarifArtifactChange>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactChange {
    pub artifact_location: SarifArtifactLocation,
    #[serde(default)]
    pub replacements: Vec<SarifReplacement>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifReplacement {
    pub deleted_region: SarifRegion,
    #[serde(default)]
    pub inserted_content: Option<SarifArtifactContent>,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SarifSuppression {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub location: Option<SarifLocation>,
    #[serde(default)]
    pub properties: Value,
}
