use crate::security_ir::Finding;
use blake3::Hasher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintPair {
    pub native: Option<String>,
    pub workspace: String,
}

pub struct FingerprintEngine;

impl FingerprintEngine {
    pub fn for_finding(finding: &Finding) -> FingerprintPair {
        let workspace = Self::workspace_fingerprint(
            &finding.scanner_id,
            &finding.rule_id,
            &finding.location.file_path,
            &finding.message,
            finding.location.region.start_line,
        );
        FingerprintPair {
            native: finding.native_fingerprint.clone(),
            workspace,
        }
    }

    pub fn workspace_fingerprint(
        scanner_id: &str,
        rule_id: &str,
        file_path: &str,
        message: &str,
        _line: u32,
    ) -> String {
        let mut hasher = Hasher::new();
        for value in [
            normalize_slug(scanner_id),
            normalize_slug(rule_id),
            normalize_path(file_path),
            normalize_message(message),
        ] {
            hasher.update(value.as_bytes());
            hasher.update(b"\0");
        }
        hasher.finalize().to_hex().to_string()
    }
}

fn normalize_slug(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}

fn normalize_message(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut in_digit = false;
    for character in value.chars() {
        if character.is_ascii_digit() {
            if !in_digit {
                output.push('#');
                in_digit = true;
            }
        } else {
            in_digit = false;
            if character.is_whitespace() || "[](){}:;,'\"".contains(character) {
                if !output.ends_with(' ') {
                    output.push(' ');
                }
            } else {
                output.push(character.to_ascii_lowercase());
            }
        }
    }
    output.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_changes_do_not_change_fingerprint() {
        let first = FingerprintEngine::workspace_fingerprint(
            "semgrep",
            "rule.a",
            "src/a.ts",
            "Use of SQL query",
            10,
        );
        let second = FingerprintEngine::workspace_fingerprint(
            "semgrep",
            "rule.a",
            "src/a.ts",
            "Use of SQL query",
            40,
        );
        assert_eq!(first, second);
    }

    #[test]
    fn rule_changes_do_change_fingerprint() {
        let first = FingerprintEngine::workspace_fingerprint(
            "semgrep", "rule.a", "src/a.ts", "message", 10,
        );
        let second = FingerprintEngine::workspace_fingerprint(
            "semgrep", "rule.b", "src/a.ts", "message", 10,
        );
        assert_ne!(first, second);
    }

    #[test]
    fn file_changes_do_change_fingerprint() {
        let first = FingerprintEngine::workspace_fingerprint(
            "semgrep", "rule.a", "src/a.ts", "message", 10,
        );
        let second = FingerprintEngine::workspace_fingerprint(
            "semgrep", "rule.a", "src/b.ts", "message", 10,
        );
        assert_ne!(first, second);
    }

    #[test]
    fn small_message_changes_are_normalized() {
        let first = FingerprintEngine::workspace_fingerprint(
            "semgrep",
            "rule.a",
            "src/a.ts",
            "Finding in line 10",
            10,
        );
        let second = FingerprintEngine::workspace_fingerprint(
            "semgrep",
            "rule.a",
            "src/a.ts",
            "Finding in line 42",
            42,
        );
        assert_eq!(first, second);
    }
}
