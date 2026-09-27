use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

pub struct SecretRedactor;

impl SecretRedactor {
    pub fn redact_text(input: &str) -> String {
        let mut output = input.to_string();
        for pattern in patterns() {
            output = pattern
                .replace_all(&output, |captures: &regex::Captures<'_>| {
                    let prefix = captures
                        .get(1)
                        .map(|value| value.as_str())
                        .unwrap_or_default();
                    format!("{prefix}{}", mask(""))
                })
                .to_string();
        }
        output
    }

    pub fn redact_json(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut next = serde_json::Map::with_capacity(map.len());
                for (key, item) in map {
                    if is_secret_key(key) {
                        next.insert(key.clone(), Value::String(mask_value(item)));
                    } else {
                        next.insert(key.clone(), Self::redact_json(item));
                    }
                }
                Value::Object(next)
            }
            Value::Array(items) => Value::Array(items.iter().map(Self::redact_json).collect()),
            Value::String(text) => Value::String(Self::redact_text(text)),
            _ => value.clone(),
        }
    }
}

fn patterns() -> &'static Vec<Regex> {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)\b(AKIA|ASIA)[A-Z0-9]{16}\b").expect("AWS key regex"),
            Regex::new(r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,})\b").expect("GitHub token regex"),
            Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}").expect("Bearer regex"),
            Regex::new(
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            )
            .expect("private key regex"),
            Regex::new(r"(?i)\b(?:xox[baprs]-[A-Za-z0-9-]{10,})\b").expect("Slack token regex"),
        ]
    })
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "token",
        "private_key",
        "client_secret",
        "raw",
    ]
    .iter()
    .any(|part| normalized.contains(part))
}

fn mask_value(value: &Value) -> String {
    match value {
        Value::String(text) => mask(text),
        _ => "••••••••".into(),
    }
}

fn mask(value: &str) -> String {
    let visible = value.chars().count().min(8);
    let suffix: String = value
        .chars()
        .rev()
        .take(visible.saturating_sub(4))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if suffix.is_empty() {
        "••••••••".into()
    } else {
        format!("••••••••{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_obvious_aws_key() {
        let input = "key=AKIA1234567890ABCDEF";
        let output = SecretRedactor::redact_text(input);
        assert!(!output.contains("AKIA1234567890ABCDEF"));
        assert!(output.contains('•'));
    }

    #[test]
    fn redacts_secret_properties_recursively() {
        let value = json!({"properties": {"api_token": "something-sensitive", "note": "safe"}});
        let output = SecretRedactor::redact_json(&value);
        let masked = output["properties"]["api_token"]
            .as_str()
            .expect("masked string");
        assert!(masked.starts_with("••••••••"));
        assert!(!masked.contains("something-sensitive"));
        assert_eq!(output["properties"]["note"], json!("safe"));
    }
}
