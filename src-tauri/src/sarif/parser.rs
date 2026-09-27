use crate::error::{AppError, AppResult};
use crate::sarif::model::SarifLog;

pub const MAX_SARIF_BYTES: usize = 128 * 1024 * 1024;

pub fn parse_sarif(input: &str) -> AppResult<SarifLog> {
    if input.len() > MAX_SARIF_BYTES {
        return Err(AppError::Sarif(
            "SARIF exceeds the 128 MiB import limit.".into(),
        ));
    }
    if input.trim().is_empty() {
        return Err(AppError::Sarif("The file is empty.".into()));
    }
    let log: SarifLog = serde_json::from_str(input)
        .map_err(|error| AppError::Sarif(format!("Invalid JSON or SARIF structure: {error}")))?;
    if log.version.trim() != "2.1.0" {
        return Err(AppError::Sarif(format!(
            "Unsupported SARIF version '{}'. This preview supports SARIF 2.1.0.",
            log.version
        )));
    }
    if log.runs.is_empty() {
        return Err(AppError::Sarif(
            "The SARIF document does not contain any runs.".into(),
        ));
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_log() {
        let log =
            parse_sarif(r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo"}}}]}"#)
                .expect("valid log");
        assert_eq!(log.runs[0].tool.driver.name, "demo");
    }

    #[test]
    fn rejects_unsupported_version() {
        let error = parse_sarif(r#"{"version":"2.0.0","runs":[]}"#).unwrap_err();
        assert!(error.to_string().contains("Unsupported"));
    }

    #[test]
    fn rejects_empty_runs() {
        let error = parse_sarif(r#"{"version":"2.1.0","runs":[]}"#).unwrap_err();
        assert!(error.to_string().contains("does not contain"));
    }
}
