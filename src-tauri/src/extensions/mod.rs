use crate::error::{AppError, AppResult};
use crate::security_ir::{ExtensionLicense, ExtensionManifest, ExtensionOutput, ExtensionScanner};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
struct RawManifest {
    schema_version: u32,
    id: String,
    name: String,
    version: String,
    scanner: RawScanner,
    output: RawOutput,
    capabilities: RawCapabilities,
    license: RawLicense,
}

#[derive(Debug, Clone, Deserialize)]
struct RawScanner {
    executable: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawOutput {
    format: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawCapabilities {
    #[serde(default)]
    sast: bool,
    #[serde(default)]
    secrets: bool,
    #[serde(default)]
    sca: bool,
    #[serde(default)]
    iac: bool,
    #[serde(default)]
    container: bool,
    #[serde(default)]
    licenses: bool,
    #[serde(default)]
    vulnerabilities: bool,
    #[serde(default)]
    misconfiguration: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RawLicense {
    spdx: String,
    #[serde(default)]
    bundled: bool,
}

pub fn builtin_manifests() -> AppResult<Vec<ExtensionManifest>> {
    let source = include_str!("../../../fixtures/extensions/example-gitleaks.toml");
    Ok(vec![parse_manifest(source, None)?])
}

pub fn load_manifests(directory: Option<&Path>) -> AppResult<Vec<ExtensionManifest>> {
    let mut manifests = builtin_manifests()?;
    let Some(directory) = directory else {
        return Ok(manifests);
    };
    if !directory.exists() {
        return Ok(manifests);
    }
    let mut paths = std::fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "toml"))
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let source = std::fs::read_to_string(&path)?;
        match parse_manifest(&source, Some(path.clone())) {
            Ok(manifest) => manifests.push(manifest),
            Err(error) => {
                tracing::warn!(path = %path.display(), error = %error, "extension manifest rejected")
            }
        }
    }
    Ok(manifests)
}

pub fn parse_manifest(source: &str, source_path: Option<PathBuf>) -> AppResult<ExtensionManifest> {
    let raw: RawManifest = toml::from_str(source)
        .map_err(|error| AppError::InvalidInput(format!("Invalid extension manifest: {error}")))?;
    validate(&raw)?;
    Ok(ExtensionManifest {
        schema_version: raw.schema_version,
        id: raw.id,
        name: raw.name,
        version: raw.version,
        scanner: ExtensionScanner {
            executable: raw.scanner.executable,
        },
        output: ExtensionOutput {
            format: raw.output.format,
        },
        capabilities: crate::security_ir::ScannerCapabilities {
            sast: raw.capabilities.sast,
            secrets: raw.capabilities.secrets,
            sca: raw.capabilities.sca,
            iac: raw.capabilities.iac,
            container: raw.capabilities.container,
            licenses: raw.capabilities.licenses,
            vulnerabilities: raw.capabilities.vulnerabilities,
            misconfiguration: raw.capabilities.misconfiguration,
        },
        license: ExtensionLicense {
            spdx: raw.license.spdx,
            bundled: raw.license.bundled,
        },
        trusted: false,
        source_path: source_path.map(|path| path.to_string_lossy().to_string()),
    })
}

fn validate(raw: &RawManifest) -> AppResult<()> {
    if raw.schema_version != 1 {
        return Err(AppError::InvalidInput(
            "Unsupported extension schema version. Expected 1.".into(),
        ));
    }
    if raw.id.trim().is_empty() || !raw.id.contains('.') {
        return Err(AppError::InvalidInput(
            "Extension id must use a reverse-DNS style identifier.".into(),
        ));
    }
    if raw.name.trim().is_empty() || raw.version.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Extension name and version are required.".into(),
        ));
    }
    if raw.scanner.executable.trim().is_empty() || raw.scanner.executable.contains(['/', '\\']) {
        return Err(AppError::InvalidInput(
            "Extension executable must be a command name, not a path or shell expression.".into(),
        ));
    }
    if !matches!(raw.output.format.as_str(), "sarif" | "json") {
        return Err(AppError::InvalidInput(
            "Extension output format must be 'sarif' or 'json'.".into(),
        ));
    }
    if raw.license.spdx.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Extension license SPDX identifier is required.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_builtin_manifest() {
        let manifests = builtin_manifests().expect("builtin");
        assert_eq!(manifests[0].id, "io.example.gitleaks");
        assert!(!manifests[0].trusted);
    }

    #[test]
    fn rejects_shell_expression_executable() {
        let source = include_str!("../../../fixtures/extensions/example-gitleaks.toml");
        let invalid = source.replace(
            "executable = \"gitleaks\"",
            "executable = \"cmd /c gitleaks\"",
        );
        let error = parse_manifest(&invalid, None).unwrap_err();
        assert!(error.to_string().contains("not a path or shell expression"));
    }
}
