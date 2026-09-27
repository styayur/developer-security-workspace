use crate::error::{AppError, AppResult};
use crate::security_ir::{ExtensionLicense, ExtensionManifest, ExtensionOutput, ExtensionScanner};
use serde::Deserialize;
mod runtime;
pub use runtime::ExtensionProvider;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u32,
    id: String,
    name: String,
    version: String,
    scanner: RawScanner,
    #[serde(default)]
    scan: RawScan,
    #[serde(default)]
    permissions: RawPermissions,
    output: RawOutput,
    capabilities: RawCapabilities,
    license: RawLicense,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScanner {
    executable: String,
    #[serde(default)]
    version_args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawOutput {
    format: String,
    #[serde(default)]
    source: String,
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
    let mut manifest = ExtensionManifest {
        scan: crate::security_ir::ExtensionScan {
            args: raw.scan.args,
            timeout_seconds: raw.scan.timeout_seconds,
        },
        permissions: crate::security_ir::ExtensionPermissions {
            workspace_read: raw.permissions.workspace_read,
            workspace_write: raw.permissions.workspace_write,
            network: raw.permissions.network,
        },
        approval_digest: String::new(),
        resolved_executable: None,
        runnable: false,
        schema_version: raw.schema_version,
        id: raw.id,
        name: raw.name,
        version: raw.version,
        scanner: ExtensionScanner {
            executable: raw.scanner.executable,
            version_args: raw.scanner.version_args,
        },
        output: ExtensionOutput {
            format: raw.output.format,
            source: raw.output.source,
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
    };
    manifest.runnable = runtime::validate_profile(&manifest).is_ok();
    if manifest.runnable {
        manifest.resolved_executable = which::which(&manifest.scanner.executable)
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .filter(|p| {
                !cfg!(windows) || p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            })
            .map(|p| p.to_string_lossy().to_string());
    }
    let mut digest = blake3::Hasher::new();
    digest.update(source.as_bytes());
    if let Some(path) = &manifest.resolved_executable {
        use std::io::Read;
        digest.update(path.as_bytes());
        let mut file = std::fs::File::open(path)?;
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
    }
    manifest.approval_digest = digest.finalize().to_hex().to_string();
    Ok(manifest)
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
    if !valid_command(&raw.scanner.executable) {
        return Err(AppError::InvalidInput(
            "Extension executable must be a command name, not a path or shell expression.".into(),
        ));
    }
    if raw.output.format != "sarif" {
        return Err(AppError::InvalidInput(
            "Extension output format must be 'sarif'.".into(),
        ));
    }
    validate_args(&raw.scan.args)?;
    validate_args(&raw.scanner.version_args)?;
    if raw.scan.timeout_seconds > 900 {
        return Err(AppError::InvalidInput(
            "Extension timeout cannot exceed 900 seconds.".into(),
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawScan {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    timeout_seconds: u64,
}
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPermissions {
    #[serde(default)]
    workspace_read: bool,
    #[serde(default)]
    workspace_write: bool,
    #[serde(default)]
    network: bool,
}

fn valid_command(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= 80
        && command.as_bytes()[0].is_ascii_alphanumeric()
        && command
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
        && ![
            "cmd",
            "powershell",
            "pwsh",
            "sh",
            "bash",
            "zsh",
            "python",
            "python3",
            "node",
            "ruby",
            "perl",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
        ]
        .contains(&command.to_ascii_lowercase().as_str())
}
fn validate_args(args: &[String]) -> AppResult<()> {
    if args.len() > 64 {
        return Err(AppError::InvalidInput(
            "Too many extension arguments.".into(),
        ));
    }
    for arg in args {
        if arg.len() > 4096
            || arg.contains("..")
            || arg
                .chars()
                .any(|c| c.is_control() || "$%`|;&<>".contains(c))
        {
            return Err(AppError::InvalidInput(
                "Shell expansion or control characters are not permitted in extension arguments."
                    .into(),
            ));
        }
        let mut remaining = arg.clone();
        for placeholder in ["{workspace}", "{output}", "{config}", "{changed_files}"] {
            remaining = remaining.replace(placeholder, "");
        }
        if remaining.contains(['{', '}']) {
            return Err(AppError::InvalidInput(
                "Unknown extension placeholder.".into(),
            ));
        }
    }
    Ok(())
}
