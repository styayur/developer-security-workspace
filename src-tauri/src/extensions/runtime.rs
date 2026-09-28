use super::*;
use crate::sarif::SarifLog;
use crate::scanners::{ScanContext, ScannerProvider};
use crate::security_ir::{ScanRequest, ScannerCapabilities};
use async_trait::async_trait;

// v1 deliberately has a small reviewed execution vocabulary. New command profiles need code review.
pub fn validate_profile(manifest: &ExtensionManifest) -> AppResult<()> {
    let expected = [
        "dir",
        "{workspace}",
        "--config",
        "{config}",
        "--no-banner",
        "--redact",
        "--report-format",
        "sarif",
        "--report-path",
        "{output}",
        "--exit-code",
        "0",
    ];
    if manifest.scanner.executable != "gitleaks"
        || manifest.scanner.version_args != ["version"]
        || manifest.scan.args != expected
        || !(1..=900).contains(&manifest.scan.timeout_seconds)
        || !manifest.permissions.workspace_read
        || manifest.permissions.workspace_write
        || manifest.permissions.network
        || manifest.output.format != "sarif"
        || manifest.output.source != "file"
    {
        return Err(AppError::InvalidInput(
            "This manifest has no reviewed offline, read-only execution profile in runtime v1."
                .into(),
        ));
    }
    Ok(())
}

pub struct ExtensionProvider {
    manifest: ExtensionManifest,
}
impl ExtensionProvider {
    pub fn approved(manifest: ExtensionManifest, digest: &str) -> AppResult<Self> {
        validate_profile(&manifest)?;
        if manifest.approval_digest != digest || manifest.resolved_executable.is_none() {
            return Err(AppError::InvalidInput("Review and approve the current manifest and installed executable before running this extension.".into()));
        }
        Ok(Self { manifest })
    }
}

#[async_trait]
impl ScannerProvider for ExtensionProvider {
    fn id(&self) -> &str {
        &self.manifest.id
    }
    fn display_name(&self) -> &str {
        &self.manifest.name
    }
    fn capabilities(&self) -> ScannerCapabilities {
        self.manifest.capabilities.clone()
    }
    fn license(&self) -> &'static str {
        "MIT (external Gitleaks runtime)"
    }
    fn project_url(&self) -> &'static str {
        "https://github.com/gitleaks/gitleaks"
    }
    fn install_command(&self) -> &'static str {
        "Install Gitleaks explicitly and review its license."
    }
    fn description(&self) -> &'static str {
        "Approved declarative SARIF scanner"
    }
    fn known_commands(&self) -> &'static [&'static str] {
        &["gitleaks"]
    }
    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.manifest.scan.timeout_seconds)
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["version"]
    }
    async fn scan(&self, request: &ScanRequest, context: &ScanContext) -> AppResult<Vec<SarifLog>> {
        validate_profile(&self.manifest)?;
        if request.mode != "full" {
            return Err(AppError::InvalidInput(
                "Extension v1 supports full scans only.".into(),
            ));
        }
        let temp = tempfile::Builder::new()
            .prefix("dsw-extension-")
            .tempdir()?;
        let output = temp.path().join("results.sarif");
        let config = temp.path().join("gitleaks.toml");
        // Gitleaks also discovers configuration in the target directory, independent
        // of cwd. Pin the built-in rules explicitly; no workspace or remote config.
        std::fs::write(
            &config,
            "title = 'DSW reviewed defaults'\n[extend]\nuseDefault = true\n",
        )?;
        let args = self
            .manifest
            .scan
            .args
            .iter()
            .map(|arg| match arg.as_str() {
                "{workspace}" => request.workspace_root.clone(),
                "{output}" => output.to_string_lossy().to_string(),
                "{config}" => config.to_string_lossy().to_string(),
                _ => arg.clone(),
            })
            .collect::<Vec<_>>();
        let executable = self
            .manifest
            .resolved_executable
            .as_deref()
            .ok_or_else(|| AppError::Scanner("Gitleaks is not installed.".into()))?;
        // Isolated working directory keeps output and ignore-file discovery separate.
        let result = crate::process::run_command(
            Path::new(executable),
            &args,
            temp.path(),
            context.cancel.clone(),
            context.logs.clone(),
        )
        .await?;
        if !result.success {
            return Err(AppError::Scanner(format!(
                "Extension failed with exit {:?}: {}",
                result.status_code, result.stderr
            )));
        }
        Ok(vec![crate::scanners::parse_sarif_file(&output)?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires explicitly installed Gitleaks on PATH"]
    async fn real_gitleaks_extension_smoke() {
        let workspace = tempfile::tempdir().unwrap();
        let secret = ["ghp_", "7RbK9mPx2VnQ5cFd8HsJ3wZa6YeL4tUo1GiN"].concat();
        let source = format!("github_token = \"{secret}\"\n");
        let input = workspace.path().join("sample.env");
        std::fs::write(&input, &source).unwrap();
        // A workspace config must not replace the reviewed scanner profile.
        let config =
            "title = 'untrusted workspace'\n[[rules]]\nid = 'never'\nregex = 'WILL_NOT_MATCH'\n";
        std::fs::write(workspace.path().join(".gitleaks.toml"), config).unwrap();
        let manifest = builtin_manifests().unwrap().remove(0);
        assert!(
            manifest.resolved_executable.is_some(),
            "Install Gitleaks explicitly first"
        );
        let provider =
            ExtensionProvider::approved(manifest.clone(), &manifest.approval_digest).unwrap();
        let logs = provider
            .scan(
                &ScanRequest {
                    workspace_root: workspace.path().to_string_lossy().into(),
                    ..Default::default()
                },
                &ScanContext::default(),
            )
            .await
            .unwrap();
        let findings =
            crate::sarif::normalize_log(&logs[0], workspace.path(), "smoke", "run").unwrap();
        assert!(!findings.is_empty());
        assert!(!serde_json::to_string(&findings).unwrap().contains(&secret));
        assert_eq!(std::fs::read_to_string(&input).unwrap(), source);
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".gitleaks.toml")).unwrap(),
            config
        );
        assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 2);
        println!(
            "Gitleaks extension: {} findings; redaction and read-only workspace verified",
            findings.len()
        );
    }
    #[test]
    fn only_reviewed_profile_and_current_approval_can_execute() {
        let mut manifest = builtin_manifests().unwrap().remove(0);
        assert!(validate_profile(&manifest).is_ok());
        assert!(ExtensionProvider::approved(manifest.clone(), "stale").is_err());
        manifest.permissions.workspace_write = true;
        assert!(validate_profile(&manifest).is_err());
        manifest.permissions.workspace_write = false;
        manifest.scan.args.push("--config=evil".into());
        assert!(validate_profile(&manifest).is_err());
    }
    #[test]
    fn rejects_interpreters_expansion_paths_and_unknown_placeholders() {
        for command in [
            "cmd",
            "pwsh",
            "sh",
            "node",
            "python",
            "gitleaks.exe",
            "../gitleaks",
            "x y",
            "x;evil",
        ] {
            assert!(!valid_command(command), "{command}");
        }
        for arg in [
            "$(whoami)",
            "%COMSPEC%",
            "{home}",
            "{workspace}/../outside",
            "--x\nfoo",
        ] {
            assert!(validate_args(&[arg.into()]).is_err(), "{arg}");
        }
    }
}
