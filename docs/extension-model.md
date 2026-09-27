# Declarative scanner extensions v1

A manifest describes a scanner invocation, permissions and output. It contains no executable plugin code. The [Gitleaks fixture](../fixtures/extensions/example-gitleaks.toml) is a complete runnable example when Gitleaks is independently installed.

```toml
schema_version = 1
id = "io.example.gitleaks"
name = "Gitleaks"
version = "1.0.0"

[scanner]
executable = "gitleaks"
version_args = ["version"]

[scan]
args = ["dir", "{workspace}", "--no-banner", "--redact", "--report-format", "sarif", "--report-path", "{output}", "--exit-code", "0"]
timeout_seconds = 900

[output]
format = "sarif"
source = "file"

[capabilities]
secrets = true

[permissions]
workspace_read = true
workspace_write = false
network = false

[license]
spdx = "MIT"
bundled = false
```

Place TOML files in the application-data `extensions` directory. Valid manifests are displayed in Extensions; unknown fields in execution/permission configuration fail validation. Duplicate IDs cannot execute. Third-party manifests are always untrusted, including the bundled example metadata.

## Approval and execution

1. Explicitly install a trusted Gitleaks binary on PATH.
2. Open Extensions and Recheck. Review the resolved executable, fixed argument vector, permissions, license and digest.
3. Approve the current manifest and installed binary, then Run extension.
4. Follow progress/cancellation in Scan history. Results enter the same SARIF -> IR -> identity -> SQLite pipeline as built-in providers.

Approval hashes manifest bytes, resolved executable path and binary contents. It is sent only for the chosen invocation and rechecked before launch; it is not a trust designation. Executable identity changes require another review.

## v1 restrictions

- The only executable profile is the exact Gitleaks `dir` vector above, including redaction and a temporary SARIF output file. Command names alone are not a sufficient security policy.
- Native executable names contain only ASCII alphanumerics, hyphen and underscore. Paths, shell/interpreter names and shell expansion/control characters are rejected.
- Argument templates recognize `{workspace}`, `{output}`, `{config}` and `{changed_files}`. Only the first two are executable in the reviewed profile; no recursive expansion or arbitrary environment interpolation occurs.
- Output is SARIF. stdout and custom JSON converters are not enabled in this v1. Built-in trusted Bandit/TruffleHog JSON adapters remain available through their existing providers.
- Timeout must be 1–900 seconds. Changed-files scans and arbitrary extra args/configs are not supported for extensions.
- The profile rejects workspace writes and network permission requests. Output uses a temp directory; the scanner runs there rather than discovering workspace config through its working directory.
- Native binaries still have the user's OS privileges. This runtime does not claim to sandbox hostile binaries. Adding a scanner requires a reviewed invocation profile, tests, and documentation of its filesystem/network behavior.

This restricted executable v1 is intentionally extensible through reviewed profiles without adding an arbitrary script runtime.
