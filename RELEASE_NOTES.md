# Developer Security Workspace v0.1.0-preview

Local-first SARIF desktop client, vulnerability debugger, and scanner runtime.

## Highlights

- Rust SARIF 2.1.0 parser and unified Security IR
- SQLite scan history, findings, triage, and workspace fingerprints
- Monaco source debugger with SARIF code-flow Trace Player
- New / Existing / Fixed scan diff
- Local-first SARIF import and export
- Secret redaction in findings, raw SARIF, and scanner logs
- Structured scanner process execution with cancellation and log bounds
- Semgrep, Trivy, TruffleHog, and Bandit providers
- Optional user-selected CodeQL runtime
- Metadata-only extension manifest foundation
- Dark, light, and system themes
- No account, telemetry, analytics, or cloud upload

## Real scanner verification

| Scanner | Version | Provider result |
| --- | --- | --- |
| Semgrep | 1.178.0 | Passed, 1 smoke finding |
| Trivy | 0.74.0 | Passed, 12 smoke findings |
| TruffleHog | 3.97.9 | Passed, 2 smoke findings after redaction |
| Bandit | 1.9.4 | Passed, 2 smoke findings |

CodeQL CLI is intentionally not bundled. Users can select and verify their own separately licensed runtime.

## Build verification

- Frontend tests: passed
- Rust tests: passed
- Real scanner provider integration: passed
- Strict Clippy: passed
- Windows NSIS production build: passed
- Release executable smoke launch: passed

## Scope

This is preview software. It does not provide complete protection, certification, zero false positives, or automated remediation. Scanner results must be reviewed in context.

See README.md, SECURITY.md, and docs/ for architecture, privacy, scanner configuration, and licensing details.
