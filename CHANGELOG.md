# Changelog

## v0.1.0-preview

Initial Preview MVP.

### Added

- Tauri 2 desktop shell with React, TypeScript, Vite, Tailwind, Radix, Monaco, TanStack Query, TanStack Virtual, Zustand, and React Router.
- Rust SARIF 2.1.0 parser, Security IR normalizer, workspace path mapper, secret redactor, and BLAKE3 fingerprint engine.
- SQLite persistence for projects, scan runs, scanner runs, findings, triage, fingerprints, settings, rules, and raw artifacts.
- Findings inbox with search, severity, scanner, category, status, file, CWE, and rule filters.
- Finding Debugger with Monaco source navigation and SARIF code-flow Trace Player.
- Raw redacted SARIF inspector and full-run viewer.
- Scan history, cancellation, scanner logs, New/Existing/Fixed diff, and workspace fingerprint comparison.
- Semgrep, Trivy, TruffleHog, and Bandit providers with structured process execution.
- Changed Files filtering from Git status.
- SARIF import/export and a real-parser Demo Workspace.
- CodeQL runtime selection and verification without engine redistribution.
- Extension manifest schema, loader, validator, and metadata-only permission model.
- Components and licenses UI.
- AGPL-3.0-only project and third-party documentation.
- GitHub CI and tag-driven NSIS Preview release automation.

### Verified locally

- Semgrep 1.178.0
- Trivy 0.74.0
- TruffleHog 3.97.9
- Bandit 1.9.4

Security scanners can produce false positives and false negatives. Findings should be reviewed in context before remediation or risk decisions.
