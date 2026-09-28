# Changelog

## 1.0.0 — 2026-09-28

- Streaming SARIF import, bounded disk staging, global collision-safe matching, progress and transactional cancellation.
- Hard-memory benchmark harness, Gitleaks extension smoke, desktop walkthrough and release evidence.
- Hosted MSVC build with self-signed Authenticode application/installer signatures, public certificate and SHA-256 checksums.


### Security IR and investigation workflow

- Fixed Windows desktop test/app manifests: Common Controls v6 applies to library tests, with a build-local GNU resource override and MSVC manifest input.

- Versioned Security IR v1 with provenance, typed trace kinds, fingerprints and lifecycle.
- Native/exact/context/semantic matching with collision-safe identities and inherited triage.
- New/Existing/Fixed/Reopened/Changed comparisons, SQLite pagination and lazy raw references.
- Transactional schema 1 → 2 migration preserving Preview data and redacting legacy artifacts.
- Thread-aware Trace Debugger with keyboard stepping and cross-file source navigation.
- Reviewed declarative Gitleaks runtime, manifest/binary approval and explicit permission display.
- Bounded machine output/logs, cancellation fixes, GitHub/Slack redaction fix.
- Two-scan synthetic tutorial, normalization goldens, lifecycle/storage/UI regression tests and large-SARIF generator.
- Linux/Windows CI, desktop-feature checks, dependency audit and manual real-scanner workflow.


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
