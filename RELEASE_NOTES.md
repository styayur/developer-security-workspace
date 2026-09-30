# Developer Security Workspace v1.0.1

This release hardens scan lifecycle correctness. A project can now have only one active scanner run, progress and completion events are scoped to the active project and run, Changed Files mode passes explicit changed paths to each scanner, and SARIF export emits only current non-fixed findings. ScannerRun history records the real detected scanner version for each run.

The database schema is unchanged from v1.0.0, so this is a drop-in upgrade. Existing findings, triage notes, and scan history remain in place. The Windows installer and SHA256SUMS are produced by the same signed Windows release workflow.

## v1.0.0 baseline

This update introduces Security IR v1, identity-based triage, explainable layered matching, Changed/Reopened comparisons and thread-aware trace navigation. Findings are queried in bounded SQLite pages and raw results load by artifact reference. The synthetic tutorial includes two scans, fixes, cross-file traces, secrets, dependencies and IaC.

Existing Preview databases migrate transactionally to schema 2; projects, occurrences and notes are preserved. Ambiguous legacy collisions are kept separate. Keep a backup before upgrading important local databases; do not downgrade a migrated database to an older Preview.

Declarative runtime v1 executes only the reviewed Gitleaks profile after the user approves the manifest and installed binary. It is not a sandbox for malicious native executables. Other manifests remain metadata. No scanner, CodeQL engine, account system or telemetry is bundled.

SARIF import now streams through bounded disk-backed staging with progress and cancellation. A 100,000-result double import/diff passes a hard 512 MiB process-memory limit.

Windows MSVC installers use a self-signed Authenticode certificate. This verifies integrity against the included public certificate, but does not provide public-CA publisher trust or remove SmartScreen. The certificate is not automatically trusted and signatures are not timestamped. Release artifacts include the public certificate and SHA256SUMS. See [release operations](docs/release.md) and [known limits](docs/performance.md).
