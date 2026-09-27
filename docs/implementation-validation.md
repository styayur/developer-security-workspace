> Historical baseline before the v1.0.0 follow-up. Streaming, Gitleaks, screenshots and signed hosted release results supersede the pending items below; see [v1.0.0 validation](release/v1.0.0-validation.md).

# Implementation and validation — 2026-09-27

This change extends the existing DSW repository and real providers. It retains Tauri/Rust/SQLite/React, the workspace guard, executable + argv execution, local persistence and user-managed scanner installations. No service, account, telemetry, AI matching, arbitrary extension scripts or scanner bundling was added.

## Changed areas and primary files

| Area | Primary files | Result |
| --- | --- | --- |
| IR | `src-tauri/src/security_ir/{mod,protocol}.rs`, `sarif/normalize.rs`, `src/types/domain.ts` | Protocol version 1, provenance, typed trace roles, structured fingerprints, identity lifecycle and raw references |
| Matching | `src-tauri/src/fingerprint/mod.rs`, `matching.rs` | Native → Exact → Context → Relocated, deterministic and one-to-one |
| Persistence | `src-tauri/src/storage/{migrations,lifecycle,query,mod}.rs` | Non-destructive schema 2, identity triage, SQL filtering/counting/pages and reference-based raw storage |
| Investigation | `src/components/TraceDebugger.tsx`, `src/pages/{FindingDetail,Findings,ScanDiff}Page.tsx` | Independent trace paths, keyboard stepping, source ranges, counted list/diff pages |
| Scanner configuration | `src/components/ScannerConfigForm.tsx`, scanner providers | Provider-owned field metadata replaces scanner-ID branches in the settings UI |
| Extensions/process | `src-tauri/src/extensions/{mod,runtime}.rs`, `state.rs`, `process/mod.rs`, `commands/scans.rs` | Reviewed Gitleaks runtime, explicit binary/manifest approval, bounded logs/output, cancellation/deadlines |
| Demo | `src-tauri/src/workspace/demo.rs`, `fixtures/ir/rich.sarif`, `fixtures/sarif/tutorial-iac.sarif` | Repeatable two-scan tutorial with SQL trace/fix, redacted synthetic secret, SCA and IaC |
| CI/build | `.github/workflows/{ci,release,dependencies,scanner-integration}.yml`, `deny.toml`, `src-tauri/build.rs`, `windows-app.manifest` | Windows and Linux checks, desktop tests, audited dependencies, manual real-provider smoke, NSIS/checksums and correct Windows manifests |
| Regression/performance | `src-tauri/src/{regression_tests,storage/regression_tests}.rs`, `src/{components/TraceDebugger,pages/Investigation}.test.tsx`, `fixtures/{ir,fingerprint,diff}`, `scripts/generate-large-sarif.mjs` | Golden normalization, conservative identity/lifecycle, security/migration/UI tests and generated large inputs |

## Architecture, IR and migration

Scanners are replaceable producers. Security IR and the investigation workflow are the product.

IR versioning is independent of database/app versions. Provenance includes scanner identity/version, parser/adapter version, source format/origin, scan ID, IR version and rule/result metadata hashes. Existing Finding fields remain; additive fields have serde defaults. Trace roles require unambiguous explicit SARIF kinds; prose is not evidence.

The schema 1 → 2 migration runs transactionally and preserves projects, occurrences, notes and triage. Legacy hashes group only without same-scan collisions. New columns/tables store identities, lifecycle, candidates, provenance and raw result references. Legacy artifact content is re-redacted. Invalid stored artifact JSON or a future schema causes a visible error; migration does not drop/reset data. Empty databases, old databases, repeated startup, future versions and rollback are tested. Old context/historical absence cannot be reconstructed reliably and is not invented.

## Identity, lifecycle and diff

Native hashes use ordered scanner fingerprint maps. Exact hashes exclude line numbers and normalize message numeric drift and platform path conventions. Context hashes use guarded ±3 source lines with whitespace normalization; only hashes persist. Semantic v1 requires same scanner/rule and supplied symbols plus CWE, with no AI or CWE-only match.

Each match stage requires uniqueness on both sides. Ambiguous same-rule occurrences stay separate; conflicting symbols are rejected. Matches expose previous occurrence/run, Native/Exact/Context/Relocated method and Exact/Strong/Weak confidence. Identity stores first/last seen, count, fixed/reopened dates, state and durable triage.

New means unmatched; Existing means matched with unchanged investigation signature; Changed covers material severity/message/location/flow/metadata changes; Fixed requires absence in a completed full scan with scanner coverage; Reopened means a Fixed identity returned. Failed/partial/cancelled/changed-files scans cannot establish absence. Imported empty runs retain producer coverage; failed imports finish Failed. Triage inherits by identity rather than a loose hash. Historical comparisons are bounded identity/signature joins.

## Trace and performance

The debugger selects a single thread flow, shows Step n/N and explicit role icons, highlights the active step, supports click/Previous/Next/arrows/Home/End, and loads cross-file source/ranges through the workspace guard. Flows are never concatenated into a false sequence. Existing resizable Monaco/inspector panes remain.

SQLite performs filtering, counts and pagination. UI pages contain 100 summaries, IPC caps at 500, and details load on selection. Raw artifacts store run metadata once and each redacted result once; findings hold references. The command palette requests eight rows; navigation returns adjacent IDs. Identity assignment no longer clones whole finding batches; source-context caching and raw-copy release reduce peak memory.

Debug/test benchmarks passed at 10k, 50k and 100k findings per scan. The 100k two-scan import/diff took 220.04 seconds; 100-row queries took 472/510 ms, payloads about 55 KB, observed peak working set 1.32 GiB. See [reproducible commands and measurement boundaries](performance.md).

## Extension/security boundary

Runtime v1 accepts only the reviewed Gitleaks offline/read-only, file-SARIF profile. Other manifests remain metadata. Manifest executable must be a command name; interpreters, paths, shell interpolation, unknown placeholders, custom converters, network/write requests and unreviewed argv are rejected for execution. Parameters become whole argv elements. Output goes to an app-created temporary directory. The UI shows executable, argv, capabilities, declarations, output, license and untrusted status; manifest + resolved binary digest changes invalidate approval.

This is not an OS sandbox for a hostile native executable. Users must trust their installed binary. Existing four providers stay real. Human logs/machine JSON use separate bounded paths; secret-keyed JSON and known token patterns are redacted. A GitHub/Slack capture-group leakage bug was fixed. Cancellation tests exercise a running native process, not just a pre-cancelled token.

## CI and release

PR CI covers Ubuntu and Windows frontend/core checks, with desktop-feature clippy/tests on Windows. Main/manual runs package NSIS. Tag releases require checks/build success, an existing installer and SHA256SUMS before prerelease upload. Installers remain unsigned. The real-scanner workflow is manual and pins tools; the app does not install them. Dependency checks use explicit licenses/sources and pinned cargo-audit/cargo-deny without blanket ignores.

Local testing found and fixed a genuine Windows loader issue: bin-only Tauri manifests did not cover library tests, and the GNU default manifest could override Common Controls v6. The shared manifest now applies to test/app executables with no toolchain modification. [Build and release details](release.md) explain the platform-specific flags.

## Actual checks

All commands were run from the repository root. Windows Rust commands used the installed stable GNU toolchain/MinGW via command-local RUSTC, RUSTDOC, PATH and `CARGO_TARGET_DIR=src-tauri/target-gnu-release`; the default MSVC toolchain cannot link here because Visual Studio C++ Build Tools are absent.

| Command | Result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Passed; lockfile unchanged |
| `pnpm typecheck` | Passed |
| `pnpm test` | 9 passed |
| `pnpm build` | Passed; large lazy Monaco chunk warning remains |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings` | Passed |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked` | 53 passed, 2 intentionally ignored |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --locked --features desktop --all-targets -- -D warnings` | Passed |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked --features desktop` | 55 passed, 2 intentionally ignored, after manifest fix |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked installed_scanners_execute_through_providers -- --ignored --nocapture` | Real Semgrep/Bandit/Trivy/TruffleHog provider smoke; findings 1/2/12/2 |
| `cargo test --manifest-path src-tauri/Cargo.toml large_sarif_benchmark -- --ignored --nocapture` | Passed separately for 10k, 50k, 100k inputs |
| `cargo audit --file src-tauri/Cargo.lock` | Passed with 7 visible transitive maintenance/soundness warnings; details in release docs |
| `cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml --locked check` | Advisories, bans, licenses and sources passed; duplicate-version warnings remain |
| `pnpm audit --prod --audit-level high` | No known vulnerabilities reported |
| `actionlint` 1.7.12 | All workflows passed static validation |
| `git diff --check` | Passed |
| `./scripts/build-windows-gnu.ps1` → `pnpm tauri build` | Passed; rebuilt NSIS with corrected manifest; no manifest conflict warning |
| PE resource inspection | Release app and desktop test both contain Common Controls v6 and asInvoker |

The two ignored tests are intentionally environment-dependent (installed providers and large generated benchmark); both were separately exercised. No coverage percentage is claimed. Hosted GitHub Actions has not been triggered from these uncommitted local changes.

## Local installer artifact

The verified unsigned installer is `src-tauri/target-gnu-release/release/bundle/nsis/Developer Security Workspace_0.1.0-preview_x64-setup.exe` (3,637,488 bytes). Its SHA256 is:

```text
ED70473191D1CBCC2C6585B3327B112831AE56B2B1CA8D386AF6B1FB3936996A
```

The checksum file is `work/SHA256SUMS.txt`. Build outputs and generated benchmarks stay ignored; no release was published and no git commit/push was made.

## Remaining limits and next work

- Parsing remains whole-document, capped at 128 MiB. Low-memory machines and pathological huge individual flows/results need further profiling/budgets. Full Raw inspection is limited to 8 MiB; export remains a backend batch operation.
- The matching policy intentionally favors extra unmatched findings over false merges. Legacy history lacks enough evidence to recover every old lifecycle transition. Context reflects files available at import time.
- Gitleaks execution was not smoke-tested against an installed CLI on this machine; manifest/runtime security tests passed. Only its reviewed profile is executable, and declarations cannot constrain a malicious binary at OS level.
- No real desktop screenshot, interactive packaged-app walkthrough, Authenticode signature or hosted MSVC CI run is claimed. Screenshot placement/capture instructions are provided instead of a fabricated product image.
- The Monaco chunk and seven upstream cargo-audit warnings remain visible.

At most five next steps: streaming import with per-result budgets/cancellation; low-RAM release-build profiling; installed Gitleaks smoke plus OS-level containment evaluation; real packaged-app walkthrough/screenshots; hosted MSVC release validation and signing with an actual certificate.
