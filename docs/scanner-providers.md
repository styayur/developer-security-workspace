# Scanner Providers

## Common provider contract

Every provider exposes identity, display metadata, capabilities, detection, version, scan, cancellation, license, official URL, install guidance, and structured configuration.

The process layer executes only an executable plus arguments. Cancellation terminates the process tree. Scanner output is limited, and logs are redacted.

## Semgrep

Semgrep is treated as two license objects:

1. Semgrep engine (LGPL-2.1).
2. Rule sources, which may use a separate Semgrep-maintained rules license or another license selected by the user.

The Preview supports local rule files, local rule directories, and registry config identifiers. It generates SARIF with metrics disabled. Semgrep-maintained rules are not copied into this AGPL repository.

## Trivy

The Preview uses filesystem SARIF output. Users can select vulnerability, misconfiguration, secret, and license scanner categories. Database update behavior is not hidden; a user can choose skip-db-update when the database is already present.

## TruffleHog

TruffleHog filesystem scanning uses a JSON compatibility adapter into SARIF. The adapter keeps detector name, verification state, file, line, and scanner-provided redacted value. It does not persist the raw candidate secret. Users can request only verified output.

## Bandit

Bandit first attempts SARIF when the optional sarif formatter is installed. If that formatter is unavailable, the provider falls back to Bandit JSON and preserves test ID, test name, text, severity, confidence, CWE, filename, line, and more-info URL.

## Installation

No managed installer runs automatically. UI setup commands are informational and copied by the user. Recheck searches configured paths, PATH, and bounded known install locations rather than scanning the entire disk.

## Verified Preview configuration

The v0.1.0-preview smoke run used:

| Provider | Version | Output path |
| --- | --- | --- |
| Semgrep | 1.178.0 | Native SARIF |
| Trivy | 0.74.0 | Native SARIF |
| TruffleHog | 3.97.9 | JSON compatibility adapter |
| Bandit | 1.9.4 | JSON compatibility adapter |

The smoke fixture is fixtures/scanner-smoke. It includes a repository-owned Semgrep rule, an obsolete lodash lockfile entry, a root-user Dockerfile, a Python shell injection, and base64-encoded synthetic secret tokens.

Recommended defaults:

- Semgrep metrics are disabled.
- Semgrep rules should be selected explicitly by local path or registry identifier.
- Trivy enables vulnerability, misconfiguration, secret, and license scanners.
- TruffleHog reports verified, unverified, unknown, and filtered-unverified detections unless verified-only mode is selected.
- Bandit uses SARIF when installed and falls back to its JSON compatibility adapter.
- Raw secret candidates are removed before persistence and UI rendering.
