# Licensing

## Application

Developer Security Workspace source is licensed under AGPL-3.0-only. The full license text is in the repository root LICENSE file.

## External scanners

Semgrep, Trivy, TruffleHog, Bandit, and CodeQL are not bundled. Users install and run them under their own licenses:

- Semgrep engine: LGPL-2.1.
- Semgrep-maintained rules: separate terms.
- Trivy: Apache-2.0.
- TruffleHog: AGPL-3.0-only.
- Bandit: Apache-2.0.
- CodeQL CLI and engine: GitHub CodeQL Terms.

Product names and trademarks belong to their respective owners. This project is independent and not endorsed by those vendors.

## CodeQL

The Preview does not download, vendor, or redistribute the CodeQL CLI/engine. It allows a user to select and verify a runtime path but does not implement full database analysis in v0.1.0-preview. Imported CodeQL SARIF uses the same generic SARIF pipeline as other scanners.

The Preview does not currently vendor upstream github/codeql MIT queries or libraries. If a future release does, that content must be placed under third_party/codeql with the upstream MIT license, notices, source URL, exact revision, and update process.

## Rule content

No Semgrep-maintained rules are copied or relicensed by this repository. Users remain responsible for the license terms of custom, registry, or third-party rules they run.
