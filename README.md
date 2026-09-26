<div align="center">

<pre>
██████╗ ███████╗██╗    ██╗
██╔══██╗██╔════╝██║    ██║
██║  ██║███████╗██║ █╗ ██║
██║  ██║╚════██║██║███╗██║
██████╔╝███████║╚███╔███╔╝
╚═════╝ ╚══════╝ ╚══╝╚══╝
</pre>

# Developer Security Workspace

### Universal SARIF Desktop Client

**Detect → Normalize → Understand → Trace → Compare → Triage**

[![Release](https://img.shields.io/github/v/release/styayur/developer-security-workspace?include_prereleases&style=for-the-badge&label=release)](https://github.com/styayur/developer-security-workspace/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?style=for-the-badge&logo=tauri)](https://tauri.app/)
[![Rust](https://img.shields.io/badge/Rust-stable-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![React](https://img.shields.io/badge/React-19-149ECA?style=for-the-badge&logo=react)](https://react.dev/)

A local-first vulnerability explorer, debugger, and scanner runtime.

**No account. No telemetry. No cloud upload. No fake scanner results.**

</div>

---

## Why this exists

Most scanner output ends at a table. Developer Security Workspace treats a finding as something to debug:

~~~text
SARIF / Scanner
       │
       ▼
 Rust Security IR
       │
       ├── source location
       ├── source → propagation → sink
       ├── rule / CWE / fix metadata
       ├── native + workspace fingerprint
       └── raw SARIF
       │
       ▼
 SQLite
       │
       ▼
 Findings → Trace → Compare → Triage
~~~

The UI is an IDE-style workbench, not an enterprise dashboard. It is built for people who need to understand the finding, not just count it.

## Current Preview

| Capability | Status |
| --- | --- |
| Tauri 2 desktop runtime | Ready |
| SARIF 2.1.0 parser | Ready |
| Rust Security IR | Ready |
| SQLite history and migrations | Ready |
| Monaco source debugger | Ready |
| SARIF code flows / Trace Player | Ready |
| Raw SARIF inspector | Ready |
| BLAKE3 workspace fingerprints | Ready |
| New / Existing / Fixed diff | Ready |
| Triage and notes | Ready |
| SARIF import / export | Ready |
| Demo Workspace | Ready |
| Semgrep provider | Verified locally |
| Trivy provider | Verified locally |
| TruffleHog provider | Verified locally |
| Bandit provider | Verified locally |
| CodeQL runtime | User-selected only |
| Extension execution | Intentionally disabled |

## Verified scanner matrix

The Preview was exercised against real local CLI installations:

| Scanner | Verified version | Output | Smoke findings |
| --- | --- | --- | --- |
| Semgrep | 1.178.0 | SARIF | 1 |
| Trivy | 0.74.0 | SARIF | 16 through app provider |
| TruffleHog | 3.97.9 | JSON compatibility adapter | 2 through app provider |
| Bandit | 1.9.4 | JSON compatibility adapter | 2 |

The smoke fixture is under fixtures/scanner-smoke. It contains synthetic values only.

### Recommended configuration

- **Semgrep:** local rules or an explicit registry config; metrics are disabled.
- **Trivy:** vulnerabilities, misconfiguration, secrets, and licenses enabled.
- **TruffleHog:** verified, unverified, unknown, and filtered-unverified candidates; raw values are redacted before persistence.
- **Bandit:** SARIF when available, structured JSON compatibility fallback otherwise.
- **CodeQL:** user-provided runtime only; no engine redistribution or silent download.

## Install

Download the latest NSIS installer from [GitHub Releases](https://github.com/styayur/developer-security-workspace/releases).

Requirements on Windows:

- Windows 10/11 x64
- WebView2 runtime
- Scanner CLIs are optional; the app detects them but never downloads them silently

## Development

~~~powershell
pnpm install
pnpm typecheck
pnpm test
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml
pnpm tauri dev
~~~

Build the Windows installer with MSVC:

~~~powershell
pnpm tauri build
~~~

Windows GNU fallback:

~~~powershell
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal
powershell -ExecutionPolicy Bypass -File scripts/build-windows-gnu.ps1
~~~

## Architecture

~~~text
┌──────────────────────────────────────────────────────────────┐
│ React / TypeScript / Monaco / TanStack                       │
├──────────────────────────────────────────────────────────────┤
│                    Tauri IPC boundary                        │
├──────────────────────────────────────────────────────────────┤
│ Rust Runtime                                                 │
│  ├─ SARIF parser + path mapper + normalizer                  │
│  ├─ Security IR + BLAKE3 fingerprints                        │
│  ├─ Scanner Provider runtime + cancellation + log limits     │
│  ├─ Secret redaction + source guard                          │
│  └─ SQLite history + triage + diff                           │
└──────────────────────────────────────────────────────────────┘
~~~

No localhost HTTP backend is started.

## Repository map

~~~text
src/                 React desktop UI
src-tauri/src/       Rust runtime and Tauri commands
fixtures/sarif/      SARIF parser fixtures
fixtures/scanner-smoke/
docs/                Architecture, security, scanner, licensing docs
third_party/         Third-party attribution boundaries
~~~

## Privacy

- No login.
- No account.
- No telemetry.
- No analytics.
- No cloud upload.
- The database lives in the operating system application-data directory.
- Source files are read-only and confined to the active workspace.
- Scanner logs and persisted raw SARIF are secret-redacted.

## Build quality

The preview currently passes:

~~~text
pnpm typecheck
pnpm test                 5/5
pnpm build
cargo test                30 passed, 1 scanner integration ignored by default
cargo test -- --ignored   4 real scanner providers passed locally
cargo fmt --check
Clippy with -D warnings
pnpm tauri build
~~~

## Known limitations

- Full CodeQL database analysis is not part of this Preview.
- Extension runtime execution is intentionally disabled.
- TruffleHog and Bandit use compatibility adapters when native SARIF is unavailable.
- Scanner installation remains an explicit user action.
- Unsigned Preview builds may trigger Windows SmartScreen.
- False positives and false negatives must be reviewed by a human.

## Security

See SECURITY.md. Do not report vulnerabilities in public issues.

## License

Application source: **AGPL-3.0-only**. See LICENSE.

Optional scanners and runtimes retain their own licenses. See NOTICE.md, THIRD_PARTY_LICENSES.md, and docs/licensing.md.

This project is not affiliated with or endorsed by Semgrep, Aqua Security, Truffle Security, PyCQA, GitHub, or any scanner vendor.

---

<div align="center">

**Scan locally. Understand deeply. Ship deliberately.**

</div>
