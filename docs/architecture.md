# Architecture

## Runtime boundary

React runs in the Tauri WebView. All privileged work crosses Tauri IPC into Rust. The application does not start a localhost HTTP server or host a remote backend.

## Data pipeline

~~~text
Repository or SARIF file
  → Rust parser
  → Security IR normalizer
  → path mapping and secret redaction
  → workspace fingerprint engine
  → SQLite
  → Tauri IPC
  → React views
~~~

The frontend consumes typed Security IR objects. Raw SARIF is retained only as redacted result data for the Raw inspector and for full-run inspection.

## Backend modules

- commands: Tauri IPC command surface.
- workspace: repository detection, Git metadata, source reading, and path validation.
- sarif: flexible SARIF 2.1.0 model, parser, URI mapper, and Security IR normalization.
- security_ir: serializable domain types shared across commands and persistence.
- storage: SQLite schema and persistence methods.
- fingerprint: BLAKE3 workspace fingerprint v1.
- process: structured process runner, bounded log capture, cancellation, and process-tree termination.
- scanners: provider abstraction plus Semgrep, Trivy, TruffleHog, and Bandit.
- extensions: manifest schema loading and validation.
- licenses: component and license inventory.
- secret_redaction: recursive JSON and text redaction.

## Frontend modules

- app shell and routing
- findings inbox and virtualized list
- finding debugger, Monaco source, code flow, Raw inspector
- scan history, logs, cancellation, and diff
- scanner detection, configuration, and orchestration
- SARIF import/export and demo flow
- settings, CodeQL runtime configuration, extensions, and licenses

## Persistence

SQLite is stored in the operating system application data directory. The Preview schema includes projects, recent projects, scan runs, scanner runs, scan artifacts, findings, finding locations, finding fingerprints, finding triage, scanner configs, settings, and rules.

The schema is applied with IF NOT EXISTS migrations and never performs a destructive reset at startup.
