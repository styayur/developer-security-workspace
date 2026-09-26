# Security Model

## Scanner execution

Providers accept structured configuration. The process layer receives an executable path and an argument vector. It never evaluates a shell command string.

Controls include:

- executable existence validation
- Windows .exe requirement for user-selected scanner binaries
- workspace target canonicalization
- 15 minute timeout
- cancellation token
- process-tree termination on Windows and process termination on Unix
- 2 MiB per stdout/stderr capture bound
- temporary output directories
- source-independent logs

## Workspace and source access

SARIF artifact URIs and source viewer paths are normalized and constrained to the active workspace root. Path traversal is rejected. Source files are read-only, limited to 2 MiB, and binary content is rejected.

## Secret handling

The redactor handles obvious AWS, GitHub, Slack, Bearer, and private-key patterns. Recursive JSON redaction masks values for keys containing secret, token, password, private key, client secret, or raw. Redaction runs before database persistence and before scanner logs reach the UI.

The Preview intentionally favors over-redaction. Raw SARIF inspection uses the redacted result retained by normalization.

## Extension safety

Extension manifests are parsed and validated but not executed. Executable values must be command names without path separators or shell expressions. The Preview does not expose an arbitrary JavaScript plugin runtime.

## Privacy

No telemetry, analytics, login, account, or cloud upload exists. External scanners are independently installed and may maintain their own network or update behavior. The application does not silently download scanner binaries.
