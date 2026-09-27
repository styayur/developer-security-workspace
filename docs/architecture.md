# Architecture

> Scanners are replaceable producers. Security IR and the investigation workflow are the product.

React/Monaco runs inside Tauri. Privileged filesystem, process and SQLite operations stay in Rust; there is no HTTP backend, account service or telemetry client.

## Data pipeline

```text
Native scanner / SARIF import / reviewed declarative scanner
  -> parser + trusted adapters + source path guard + redaction
  -> Security IR v1 + layered fingerprints
  -> conservative one-to-one matcher
  -> identity + occurrence + triage + SQLite
  -> paginated summaries -> on-demand debugger detail / trace / raw result
```

Scanner-specific adaptation belongs in providers and normalizers. React consumes the same IR for every producer.

## Security IR v1

`SECURITY_IR_VERSION = 1` is a protocol version, independent of the application and database schema versions. Finding provenance carries scanner ID/name/version, adapter version, source format, imported/generated/demo origin, scan ID, IR version and rule/result metadata digests. Scan runs also expose the IR version. Unknown scanner versions stay absent.

The existing flat Finding shape is retained for compatibility. Explicit fields cover provenance, structured fingerprints, lifecycle and raw references alongside classification, rule, locations, flows, fixes and evidence. Legacy native/workspace fingerprint fields remain readable. Additive optional fields use serde defaults; incompatible semantic changes require a new IR version, migration and updated golden corpus. Do not silently reinterpret an existing fingerprint version.

Trace kinds are Source, Propagation, Sanitizer, Sink, Call, Return and Unknown. Only explicit SARIF `kinds` values establish kind. Prose saying “source” or “sink” is not sufficient evidence. Flow and thread boundaries remain separate.

## Fingerprints and matching

- Native: full SARIF fingerprints take priority over partial fingerprints. Sorted key/value pairs are hashed to avoid nondeterministic HashMap selection and retaining sensitive identifiers.
- Exact: scanner/rule, normalized path and normalized message, excluding line. Numeric message drift is normalized. Windows drive paths normalize case and separators; Unix path case remains significant.
- Context: BLAKE3 over the finding's ±3 source lines, whitespace-normalized, scoped to scanner/rule and any supplied symbols. Only a digest is persisted. Source reads use the canonical workspace guard and 2 MiB limit. This reflects source available **at import time**, not a verified historical checkout.
- Semantic v1: scanner/rule, sorted CWE set and supplied logical locations. No symbol means no semantic hash. CWE alone never establishes identity; there is no AI or embedding matching.

`FindingMatcher` applies Native -> Exact -> Context -> Relocated. Every stage requires a unique candidate on both sides and consumes both occurrences once. Conflicting supplied symbols are rejected. Duplicate ambiguous candidates remain unmatched rather than inheriting someone else's triage. Context may disambiguate a repeated exact hash. Explanations retain previous occurrence/run, method and Exact/Strong/Weak confidence, without invented numeric probabilities.

## Lifecycle and comparisons

Each occurrence belongs to a long-lived identity. Identities retain firstSeen, lastSeen, occurrenceCount, fixedAt, reopenedAt, latest occurrence and user triage. New observations inherit Confirmed, False Positive, Accepted Risk and Ignored decisions by identity. Triage is distinct from the occurrence's diff class.

- New: no unique identity match.
- Existing: matched, investigation signature unchanged. A line shift alone stays Existing.
- Changed: matched but severity, material message, path/symbol, source/sink characteristics, scanner version, result properties or rule metadata changed.
- Fixed: absent after a completed full scan that explicitly covered that scanner.
- Reopened: a previously Fixed identity returns.

Failed, cancelled, partial, changed-files and uncovered-scanner scans do not establish absence. Scan completion and fixed-state updates commit together. Imported empty runs must retain producer coverage. Comparisons of selected historical runs use identity joins and signature differences, and return bounded pages per class. The displayed identity state is current; the diff classification of each occurrence remains stored separately.

Conservative matching can produce extra New/Fixed entries when evidence is ambiguous. Cross-rule matching and fuzzy cross-function matches are intentionally unsupported in v1.

## Persistence and migrations

SQLite lives in the application-data directory with foreign keys and WAL enabled. `storage/migrations.rs` applies ordered versions in a transaction. Failure is returned to the caller; newer schema versions are rejected. No table reset or destructive schema rebuild occurs.

Schema 1 is the original Preview schema. Schema 2 adds provenance/fingerprint/lifecycle/candidate/reference columns, identities, artifact result storage and query indexes. Existing occurrences and notes survive. Legacy hashes are grouped into an identity only when no scan contains a collision; collision groups retain separate identities. Legacy context cannot be reconstructed safely from today's files, so migration leaves it absent. Historical Fixed/Reopened states cannot be recovered perfectly from the old format.

New artifacts store run metadata once and each redacted result once in `scan_artifact_results`; findings store the artifact/run/result reference. Legacy embedded raw results remain readable. Migration also redacts existing raw artifact payloads; malformed stored artifact JSON aborts migration rather than discarding data. Raw result detail resolves only its referenced row. Full-run inspection is bounded at 8 MiB; large results remain individually inspectable.

## Query and UI boundaries

All list filters (project/run, severity, scanner, category, status, rule, path, CWE, lifecycle and search) execute in SQLite using bound parameters. List pages default to 100 and are capped at 500. The compatibility list IPC is also capped at 500. Summaries omit flows/fixes/raw payloads. Counts and scanner choices use SQL aggregation; adjacent-finding navigation returns only IDs and count metadata. The virtualized UI renders one page and expires inactive page caches after 30 seconds.

The debugger retains resizable Monaco/inspector panes. Trace paths select a single thread, show Step n/N, support Previous/Next and arrow/Home/End keys, and load cross-file source through the same guarded read API.

See [performance](performance.md), [extension boundary](extension-model.md) and [security model](security-model.md).
