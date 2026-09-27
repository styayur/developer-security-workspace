# Large SARIF performance

The inbox loads SQLite pages of 100 summaries (IPC cap 500), with detail and raw results fetched on selection. Counts, scanner choices and diff buckets are SQL queries. Inactive pages expire from React Query after 30 seconds.

## Streaming import and cancellation

The desktop importer reads one result at a time into a temporary SQLite database. Run metadata may precede or follow results. Raw values are redacted before staging; native fingerprint digests are computed before redaction. Normalization also processes one result at a time. Matching uses disk-backed SQL over the whole unmatched candidate set, so a duplicate in another batch cannot cause a false unique match.

The durable artifact, results, identities, lifecycle and completed scan status commit in one transaction. Cancelling during parsing, normalization, matching or insertion interrupts work; insertion cancellation rolls back the transaction. Temporary files are removed. The scan is recorded as cancelled, without partial findings or changed identities. Progress and Cancel import are available on both Welcome and SARIF pages.

Limits: 1 GiB input, 2 MiB per JSON value/result, 8 MiB total metadata including member names, 4,096 runs and 1,000,000 results. These are rejection limits, not preallocated buffers. SQLite caches are bounded and matching temporary tables spill to disk. A single result includes its flows, so the result limit also bounds exceptionally large traces. The generic scanner-output parser remains capped at 128 MiB.

## Reproduce a hard memory limit

Generate a report with a new filename (the generator refuses overwrite):

```powershell
node scripts/generate-large-sarif.mjs 100000 work/large-100000.sarif
cargo test --manifest-path src-tauri/Cargo.toml --no-run
# Use the test executable path printed by Cargo; copy it before rebuilding.
python scripts/benchmark-low-memory.py TEST_EXECUTABLE work/large-100000.sarif work/streaming-benchmark 512
```

GNU users first configure RUSTC/RUSTDOC/PATH as in `scripts/build-windows-gnu.ps1`. The Python harness uses only the standard library. It creates the child suspended, assigns a Windows Job Object with PROCESS_MEMORY=512 MiB, then resumes it. It records kernel peak working set/commit counters, enforced limit, exit code and elapsed time in metrics.json; test output goes to benchmark.log. The benchmark imports twice into a fresh temporary database, queries 100 summaries, and asserts that all second-scan findings are Existing in the diff.

## Local results, 2026-09-27

Windows x64 GNU debug/test build, 100,000 findings per scan, 29,292,291-byte synthetic report. An initial streaming run completed both imports and diff in 336.19 s with a 512 MiB enforced limit, 66,211,840-byte peak working set and 54,374,400-byte peak committed memory. Pages took 347/604 ms and serialized to 54,764/55,764 bytes. Final-version measurements are recorded in `release/v1.0.0-validation.md`.

For comparison, the earlier whole-document importer used a sampled peak working set of 1,415,614,464 bytes (1.32 GiB), completing the same two scans and diff in 220.04 s. Streaming trades extra staging I/O for substantially lower memory. These concurrent-development debug measurements are not controlled release-build timing comparisons.

## Remaining costs

Full-run Raw inspection is limited to 8 MiB; individual redacted results remain available. Export and external scanner adapters still use backend batch operations. Substring filters/severity ordering can scan or sort rows. A process memory limit is not a simulation of an entire low-RAM Windows system: it excludes WebView2, OS caches and other processes. The measured limit covers the importer, SQLite and diff test, not the complete desktop process tree. Source context depends on files available at import time and reads bounded files. Native third-party scanner memory is outside the import benchmark.
