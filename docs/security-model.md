# Security model

## Process execution

Providers use `Command::new(executable).args(argv)` with null stdin, piped output and no shell evaluation. Source roots are canonicalized against the selected project. Windows user-selected executables must be `.exe`; `.cmd`, `.bat` and `.ps1` wrappers are rejected. No scanner is silently downloaded.

Cancellation checks run before spawn and terminate the process tree on Windows (taskkill) and the process group on Unix. Scan deadlines cancel the child token before awaiting logs. Detection commands have a ten-second deadline. There are at most two concurrent providers in a scan.

Human output capture is capped at 2 MiB per stream. Fixed-size reads avoid unbounded allocation for unterminated lines; log events are capped at 2,000 lines/2 MiB per stream and oversized/private-key lines are omitted. JSON log records use recursive redaction. Machine JSON is captured separately (128 MiB cap) and never emitted as stdout log events. Oversized machine output fails explicitly instead of importing a truncated report.

## Workspace boundary

Source files are read-only, UTF-8, limited to 2 MiB and constrained by canonical root containment, including symlinks. Fingerprint context uses this same guard. SARIF paths may be retained for display when they cannot be mapped safely, but cannot bypass source access validation. Fixes are displayed; they do not automatically write to the workspace.

## Secrets

Normalization and artifact persistence redact secret-keyed JSON and obvious AWS/GitHub/Slack/Bearer/private-key patterns. Raw scanner JSON stays in memory only until its trusted adapter processes it. TruffleHog adapters discard Raw, RawV2 and SecretParts. Triage notes are pattern-redacted before persistence. Schema migration re-redacts legacy artifact payloads.

The redactor is heuristic and is not a guarantee that arbitrary unlabelled secrets can be detected. The source viewer intentionally displays the user's local source, which may contain secrets. Do not publish screenshots of private workspaces. Demo files use synthetic values only. No source context is stored as fingerprint metadata, only its hash.

## Declarative extensions

Runtime v1 executes only the reviewed Gitleaks offline/read-only argument profile; other valid manifests remain metadata. No JavaScript/eval runtime, arbitrary executable path from a manifest, shell interpreter or environment interpolation is accepted. `{workspace}` and `{output}` expand as complete argv elements; the output path is an application-created temporary file. Other recognized placeholders are reserved and cannot execute through the v1 profile.

The UI shows the executable's resolved path, arguments, capabilities, workspace/network declarations, output, license and untrusted status. An explicit checkbox approves the manifest plus installed binary digest for the selected workspace. Changes invalidate approval. The launch path revalidates the manifest and digest. Gitleaks runs from a temporary directory with configuration environment overrides removed.

Permissions are declarations and restrictions on the supported invocation, **not an OS sandbox for a malicious native binary**. Users must trust the binary they install. Runtime v1 rejects requested workspace writes/network access and does not accept arbitrary flags or external config files. Additional execution profiles require reviewed code and tests. See [extension model](extension-model.md).

## Privacy and external scanners

DSW has no telemetry, login, analytics, cloud storage or remote backend. Scanner installations remain user-managed. Existing native scanners may download rules/databases or verify credentials according to explicit scanner settings; their own network behavior is not an OS-enforced DSW permission. The manual smoke workflow explicitly downloads pinned tools and Trivy's database, and disables TruffleHog verification of synthetic candidates.

## Dependency policy

Linux and Windows CI exercise Rust/TypeScript. Dependency checks use cargo-audit, cargo-deny and production high/critical frontend audit. No blanket advisory suppression is configured. See [release operations](release.md) for maintaining narrowly scoped exceptions and self-signed releases.
