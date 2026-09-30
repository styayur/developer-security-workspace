# Security Policy

## Supported versions

Security fixes target the latest v1 release and current `main`. Older preview builds may receive compatibility guidance only. Do not treat scanner output, fingerprints, triage state, or exported SARIF as a complete security assessment.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report through the repository hosting provider's private security advisory feature. Include affected version, reproduction, impact, attacker capability, suspect input type, and suggested remediation.

## Security model

- Tauri IPC is the only frontend/backend boundary.
- No localhost HTTP backend or remote application service is started.
- Scanner commands are constructed from a validated executable plus an argument array. Arbitrary shell command strings are not accepted.
- Workspace and source file access is constrained to the active project root.
- Windows scanner binaries selected manually must be .exe files.
- Scanner output is bounded, temporary, and optionally streamed into a bounded in-memory log.
- Obvious secret values are redacted before persistence or display.
- Extension manifests do not execute code.
- External scanner binaries, dependencies, rule packs, and CodeQL runtimes are not downloaded automatically.

## Threat model

The Preview mitigates malicious SARIF path traversal, shell injection through scanner configuration, accidental persistence of obvious secret values, unbounded scanner output, third-party plugin execution, and silent scanner download.

It does not sandbox a malicious scanner executable that the user deliberately installs and runs. Scanner trust remains the user's responsibility.
