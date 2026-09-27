# CI and release operations

`ci.yml` runs frozen pnpm install, typecheck, tests, build, Rust fmt, clippy and tests on Ubuntu and Windows. Windows additionally compiles/tests/clippies the `desktop` feature, which includes the Tauri commands omitted from core-only builds. Main pushes and manual CI runs produce an NSIS installer artifact; PRs do not run the heavyweight installer packaging step.

`scanner-integration.yml` is manual and does not block ordinary PRs. It explicitly installs pinned Semgrep, Trivy, TruffleHog, Bandit and Gitleaks versions, verifies the TruffleHog archive checksum, downloads the Trivy database and executes the ignored provider smoke test against the synthetic fixture. TruffleHog credential verification is disabled in this test. Scanner CLIs are never bundled into the app.

`dependencies.yml` runs pinned cargo-audit 0.22.2, cargo-deny 0.20.2 and `pnpm audit --prod --audit-level high` on PR/push/manual and weekly. `deny.toml` lists permitted licenses/sources, denies wildcard dependencies and unknown sources, and warns on duplicate versions/yanked crates. Unmaintained *direct* dependencies fail; transitive maintenance advisories remain a review signal. Actual vulnerabilities are not globally ignored.

If an advisory needs an exception, record the exact ID/package, applicability rationale, owner, tracking issue and expiry/review date in the tool's config and this document. Registry/advisory-service outages should be rerun; do not permanently disable the job or silently ignore all warnings. Official policy reference: [cargo-deny advisories configuration](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html).

## Publishing

A `v*` tag triggers `release.yml`: frozen install, frontend tests, Rust desktop checks/tests, signed MSVC NSIS build, signature verification and SHA256SUMS, followed by a stable GitHub release. Manual runs execute the same checks and signed build but only upload an Actions artifact. Packaging fails if an installer or signing secret is missing. No release upload happens before checks pass.

Version 1.0.0 uses an RSA-3072/SHA-256 **self-signed** Authenticode publisher certificate. Its public copy is `docs/release/DSW-self-signed.cer`, thumbprint `31060FB6F043C9ED8886E8F46E488163FD4C755A`, valid until 2028-09-27. It is not a public-CA certificate and does not remove SmartScreen or establish independently verified publisher identity. Do not automatically import it into Trusted Root stores. Signatures have no timestamp; verification is limited by certificate validity.

Encrypted PFX and its password are separate repository Actions secrets, `WINDOWS_CERTIFICATE` and `WINDOWS_CERTIFICATE_PASSWORD`. The ephemeral runner imports the key into CurrentUser/My, verifies the expected public certificate, signs the application and installer through Tauri's custom sign command, then removes the runner private key. PFX/P12 files are ignored by Git; neither the password nor private key belongs in the repository or release assets.

`scripts/verify-windows-signature.ps1` checks the PE digest via WinVerifyTrust and accepts only success or the expected untrusted-root status, checks the exact signer thumbprint, and validates the certificate in an isolated custom-root chain. It never changes a trust store. A local tampered-EXE regression check returned TRUST_E_BAD_DIGEST and was rejected. SHA256SUMS covers the installer and public certificate. This verifies integrity against the published certificate; users must still obtain the certificate/checksums from a source they trust.

Local MSVC builds require Visual Studio C++ Build Tools and WebView2. `scripts/build-windows-gnu.ps1` remains available for machines with the GNU toolchain/MinGW. A successful local build is not evidence that hosted GitHub Actions has run; inspect the actual workflow run before publishing a release.

## Dependency review on 2026-09-27

Local cargo-audit passed with seven informational warnings: RUSTSEC-2024-0370 (proc-macro-error), RUSTSEC-2025-0075/0080/0081/0098/0100 (UNIC crates), and RUSTSEC-2024-0429 (glib iterator soundness). They are transitive dependencies of the desktop stack; glib is a non-Windows GTK dependency. These warnings remain visible and have no ignore entries. Review the upstream Tauri dependency graph when updating the desktop stack; the audit passing does not mean these warnings are resolved.

The license allowlist explicitly includes `Apache-2.0 WITH LLVM-exception` for target-lexicon's declared license. Duplicated transitive versions are warnings, not hidden. Check locally with `cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml --locked check`.

## Windows executable manifests

`build.rs` and `windows-app.manifest` embed Common Controls v6, long-path awareness and asInvoker into both the desktop executable and unit-test executables. Tauri's default resource hook targets binaries only; desktop library tests also need the manifest to load the dialog stack. Microsoft documents the Common Controls v6 requirement for [TaskDialogIndirect](https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-taskdialogindirect).

MSVC receives `/MANIFEST:EMBED` and `/MANIFESTINPUT`. GNU compiles one resource with `windres` and uses a build-local GCC `-B` prefix for `default-manifest.o`. This avoids conflicting application/default manifests with newer MinGW linkers and never changes installed toolchain files. Set `WINDRES` to the resource compiler executable when it is not on PATH. The app remains asInvoker; no elevation is requested.
