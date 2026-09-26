# Contributing

## Development setup

1. Install Node.js 22+, pnpm, Rust stable, and the platform C++ build tools required by Tauri.
2. Run pnpm install.
3. Run pnpm tauri dev.

## Quality gate

Before opening a pull request:

~~~powershell
pnpm typecheck
pnpm test
pnpm build
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
~~~

## Architecture rules

- React never interprets raw SARIF as its domain model. Rust normalizes into Security IR.
- Scanner commands are constructed in Rust Providers using structured arguments.
- Do not invoke sh -c, cmd /c, PowerShell command strings, or equivalent shell evaluation for user-editable values.
- Do not silently download scanner binaries, rule packs, or CodeQL runtimes.
- Do not commit real secrets. Secret fixtures must be clearly synthetic.
- Do not add telemetry, analytics, login, or cloud upload without an explicit product decision and security review.
- Preserve third-party license and attribution boundaries.

## Scanner compatibility adapters

A compatibility adapter is acceptable when a scanner lacks SARIF support, but it must preserve the required security fields and pass through the same redaction and fingerprinting pipeline as SARIF. Document the adapter in the provider module and add tests.

## License

By contributing, you agree that your contribution is licensed under AGPL-3.0-only unless a separate written agreement applies.
