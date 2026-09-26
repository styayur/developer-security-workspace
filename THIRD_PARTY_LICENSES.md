# Third-Party Licenses

This inventory is provided for the Preview release foundation. Build artifacts also include transitive dependencies whose license metadata is available from their packages.

## JavaScript and frontend

| Component | License | Use |
| --- | --- | --- |
| React / React DOM | MIT | UI |
| Vite | MIT | Build tooling |
| TypeScript | Apache-2.0 | Type system |
| Tailwind CSS | MIT | Styling |
| Radix UI primitives | MIT | Accessible UI primitives |
| Lucide | ISC | Icons |
| Monaco Editor | MIT | Source and JSON viewer |
| TanStack Query | MIT | Server-state synchronization |
| TanStack Virtual | MIT | Virtualized lists |
| Zustand | MIT | Local UI state |
| React Router | MIT | Routing |
| Motion | MIT | Small UI transitions |
| clsx | MIT | Class composition |
| tailwind-merge | MIT | Class conflict resolution |
| Vitest and Testing Library | MIT | Tests |

## Rust

| Component | License | Use |
| --- | --- | --- |
| Tauri | MIT OR Apache-2.0 | Desktop runtime |
| Tokio | MIT | Async runtime |
| Serde / serde_json | MIT OR Apache-2.0 | Serialization |
| rusqlite | MIT | SQLite bindings |
| SQLite | Public Domain | Local database engine |
| uuid | Apache-2.0 OR MIT | Identifiers |
| chrono | MIT OR Apache-2.0 | Timestamps |
| blake3 | CC0-1.0 OR Apache-2.0 | Fingerprinting |
| thiserror | MIT OR Apache-2.0 | Errors |
| tracing | MIT | Diagnostics |
| which | MIT | Executable discovery |
| walkdir | Unlicense OR MIT | Bounded file inspection |
| url | MIT OR Apache-2.0 | URI mapping |
| tempfile | MIT OR Apache-2.0 | Temporary scanner output |
| async-trait | MIT OR Apache-2.0 | Provider abstraction |

## Optional external tools

Semgrep, Trivy, TruffleHog, Bandit, and CodeQL are user-installed external tools and are not distributed in this repository. See docs/licensing.md and each project's official license text.
