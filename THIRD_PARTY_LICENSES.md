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
| time | MIT OR Apache-2.0 | Internal RFC3339 timestamps and durations |
| GLib 0.18.5 source backport | MIT | Optional GTK3 desktop bindings; original terms and per-file source provenance retained in `vendor/glib` and `security/glib-provenance.json` |
| blake3 | CC0-1.0 OR Apache-2.0 | Fingerprinting |
| thiserror | MIT OR Apache-2.0 | Errors |
| tracing | MIT | Diagnostics |
| which | MIT | Executable discovery |
| walkdir | Unlicense OR MIT | Bounded file inspection |
| url | MIT OR Apache-2.0 | URI mapping |
| tempfile | MIT OR Apache-2.0 | Temporary scanner output |
| async-trait | MIT OR Apache-2.0 | Provider abstraction |

## Optional external tools

The direct Chrono dependency and unused rusqlite Chrono feature were removed;
the complete platform lock can still list inactive optional Chrono through
other dependencies. This table is not a binary-composition claim. The reviewed
GLib source retains its upstream version and license, with upstream/local
changes disclosed in `security/glib-backport.md`. Imported native regression
helpers are Apache-2.0; full terms are in
`security/glib-regression/LICENSE-APACHE-2.0` and file headers identify that scope.

Semgrep, Trivy, TruffleHog, Bandit, and CodeQL are user-installed external tools and are not distributed in this repository. See docs/licensing.md and each project's official license text.
