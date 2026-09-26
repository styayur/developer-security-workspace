use crate::security_ir::ComponentInfo;

pub fn components() -> Vec<ComponentInfo> {
    vec![
        component(
            "Tauri",
            "2",
            "MIT OR Apache-2.0",
            "Desktop application runtime and IPC boundary",
            "https://tauri.app/",
        ),
        component("React", "19", "MIT", "User interface", "https://react.dev/"),
        component(
            "Vite",
            "7",
            "MIT",
            "Frontend build tooling",
            "https://vite.dev/",
        ),
        component(
            "Tailwind CSS",
            "3",
            "MIT",
            "Utility styling system",
            "https://tailwindcss.com/",
        ),
        component(
            "Radix Primitives",
            "latest",
            "MIT",
            "Accessible UI primitives",
            "https://www.radix-ui.com/",
        ),
        component(
            "Monaco Editor",
            "0.52",
            "MIT",
            "Read-only source and JSON viewer",
            "https://microsoft.github.io/monaco-editor/",
        ),
        component(
            "TanStack Query",
            "5",
            "MIT",
            "Frontend data synchronization",
            "https://tanstack.com/query/",
        ),
        component(
            "TanStack Virtual",
            "3",
            "MIT",
            "Virtualized finding lists",
            "https://tanstack.com/virtual/",
        ),
        component(
            "Zustand",
            "5",
            "MIT",
            "Local UI state",
            "https://zustand.docs.pmnd.rs/",
        ),
        component(
            "SQLite / rusqlite",
            "0.37",
            "MIT",
            "Local scan history and triage persistence",
            "https://github.com/rusqlite/rusqlite",
        ),
        component(
            "Semgrep",
            "external",
            "LGPL-2.1 engine; rules separately licensed",
            "Optional external scanner",
            "https://semgrep.dev/",
        ),
        component(
            "Trivy",
            "external",
            "Apache-2.0",
            "Optional external scanner",
            "https://trivy.dev/",
        ),
        component(
            "TruffleHog",
            "external",
            "AGPL-3.0-only",
            "Optional external scanner",
            "https://github.com/trufflesecurity/trufflehog",
        ),
        component(
            "Bandit",
            "external",
            "Apache-2.0",
            "Optional external scanner",
            "https://bandit.readthedocs.io/",
        ),
        component(
            "CodeQL CLI",
            "external",
            "GitHub CodeQL Terms",
            "Separately licensed runtime, not bundled",
            "https://github.com/github/codeql-cli-binaries",
        ),
    ]
}

fn component(name: &str, version: &str, license: &str, purpose: &str, url: &str) -> ComponentInfo {
    ComponentInfo {
        name: name.into(),
        version: version.into(),
        license: license.into(),
        purpose: purpose.into(),
        url: url.into(),
    }
}
