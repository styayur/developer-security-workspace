use crate::error::{AppError, AppResult};
use crate::security_ir::{Project, SourceFile};
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

pub fn detect_project(path: &Path) -> AppResult<Project> {
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        AppError::Workspace(format!("Unable to open '{}': {error}", path.display()))
    })?;
    if !canonical.is_dir() {
        return Err(AppError::Workspace(format!(
            "'{}' is not a directory.",
            canonical.display()
        )));
    }
    let is_git = canonical.join(".git").exists();
    let branch = if is_git {
        git_value(&canonical, &["rev-parse", "--abbrev-ref", "HEAD"])
    } else {
        None
    };
    let commit_hash = if is_git {
        git_value(&canonical, &["rev-parse", "--short", "HEAD"])
    } else {
        None
    };
    let (file_count, primary_language) = inspect_files(&canonical);
    let name = canonical
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Workspace".to_string());
    let now = Utc::now().to_rfc3339();
    Ok(Project {
        id: Uuid::new_v4().to_string(),
        name,
        path: canonical.to_string_lossy().to_string(),
        is_git,
        branch,
        commit_hash,
        primary_language,
        file_count,
        last_opened_at: now.clone(),
        created_at: now,
    })
}

pub fn read_source_file(
    project: &Project,
    relative_path: &str,
    max_bytes: u64,
) -> AppResult<SourceFile> {
    let root = Path::new(&project.path);
    let candidate = if Path::new(relative_path).is_absolute() {
        PathBuf::from(relative_path)
    } else {
        root.join(relative_path)
    };
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
        AppError::Workspace(format!("Unable to read '{}': {error}", candidate.display()))
    })?;
    let canonical_root = std::fs::canonicalize(root)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(AppError::Workspace(
            "The requested file is outside the active workspace.".into(),
        ));
    }
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(AppError::Workspace(
            "The selected path is not a file.".into(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(AppError::Workspace(format!(
            "File is too large for inline rendering. Limit: {} bytes.",
            max_bytes
        )));
    }
    let bytes = std::fs::read(&canonical)?;
    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        return Err(AppError::Workspace(
            "Binary files cannot be rendered in the source viewer.".into(),
        ));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| AppError::Workspace("The file is not valid UTF-8 text.".into()))?;
    Ok(SourceFile {
        path: relative_path.replace('\\', "/"),
        absolute_path: canonical.to_string_lossy().to_string(),
        language: language_for(&canonical),
        content,
        size: metadata.len(),
        truncated: false,
    })
}

fn git_value(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn inspect_files(root: &Path) -> (u64, String) {
    let mut languages: HashMap<&'static str, u64> = HashMap::new();
    let mut count = 0_u64;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_visit)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        count += 1;
        if let Some(language) = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .and_then(extension_language)
        {
            *languages.entry(language).or_default() += 1;
        }
    }
    let primary = languages
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(language, _)| language.to_string())
        .unwrap_or_else(|| "Other".into());
    (count, primary)
}

fn should_visit(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    if !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        name.as_ref(),
        ".git" | "node_modules" | "target" | "dist" | "coverage" | ".next" | ".venv" | "venv"
    )
}

fn extension_language(extension: &str) -> Option<&'static str> {
    match extension.to_ascii_lowercase().as_str() {
        "rs" => Some("Rust"),
        "ts" | "tsx" => Some("TypeScript"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "cs" => Some("C#"),
        "cpp" | "cc" | "cxx" | "hpp" => Some("C++"),
        "c" | "h" => Some("C"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "swift" => Some("Swift"),
        "kt" | "kts" => Some("Kotlin"),
        "tf" | "tfvars" => Some("Terraform"),
        "dockerfile" => Some("Docker"),
        "yaml" | "yml" => Some("YAML"),
        "json" => Some("JSON"),
        "toml" => Some("TOML"),
        _ => None,
    }
}

pub fn language_for(path: &Path) -> String {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("Dockerfile"))
    {
        return "dockerfile".into();
    }
    path.extension()
        .and_then(|value| value.to_str())
        .and_then(extension_language)
        .unwrap_or("plaintext")
        .to_ascii_lowercase()
}

pub fn demo_workspace_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("src/api/user.ts", "import express from \"express\";\nimport { db } from \"../db\";\n\nconst router = express.Router();\n\nrouter.get(\"/user\", async (req, res) => {\n  const id = req.query.id as string;\n  const query = `SELECT * FROM users WHERE id = '${id}'`;\n  const result = await db.query(query);\n  res.json(result.rows[0]);\n});\n\nexport default router;\n"),
        ("src/db.ts", "export const db = {\n  async query(sql: string) {\n    // Demo-only adapter. No real database is used.\n    return { rows: [{ sql }] };\n  }\n};\n"),
        ("scripts/legacy_task.py", "import subprocess\n\n\ndef run_report(path):\n    # Demo fixture: unsafe command construction for Bandit parsing.\n    command = \"cat \" + path\n    return subprocess.check_output(command, shell=True)\n"),
        (".env.example", "EXAMPLE_NOT_A_REAL_SECRET\nDATABASE_URL=postgres://local/demo\n"),
        ("package-lock.json", "{\n  \"name\": \"demo-workspace\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/example-package\": { \"version\": \"0.0.0\" }\n  }\n}\n"),
        ("README.md", "# Demo Workspace\n\nThis workspace is generated locally so the bundled SARIF fixtures can be exercised through the real parser.\n"),
    ]
}

pub fn ensure_demo_workspace(root: &Path) -> AppResult<()> {
    for (relative, content) in demo_workspace_files() {
        let destination = root.join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !destination.exists() {
            std::fs::write(destination, content)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unicode_space_path() {
        let root = std::env::temp_dir().join("dsw demo ünicode");
        std::fs::create_dir_all(&root).expect("temp dir");
        std::fs::write(root.join("main.rs"), "fn main() {}").expect("file");
        let project = detect_project(&root).expect("project");
        assert_eq!(project.primary_language, "Rust");
        assert_eq!(project.file_count, 1);
    }

    #[test]
    fn rejects_paths_outside_workspace() {
        let root = std::env::temp_dir().join("dsw-read-root");
        std::fs::create_dir_all(&root).expect("temp dir");
        let project = Project {
            path: root.to_string_lossy().to_string(),
            ..Default::default()
        };
        let error = read_source_file(&project, "../outside.txt", 1024).unwrap_err();
        assert!(
            error.to_string().contains("Unable to read") || error.to_string().contains("outside")
        );
    }
}
