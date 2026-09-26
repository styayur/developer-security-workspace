use crate::error::{AppError, AppResult};
use std::path::{Component, Path, PathBuf};
use url::Url;

pub fn map_artifact_uri(workspace_root: &Path, uri: &str) -> AppResult<PathBuf> {
    let decoded = uri.replace("%20", " ");
    let candidate = if let Ok(url) = Url::parse(&decoded) {
        if url.scheme() == "file" {
            url.to_file_path()
                .map_err(|_| AppError::Sarif(format!("Invalid file URI: {uri}")))?
        } else if url.scheme().len() == 1 {
            PathBuf::from(decoded.replace('/', "\\"))
        } else {
            workspace_root.join(decoded)
        }
    } else {
        let path = PathBuf::from(&decoded);
        if path.is_absolute() {
            path
        } else {
            workspace_root.join(path)
        }
    };
    normalize_within(workspace_root, &candidate)
}

pub fn normalize_within(workspace_root: &Path, candidate: &Path) -> AppResult<PathBuf> {
    let root = normalize_path_lexically(workspace_root);
    let normalized = normalize_path_lexically(candidate);
    if !normalized.starts_with(&root) {
        return Err(AppError::Sarif(format!(
            "Location '{}' is outside the workspace '{}'.",
            candidate.display(),
            workspace_root.display()
        )));
    }
    Ok(normalized)
}

pub fn relative_display(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            other => output.push(other.as_os_str()),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_relative_uri() {
        let root = std::env::temp_dir().join("dsw-root");
        let path = map_artifact_uri(&root, "src/main.rs").expect("mapped");
        assert!(path.ends_with("src/main.rs"));
    }

    #[test]
    fn blocks_traversal() {
        let root = std::env::temp_dir().join("dsw-root");
        let error = map_artifact_uri(&root, "../../secret.txt").unwrap_err();
        assert!(error.to_string().contains("outside the workspace"));
    }

    #[test]
    fn maps_file_uri() {
        let root = std::env::temp_dir().join("dsw-root");
        let file = root.join("src").join("main.rs");
        let uri = Url::from_file_path(&file).expect("file url").to_string();
        let path = map_artifact_uri(&root, &uri).expect("mapped");
        assert!(path.ends_with("src/main.rs"));
    }
}
