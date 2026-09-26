use crate::error::{AppError, AppResult};
use crate::security_ir::LogEntry;
use chrono::Utc;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

const MAX_LOG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct CommandOutput {
    pub success: bool,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub async fn run_command(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    cancel: CancellationToken,
    logs: Option<UnboundedSender<LogEntry>>,
) -> AppResult<CommandOutput> {
    if !executable.exists() {
        return Err(AppError::Process(format!(
            "Executable does not exist: {}",
            executable.display()
        )));
    }
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().map_err(|error| {
        AppError::Process(format!("Unable to start {}: {error}", executable.display()))
    })?;
    let process_id = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Process("stdout was unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Process("stderr was unavailable".into()))?;
    let stdout_task = tokio::spawn(read_stream(stdout, "stdout".into(), logs.clone()));
    let stderr_task = tokio::spawn(read_stream(stderr, "stderr".into(), logs));
    let status = tokio::select! {
        result = child.wait() => result.map_err(|error| AppError::Process(format!("Process failed: {error}")))?,
        _ = cancel.cancelled() => {
            if let Some(pid) = process_id {
                terminate_process_tree(pid);
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(AppError::Process("Scan cancelled by user.".into()));
        }
    };
    let (stdout, _stdout_truncated) = stdout_task
        .await
        .map_err(|error| AppError::Process(format!("stdout reader failed: {error}")))??;
    let (stderr, _stderr_truncated) = stderr_task
        .await
        .map_err(|error| AppError::Process(format!("stderr reader failed: {error}")))??;
    Ok(CommandOutput {
        success: status.success(),
        status_code: status.code(),
        stdout,
        stderr,
    })
}

async fn read_stream<R>(
    stream: R,
    stream_name: String,
    logs: Option<UnboundedSender<LogEntry>>,
) -> AppResult<(String, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut output = String::new();
    let mut truncated = false;
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let bytes = reader.read_until(b'\n', &mut buffer).await?;
        if bytes == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&buffer).trim_end().to_string();
        let redacted = crate::secret_redaction::SecretRedactor::redact_text(&text);
        if let Some(sender) = &logs {
            let _ = sender.send(LogEntry {
                timestamp: Utc::now().to_rfc3339(),
                stream: stream_name.clone(),
                message: redacted.clone(),
            });
        }
        if output.len() < MAX_LOG_BYTES {
            let remaining = MAX_LOG_BYTES - output.len();
            if redacted.len() <= remaining {
                output.push_str(&redacted);
                output.push('\n');
            } else {
                output.extend(redacted.chars().take(remaining));
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((output, truncated))
}

pub fn terminate_process_tree(process_id: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &process_id.to_string(), "/T", "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &format!("-{process_id}")])
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_structured_arguments_without_shell() {
        let executable = if cfg!(windows) {
            which::which("where.exe").expect("where.exe")
        } else {
            std::path::PathBuf::from("/bin/echo")
        };
        let args = if cfg!(windows) {
            vec!["cmd.exe".into()]
        } else {
            vec!["safe argument".into()]
        };
        let output = run_command(
            &executable,
            &args,
            Path::new("."),
            CancellationToken::new(),
            None,
        )
        .await
        .expect("command runs");
        assert!(output.success);
        let expected = if cfg!(windows) {
            "cmd.exe"
        } else {
            "safe argument"
        };
        assert!(output.stdout.to_ascii_lowercase().contains(expected));
    }

    #[test]
    fn scanner_log_redaction_uses_secret_redactor() {
        let redacted = crate::secret_redaction::SecretRedactor::redact_text("AKIA1234567890ABCDEF");
        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(redacted.contains('•'));
    }
}
