use crate::error::{AppError, AppResult};
use crate::security_ir::LogEntry;
use chrono::Utc;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt};
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
    run_inner(executable, args, cwd, cancel, logs, false).await
}

/// Machine output is captured separately from redacted human logs and never emitted as log events.
pub async fn run_command_data(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    cancel: CancellationToken,
    logs: Option<UnboundedSender<LogEntry>>,
) -> AppResult<CommandOutput> {
    run_inner(executable, args, cwd, cancel, logs, true).await
}
async fn run_inner(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    cancel: CancellationToken,
    logs: Option<UnboundedSender<LogEntry>>,
    machine: bool,
) -> AppResult<CommandOutput> {
    if cancel.is_cancelled() {
        return Err(AppError::Process("Scan cancelled by user.".into()));
    }
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
    command
        .env_remove("GITLEAKS_CONFIG")
        .env_remove("GITLEAKS_CONFIG_TOML");
    #[cfg(unix)]
    command.process_group(0);
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
    let stdout_task = tokio::spawn(read_stream(
        stdout,
        "stdout".into(),
        if machine { None } else { logs.clone() },
        if machine {
            crate::sarif::MAX_SARIF_BYTES
        } else {
            MAX_LOG_BYTES
        },
        machine,
    ));
    let stderr_task = tokio::spawn(read_stream(
        stderr,
        "stderr".into(),
        logs,
        MAX_LOG_BYTES,
        false,
    ));
    let status = tokio::select! {
        result = child.wait() => result.map_err(|error| AppError::Process(format!("Process failed: {error}")))?,
        _ = cancel.cancelled() => {
            if let Some(pid) = process_id {
                terminate_process_tree(pid);
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            return Err(AppError::Process("Scan cancelled by user.".into()));
        }
    };
    let (stdout, stdout_truncated) = stdout_task
        .await
        .map_err(|error| AppError::Process(format!("stdout reader failed: {error}")))??;
    let (stderr, _stderr_truncated) = stderr_task
        .await
        .map_err(|error| AppError::Process(format!("stderr reader failed: {error}")))??;
    if machine && stdout_truncated {
        return Err(AppError::Process(
            "Scanner data exceeded the 128 MiB output limit; no partial results were imported."
                .into(),
        ));
    }
    Ok(CommandOutput {
        success: status.success(),
        status_code: status.code(),
        stdout,
        stderr,
    })
}

async fn read_stream<R>(
    mut stream: R,
    stream_name: String,
    logs: Option<UnboundedSender<LogEntry>>,
    limit: usize,
    machine: bool,
) -> AppResult<(String, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = [0u8; 16384];
    let mut truncated = false;
    let mut line = Vec::new();
    let mut oversized = false;
    let mut emitted = 0usize;
    let mut log_bytes = 0usize;
    let mut private_key = false;
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
        // Bounded lines and bounded event count: a scanner cannot grow a log queue indefinitely.
        if logs.is_some() && emitted < 2000 && log_bytes < MAX_LOG_BYTES {
            for byte in &buffer[..count] {
                if *byte == b'\n' {
                    let text = String::from_utf8_lossy(&line);
                    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY") {
                        private_key = true;
                    }
                    let redacted = if private_key || oversized {
                        "[sensitive or oversized log line omitted]".into()
                    } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        crate::secret_redaction::SecretRedactor::redact_json(&value).to_string()
                    } else {
                        crate::secret_redaction::SecretRedactor::redact_text(&text)
                    };
                    if text.contains("-----END") && text.contains("PRIVATE KEY") {
                        private_key = false;
                    }
                    if emitted < 2000 && log_bytes + redacted.len() <= MAX_LOG_BYTES {
                        if let Some(sender) = &logs {
                            let _ = sender.send(LogEntry {
                                timestamp: Utc::now().to_rfc3339(),
                                stream: stream_name.clone(),
                                message: redacted.clone(),
                            });
                        }
                        emitted += 1;
                        log_bytes += redacted.len();
                    }
                    line.clear();
                    oversized = false;
                } else if line.len() < 8192 {
                    line.push(*byte);
                } else {
                    oversized = true;
                }
            }
        }
    }
    let text = String::from_utf8_lossy(&output);
    Ok((
        if machine {
            text.into_owned()
        } else {
            redact_capture(&text, truncated)
        },
        truncated,
    ))
}

fn redact_capture(text: &str, truncated: bool) -> String {
    use crate::secret_redaction::SecretRedactor;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return SecretRedactor::redact_json(&value).to_string();
    }
    let redacted = SecretRedactor::redact_text(text);
    let mut private_key = false;
    redacted
        .split_inclusive('\n')
        .map(|line| {
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
                private_key = true;
            }
            let omit = private_key || (truncated && !line.ends_with('\n'));
            if line.contains("-----END") && line.contains("PRIVATE KEY") {
                private_key = false;
            }
            if omit {
                "[sensitive or truncated log line omitted]\n".to_string()
            } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                format!("{}\n", SecretRedactor::redact_json(&value))
            } else {
                line.to_string()
            }
        })
        .collect()
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
    #[tokio::test]
    async fn huge_unterminated_logs_and_multibyte_capture_are_bounded() {
        let input = vec![b'x'; 3 * 1024 * 1024];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (output, truncated) =
            read_stream(input.as_slice(), "stderr".into(), Some(tx), 1024, false)
                .await
                .unwrap();
        assert!(output.len() <= 1024);
        assert!(truncated);
        assert!(rx.try_recv().is_err());
        let input = "多".repeat(1000);
        let (output, truncated) = read_stream(input.as_bytes(), "stdout".into(), None, 300, true)
            .await
            .unwrap();
        assert_eq!(output.len(), 300);
        assert!(truncated);
    }
    #[tokio::test]
    async fn log_events_are_capped_and_json_secret_values_are_redacted() {
        let input = format!(
            "{}{}",
            "{\"Raw\":\"SYNTHETIC_NOT_A_SECRET\"}\n",
            "hello\n".repeat(10000)
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (capture, _) = read_stream(input.as_bytes(), "stderr".into(), Some(tx), 1024, false)
            .await
            .unwrap();
        assert!(!capture.contains("SYNTHETIC_NOT_A_SECRET"));
        let mut count = 0;
        while let Ok(entry) = rx.try_recv() {
            count += 1;
            assert!(!entry.message.contains("SYNTHETIC_NOT_A_SECRET"));
        }
        assert_eq!(count, 2000);
    }
    #[tokio::test]
    async fn cancellation_stops_a_running_process_promptly() {
        let (executable, args) = if cfg!(windows) {
            (
                which::which("ping.exe").unwrap(),
                vec!["-n".into(), "30".into(), "127.0.0.1".into()],
            )
        } else {
            (std::path::PathBuf::from("/bin/sleep"), vec!["30".into()])
        };
        let token = CancellationToken::new();
        let trigger = token.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            trigger.cancel();
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_command(&executable, &args, Path::new("."), token, None),
        )
        .await;
        cancel_task.await.unwrap();
        assert!(result
            .expect("cancellation must not hang")
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
    }
    #[tokio::test]
    async fn cancellation_does_not_spawn_a_process() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(run_command(
            Path::new("does-not-exist"),
            &[],
            Path::new("."),
            cancel,
            None
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    }
}
