use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::{Request, Response, METHOD_PING};

pub struct AutostartResponse {
    pub response: Response,
    pub daemon_was_started: bool,
}

pub fn request(socket_path: &Path, method: &str, params: Value) -> Result<Response> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to socket {}", socket_path.display()))?;
    let mut writer = BufWriter::new(
        stream
            .try_clone()
            .context("failed to clone socket stream")?,
    );
    let mut reader = BufReader::new(stream);

    let req = Request {
        id: 1,
        method: method.to_string(),
        params,
    };

    serde_json::to_writer(&mut writer, &req).context("failed to serialize request")?;
    writer
        .write_all(b"\n")
        .context("failed to write request newline")?;
    writer.flush().context("failed to flush request")?;

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read daemon response")?;
    if line.trim().is_empty() {
        bail!("daemon returned empty response");
    }

    serde_json::from_str::<Response>(&line).context("failed to parse daemon response")
}

pub fn parse_ok_response<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    if !response.ok {
        bail!(
            "daemon returned error: {}",
            response.error.unwrap_or_else(|| "unknown".to_string())
        );
    }
    serde_json::from_value(response.result.unwrap_or(Value::Null))
        .context("failed to parse daemon response body")
}

pub fn request_with_autostart(
    socket_path: &Path,
    method: &str,
    params: Value,
    autostart: bool,
) -> Result<AutostartResponse> {
    match request(socket_path, method, params.clone()) {
        Ok(response) => Ok(AutostartResponse {
            response,
            daemon_was_started: false,
        }),
        Err(_) if autostart => {
            eprintln!("daemon unavailable, starting projd...");
            start_daemon(socket_path)?;
            let _ = wait_for_ping(socket_path, Duration::from_secs(3))?;
            let response = request(socket_path, method, params)?;
            Ok(AutostartResponse {
                response,
                daemon_was_started: true,
            })
        }
        Err(err) => Err(err),
    }
}

pub fn wait_for_ping(socket_path: &Path, timeout: Duration) -> Result<Response> {
    let attempts = (timeout.as_millis() / 100).max(1) as usize;
    let mut last_error: Option<anyhow::Error> = None;

    for _ in 0..attempts {
        match request(socket_path, METHOD_PING, Value::Null) {
            Ok(response) => return Ok(response),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("timed out waiting for daemon")))
}

pub fn start_daemon(socket_path: &Path) -> Result<()> {
    let spawn = Command::new("projd")
        .arg("--socket")
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match spawn {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(local_projd) = detect_local_projd_binary() {
                let local_spawn = Command::new(local_projd)
                    .arg("--socket")
                    .arg(socket_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                if local_spawn.is_ok() {
                    return Ok(());
                }
            }

            Command::new("cargo")
                .args(["run", "-q", "-p", "projd", "--", "--socket"])
                .arg(socket_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("failed to spawn projd via cargo fallback")?;
            Ok(())
        }
        Err(err) => Err(err).context("failed to spawn projd"),
    }
}

pub fn detect_local_projd_binary() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let mut candidates = Vec::new();

    if let Some(bin_dir) = current_exe.parent() {
        candidates.push(bin_dir.join(projd_binary_name()));
        if let Some(debug_dir) = bin_dir.parent() {
            candidates.push(debug_dir.join(projd_binary_name()));
        }
    }

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(unix)]
pub const fn projd_binary_name() -> &'static str {
    "projd"
}

#[cfg(windows)]
pub const fn projd_binary_name() -> &'static str {
    "projd.exe"
}
