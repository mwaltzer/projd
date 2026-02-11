use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use projd_types::{
    default_socket_path, DownParams, ListResult, Request, Response, UpParams, UpResult,
    METHOD_DOWN, METHOD_LIST, METHOD_PING, METHOD_SHUTDOWN, METHOD_UP,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "proj", version, about = "CLI for the projd daemon")]
struct Cli {
    #[arg(long)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init,
    Up {
        path: Option<PathBuf>,
        #[arg(long, default_value_t = true)]
        autostart: bool,
    },
    Down {
        name: String,
        #[arg(long, default_value_t = true)]
        autostart: bool,
    },
    List {
        #[arg(long, default_value_t = true)]
        autostart: bool,
    },
    Ping {
        #[arg(long, default_value_t = true)]
        autostart: bool,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Start,
    Stop,
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Up { path, autostart } => cmd_up(&socket_path, path, autostart),
        Commands::Down { name, autostart } => cmd_down(&socket_path, &name, autostart),
        Commands::List { autostart } => cmd_list(&socket_path, autostart),
        Commands::Ping { autostart } => cmd_ping(&socket_path, autostart),
        Commands::Daemon { command } => match command {
            DaemonCommand::Start => cmd_start(&socket_path),
            DaemonCommand::Stop => cmd_stop(&socket_path),
            DaemonCommand::Status => cmd_status(&socket_path),
        },
    }
}

fn cmd_ping(socket_path: &Path, autostart: bool) -> Result<()> {
    let response = request_with_autostart(socket_path, METHOD_PING, Value::Null, autostart)?;
    print_ping(response)
}

fn cmd_start(socket_path: &Path) -> Result<()> {
    start_daemon(socket_path)?;
    let _ = wait_for_ping(socket_path, Duration::from_secs(3))?;
    println!("projd started ({})", socket_path.display());
    Ok(())
}

fn cmd_stop(socket_path: &Path) -> Result<()> {
    let response = request(socket_path, METHOD_SHUTDOWN, Value::Null)
        .with_context(|| format!("failed to stop daemon at {}", socket_path.display()))?;
    if !response.ok {
        bail!(
            "daemon returned error: {}",
            response.error.unwrap_or_else(|| "unknown".to_string())
        );
    }
    println!("projd stopping");
    Ok(())
}

fn cmd_status(socket_path: &Path) -> Result<()> {
    match request(socket_path, METHOD_PING, Value::Null) {
        Ok(_) => {
            println!("running ({})", socket_path.display());
            Ok(())
        }
        Err(_) => {
            println!("stopped ({})", socket_path.display());
            Ok(())
        }
    }
}

fn cmd_init() -> Result<()> {
    let cwd = fs::canonicalize(std::env::current_dir().context("failed to resolve cwd")?)
        .context("failed to canonicalize cwd")?;
    let toml_path = cwd.join(".project.toml");
    if toml_path.exists() {
        bail!("{} already exists", toml_path.display());
    }

    let default_name = cwd
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project");
    let content = format!(
        "name = \"{name}\"\npath = \"{path}\"\n\n[server]\ncommand = \"cargo run\"\nport_env = \"PORT\"\ncwd = \".\"\n\n[browser]\nurls = [\"http://localhost:${{PORT}}\"]\n",
        name = default_name,
        path = cwd.to_string_lossy()
    );
    fs::write(&toml_path, content)
        .with_context(|| format!("failed to write {}", toml_path.display()))?;
    println!("created {}", toml_path.display());
    Ok(())
}

fn cmd_up(socket_path: &Path, path: Option<PathBuf>, autostart: bool) -> Result<()> {
    let project_dir = resolve_project_dir(path)?;
    let params = UpParams {
        path: project_dir.to_string_lossy().to_string(),
    };
    let response = request_with_autostart(
        socket_path,
        METHOD_UP,
        serde_json::to_value(params).context("failed to serialize up params")?,
        autostart,
    )?;
    let result: UpResult = parse_ok_response(response)?;

    if result.created {
        println!(
            "registered {} workspace={} port={} path={}",
            result.project.name, result.project.workspace, result.project.port, result.project.path
        );
    } else {
        println!(
            "already registered {} workspace={} port={} path={}",
            result.project.name, result.project.workspace, result.project.port, result.project.path
        );
    }

    Ok(())
}

fn cmd_down(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let response = request_with_autostart(
        socket_path,
        METHOD_DOWN,
        serde_json::to_value(DownParams {
            name: name.to_string(),
        })
        .context("failed to serialize down params")?,
        autostart,
    )?;
    let result = parse_ok_response::<projd_types::ProjectRecord>(response)?;
    println!(
        "removed {} workspace={} port={}",
        result.name, result.workspace, result.port
    );
    Ok(())
}

fn cmd_list(socket_path: &Path, autostart: bool) -> Result<()> {
    let response = request_with_autostart(socket_path, METHOD_LIST, Value::Null, autostart)?;
    let result: ListResult = parse_ok_response(response)?;
    if result.projects.is_empty() {
        println!("no projects registered");
        return Ok(());
    }

    for project in result.projects {
        println!(
            "{}\t{}\t{}\t{}",
            project.name, project.workspace, project.port, project.path
        );
    }
    Ok(())
}

fn resolve_project_dir(path: Option<PathBuf>) -> Result<PathBuf> {
    let raw = match path {
        Some(path) => path,
        None => std::env::current_dir().context("failed to read current directory")?,
    };
    let canonical = fs::canonicalize(&raw)
        .with_context(|| format!("failed to resolve project path {}", raw.display()))?;
    if !canonical.is_dir() {
        bail!("project path is not a directory: {}", canonical.display());
    }
    Ok(canonical)
}

fn parse_ok_response<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    if !response.ok {
        bail!(
            "daemon returned error: {}",
            response.error.unwrap_or_else(|| "unknown".to_string())
        );
    }
    serde_json::from_value(response.result.unwrap_or(Value::Null))
        .context("failed to parse daemon response body")
}

fn print_ping(response: Response) -> Result<()> {
    if !response.ok {
        bail!(
            "daemon returned error: {}",
            response.error.unwrap_or_else(|| "unknown".to_string())
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&response.result.unwrap_or_else(|| json!({})))
            .context("failed to format ping response")?
    );
    Ok(())
}

fn request(socket_path: &Path, method: &str, params: Value) -> Result<Response> {
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

fn request_with_autostart(
    socket_path: &Path,
    method: &str,
    params: Value,
    autostart: bool,
) -> Result<Response> {
    match request(socket_path, method, params.clone()) {
        Ok(response) => Ok(response),
        Err(_) if autostart => {
            eprintln!("daemon unavailable, starting projd...");
            start_daemon(socket_path)?;
            let _ = wait_for_ping(socket_path, Duration::from_secs(3))?;
            request(socket_path, method, params)
        }
        Err(err) => Err(err),
    }
}

fn wait_for_ping(socket_path: &Path, timeout: Duration) -> Result<Response> {
    let attempts = (timeout.as_millis() / 100).max(1) as usize;
    let mut last_error: Option<anyhow::Error> = None;

    for _ in 0..attempts {
        match request(socket_path, METHOD_PING, Value::Null) {
            Ok(response) => return Ok(response),
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("timed out waiting for daemon")))
}

fn start_daemon(socket_path: &Path) -> Result<()> {
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
