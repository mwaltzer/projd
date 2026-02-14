use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use projd_types::{
    default_niri_config_path, default_socket_path, DownParams, FocusResult, ListResult, LogsParams,
    LogsResult, NameParams, ProjectLifecycleState, ProjectStatus, Request, Response, StatusParams,
    StatusResult, UpParams, UpResult, DEFAULT_ROUTER_PORT, METHOD_DOWN, METHOD_FOCUS, METHOD_LIST,
    METHOD_LOGS, METHOD_PEEK, METHOD_PING, METHOD_RESUME, METHOD_SHUTDOWN, METHOD_STATUS,
    METHOD_SUSPEND, METHOD_SWITCH, METHOD_UP, NIRI_INTEGRATION_END, NIRI_INTEGRATION_START,
};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
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
    /// Create a starter .project.toml in the current directory.
    Init,
    /// Register and start a project from a path or project name.
    Up {
        #[arg(value_name = "PATH_OR_NAME")]
        path: Option<PathBuf>,
        #[arg(long, value_name = "WORKSPACE")]
        workspace: Option<String>,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    Down {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    List {
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Switch active project state and focus its workspace.
    Switch {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Focus project context (workspace + best-effort window surfacing).
    Focus {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Mark a project as suspended.
    Suspend {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Resume a suspended project and focus it.
    Resume {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Inspect project runtime state without mutating focus.
    Peek {
        name: String,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Show project lifecycle state.
    Status {
        name: Option<String>,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long, default_value_t = false)]
        watch: bool,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Show captured logs for a project/process.
    Logs {
        name: String,
        process: Option<String>,
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        tail: Option<usize>,
    },
    /// Ping daemon health.
    Ping {
        #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
        autostart: bool,
        #[arg(long = "no-autostart")]
        no_autostart: bool,
    },
    /// Manage daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Install optional integrations.
    Install {
        #[command(subcommand)]
        command: InstallCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Start,
    Stop,
    Status,
}

#[derive(Debug, Subcommand)]
enum InstallCommand {
    /// Install managed Niri keybinding and status-watch defaults.
    Niri {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Up {
            path,
            workspace,
            autostart,
            no_autostart,
        } => cmd_up(
            &socket_path,
            path,
            workspace,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Down {
            name,
            autostart,
            no_autostart,
        } => cmd_down(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::List {
            autostart,
            no_autostart,
        } => cmd_list(&socket_path, resolve_autostart(autostart, no_autostart)),
        Commands::Switch {
            name,
            autostart,
            no_autostart,
        } => cmd_switch(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Focus {
            name,
            autostart,
            no_autostart,
        } => cmd_focus(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Suspend {
            name,
            autostart,
            no_autostart,
        } => cmd_suspend(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Resume {
            name,
            autostart,
            no_autostart,
        } => cmd_resume(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Peek {
            name,
            autostart,
            no_autostart,
        } => cmd_peek(
            &socket_path,
            &name,
            resolve_autostart(autostart, no_autostart),
        ),
        Commands::Status {
            name,
            autostart,
            no_autostart,
            json,
            watch,
            interval_ms,
        } => cmd_status_projects(
            &socket_path,
            name,
            resolve_autostart(autostart, no_autostart),
            json,
            watch,
            interval_ms,
        ),
        Commands::Logs {
            name,
            process,
            autostart,
            no_autostart,
            json,
            tail,
        } => cmd_logs(
            &socket_path,
            &name,
            process.as_deref(),
            resolve_autostart(autostart, no_autostart),
            json,
            tail,
        ),
        Commands::Ping {
            autostart,
            no_autostart,
        } => cmd_ping(&socket_path, resolve_autostart(autostart, no_autostart)),
        Commands::Daemon { command } => match command {
            DaemonCommand::Start => cmd_start(&socket_path),
            DaemonCommand::Stop => cmd_stop(&socket_path),
            DaemonCommand::Status => cmd_status(&socket_path),
        },
        Commands::Install { command } => match command {
            InstallCommand::Niri {
                config,
                interval_ms,
            } => cmd_install_niri(config, interval_ms),
        },
    }
}

const fn resolve_autostart(autostart: bool, no_autostart: bool) -> bool {
    autostart && !no_autostart
}

fn cmd_ping(socket_path: &Path, autostart: bool) -> Result<()> {
    let resp = request_with_autostart(socket_path, METHOD_PING, Value::Null, autostart)?;
    print_ping(resp.response)
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
    let toml_path = init_project_config(&cwd)?;
    println!("created {}", toml_path.display());
    Ok(())
}

fn cmd_up(
    socket_path: &Path,
    path: Option<PathBuf>,
    workspace: Option<String>,
    autostart: bool,
) -> Result<()> {
    let project_dir = resolve_project_dir(socket_path, path, autostart)?;
    if let Some(created) = ensure_project_config_exists(&project_dir)? {
        println!("initialized {}", created.display());
    }
    let params = UpParams {
        path: project_dir.to_string_lossy().to_string(),
        workspace,
    };
    let resp = request_with_autostart(
        socket_path,
        METHOD_UP,
        serde_json::to_value(params).context("failed to serialize up params")?,
        autostart,
    )?;
    let daemon_was_started = resp.daemon_was_started;
    let result: UpResult = parse_ok_response(resp.response)?;

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
    if result.started_processes.is_empty() {
        println!("runtime processes: none");
    } else {
        println!("runtime processes: {}", result.started_processes.join(", "));
    }
    if !result.local_origin.is_empty() {
        println!("origin: {}", result.local_origin);
    }

    let dashboard_url = format!("http://localhost:{DEFAULT_ROUTER_PORT}");
    println!("dashboard: {dashboard_url}");
    if daemon_was_started {
        open_url_in_browser(&dashboard_url);
    }

    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(())
}

fn cmd_down(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let resp = request_with_autostart(
        socket_path,
        METHOD_DOWN,
        serde_json::to_value(DownParams {
            name: name.to_string(),
        })
        .context("failed to serialize down params")?,
        autostart,
    )?;
    let result = parse_ok_response::<projd_types::ProjectRecord>(resp.response)?;
    println!(
        "removed {} workspace={} port={}",
        result.name, result.workspace, result.port
    );
    Ok(())
}

fn cmd_list(socket_path: &Path, autostart: bool) -> Result<()> {
    let resp = request_with_autostart(socket_path, METHOD_LIST, Value::Null, autostart)?;
    let result: ListResult = parse_ok_response(resp.response)?;
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

fn cmd_switch(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let status = request_name_status(socket_path, METHOD_SWITCH, name, autostart)?;
    print_project_status(&status);
    Ok(())
}

fn cmd_focus(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let resp = request_with_autostart(
        socket_path,
        METHOD_FOCUS,
        serde_json::to_value(NameParams {
            name: name.to_string(),
        })
        .context("failed to serialize focus params")?,
        autostart,
    )?;
    let result: FocusResult = parse_ok_response(resp.response)?;
    print_project_status(&result.status);
    println!(
        "focus workspace_focused={} windows_surfaced={}",
        result.workspace_focused, result.windows_surfaced
    );
    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn cmd_suspend(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let status = request_name_status(socket_path, METHOD_SUSPEND, name, autostart)?;
    print_project_status(&status);
    Ok(())
}

fn cmd_resume(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let status = request_name_status(socket_path, METHOD_RESUME, name, autostart)?;
    print_project_status(&status);
    Ok(())
}

fn cmd_peek(socket_path: &Path, name: &str, autostart: bool) -> Result<()> {
    let status = request_name_status(socket_path, METHOD_PEEK, name, autostart)?;
    print_project_status(&status);
    Ok(())
}

fn cmd_status_projects(
    socket_path: &Path,
    name: Option<String>,
    autostart: bool,
    json_output: bool,
    watch: bool,
    interval_ms: u64,
) -> Result<()> {
    if !watch {
        let result = request_status_result(socket_path, name.as_deref(), autostart)?;
        print!("{}", format_status_output(&result, json_output)?);
        return Ok(());
    }

    let interval = Duration::from_millis(interval_ms.max(200));
    loop {
        let result = request_status_result(socket_path, name.as_deref(), autostart)?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&result).context("failed to serialize status JSON")?
            );
        } else {
            print!("\x1b[2J\x1b[H");
            print!("{}", format_status_output(&result, false)?);
        }
        io::stdout()
            .flush()
            .context("failed to flush status watch output")?;
        thread::sleep(interval);
    }
}

fn request_status_result(
    socket_path: &Path,
    name: Option<&str>,
    autostart: bool,
) -> Result<StatusResult> {
    let resp = request_with_autostart(
        socket_path,
        METHOD_STATUS,
        serde_json::to_value(StatusParams {
            name: name.map(ToString::to_string),
        })
        .context("failed to serialize status params")?,
        autostart,
    )?;
    parse_ok_response(resp.response)
}

fn cmd_logs(
    socket_path: &Path,
    name: &str,
    process: Option<&str>,
    autostart: bool,
    json_output: bool,
    tail: Option<usize>,
) -> Result<()> {
    let resp = request_with_autostart(
        socket_path,
        METHOD_LOGS,
        serde_json::to_value(LogsParams {
            name: name.to_string(),
            process: process.map(ToString::to_string),
        })
        .context("failed to serialize logs params")?,
        autostart,
    )?;
    let mut logs: LogsResult = parse_ok_response(resp.response)?;

    if let Some(tail_lines) = tail {
        for item in &mut logs.logs {
            item.content = tail_content_lines(&item.content, tail_lines);
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&logs).context("failed to serialize logs JSON")?
        );
    } else {
        if logs.logs.is_empty() {
            println!("no logs for {}", logs.project);
            return Ok(());
        }
        for (index, item) in logs.logs.iter().enumerate() {
            if logs.logs.len() > 1 {
                if index > 0 {
                    println!();
                }
                println!("== {} ({}) ==", item.process, item.path);
            }
            print!("{}", item.content);
            if !item.content.ends_with('\n') {
                println!();
            }
        }
    }
    Ok(())
}

fn tail_content_lines(content: &str, tail_lines: usize) -> String {
    if tail_lines == 0 {
        return String::new();
    }
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() <= tail_lines {
        return content.to_string();
    }
    let mut rendered = lines[lines.len() - tail_lines..].join("\n");
    if content.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

fn request_name_status(
    socket_path: &Path,
    method: &str,
    name: &str,
    autostart: bool,
) -> Result<ProjectStatus> {
    let resp = request_with_autostart(
        socket_path,
        method,
        serde_json::to_value(NameParams {
            name: name.to_string(),
        })
        .context("failed to serialize command params")?,
        autostart,
    )?;

    parse_ok_response(resp.response)
}

fn print_project_status(status: &ProjectStatus) {
    println!(
        "{}\tstate={}\tfocused={}\tworkspace={}\tport={}\tpath={}",
        status.project.name,
        lifecycle_state_label(&status.state),
        status.focused,
        status.project.workspace,
        status.project.port,
        status.project.path
    );
}

fn format_status_output(result: &StatusResult, json_output: bool) -> Result<String> {
    if json_output {
        return serde_json::to_string(result).context("failed to serialize status JSON");
    }
    if result.projects.is_empty() {
        return Ok("no projects registered\n".to_string());
    }

    let mut output = String::new();
    for status in &result.projects {
        let _ = writeln!(
            output,
            "{}\tstate={}\tfocused={}\tworkspace={}\tport={}\tpath={}",
            status.project.name,
            lifecycle_state_label(&status.state),
            status.focused,
            status.project.workspace,
            status.project.port,
            status.project.path
        );
    }
    Ok(output)
}

const fn lifecycle_state_label(state: &ProjectLifecycleState) -> &'static str {
    match state {
        ProjectLifecycleState::Active => "active",
        ProjectLifecycleState::Backgrounded => "backgrounded",
        ProjectLifecycleState::Suspended => "suspended",
        ProjectLifecycleState::Stopped => "stopped",
    }
}

fn resolve_project_dir(
    socket_path: &Path,
    path: Option<PathBuf>,
    autostart: bool,
) -> Result<PathBuf> {
    let raw = match path {
        Some(path) => path,
        None => {
            let cwd = std::env::current_dir().context("failed to read current directory")?;
            return canonicalize_existing_dir(&cwd);
        }
    };

    if raw.exists() {
        return canonicalize_existing_dir(&raw);
    }

    if let Some(name) = path_name_target(&raw) {
        if let Some(found) = try_find_project_path_by_name(socket_path, name, autostart) {
            return canonicalize_existing_dir(&found);
        }

        if let Some(found) = resolve_name_in_project_roots(name) {
            return Ok(found);
        }

        let roots = configured_project_roots();
        if roots.is_empty() {
            bail!("project '{name}' not found; provide a local project path");
        }
        let roots = roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("project '{name}' not found; tried registered projects and roots: {roots}");
    }

    let canonical = fs::canonicalize(&raw)
        .with_context(|| format!("failed to resolve project path {}", raw.display()))?;
    if !canonical.is_dir() {
        bail!("project path is not a directory: {}", canonical.display());
    }
    Ok(canonical)
}

fn canonicalize_existing_dir(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve project path {}", path.display()))?;
    if !canonical.is_dir() {
        bail!("project path is not a directory: {}", canonical.display());
    }
    Ok(canonical)
}

fn path_name_target(path: &Path) -> Option<&str> {
    if path.components().count() != 1 {
        return None;
    }
    let name = path.to_str()?;
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(name)
}

fn try_find_project_path_by_name(
    socket_path: &Path,
    name: &str,
    autostart: bool,
) -> Option<PathBuf> {
    let resp = request_with_autostart(socket_path, METHOD_LIST, Value::Null, autostart).ok()?;
    let listed: ListResult = parse_ok_response(resp.response).ok()?;
    listed
        .projects
        .into_iter()
        .find(|project| project.name == name)
        .map(|project| PathBuf::from(project.path))
}

fn resolve_name_in_project_roots(name: &str) -> Option<PathBuf> {
    for root in configured_project_roots() {
        let candidate = root.join(name);
        if candidate.is_dir() {
            if let Ok(canonical) = fs::canonicalize(candidate) {
                return Some(canonical);
            }
        }
    }
    None
}

fn configured_project_roots() -> Vec<PathBuf> {
    if let Ok(raw) = std::env::var("PROJ_PROJECT_ROOTS") {
        let roots: Vec<PathBuf> = raw
            .split(':')
            .filter_map(|item| {
                let item = item.trim();
                if item.is_empty() {
                    None
                } else {
                    Some(expand_tilde_path(item))
                }
            })
            .collect();
        if !roots.is_empty() {
            return roots;
        }
    }

    std::env::var_os("HOME")
        .map(|home| vec![PathBuf::from(home).join("Code")])
        .unwrap_or_default()
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }

    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }

    PathBuf::from(raw)
}

fn cmd_install_niri(config: Option<PathBuf>, interval_ms: u64) -> Result<()> {
    let config_path = config.unwrap_or_else(default_niri_config_path);
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let current = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };

    let status_watch_script = proj_config_dir().join("status-watch.sh");
    write_status_watch_script(&status_watch_script, interval_ms.max(200))?;

    let fragment = render_niri_integration_fragment(&status_watch_script, interval_ms.max(200));
    let updated = write_managed_install_section(&current, &fragment)?;
    fs::write(&config_path, updated)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("updated {}", config_path.display());
    println!("installed {}", status_watch_script.display());
    println!(
        "status stream: proj status --json --watch --interval-ms {}",
        interval_ms.max(200)
    );
    println!("focus command: proj focus <project>");
    Ok(())
}

fn proj_config_dir() -> PathBuf {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(value).join("proj");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("proj");
    }
    PathBuf::from(".config").join("proj")
}

fn write_status_watch_script(path: &Path, interval_ms: u64) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let content = format!(
        "#!/usr/bin/env sh\nset -eu\nexec proj status --json --watch --interval-ms {interval_ms}\n"
    );
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn render_niri_integration_fragment(status_watch_script: &Path, interval_ms: u64) -> String {
    format!(
        "// generated by proj install niri\n\
// Open the dashboard and run focus actions from there.\n\
binds {{\n\
  Mod+Shift+P {{ spawn \"proj-tui\"; }}\n\
}}\n\
// Bars/shells can stream status from:\n\
//   {}\n\
// Equivalent command:\n\
//   proj status --json --watch --interval-ms {}\n\
// Notification jump hint:\n\
//   proj focus <project>\n",
        status_watch_script.display(),
        interval_ms
    )
}

fn write_managed_install_section(config: &str, managed_fragment: &str) -> Result<String> {
    let managed_section = format!(
        "{start}\n{fragment}{end}\n",
        start = NIRI_INTEGRATION_START,
        fragment = with_trailing_newline(managed_fragment),
        end = NIRI_INTEGRATION_END
    );

    let start = config.find(NIRI_INTEGRATION_START);
    let end = config.find(NIRI_INTEGRATION_END);
    match (start, end) {
        (Some(start_idx), Some(end_idx)) => {
            if end_idx < start_idx {
                bail!("invalid niri config: integration marker end appears before start");
            }
            let end_bound = end_idx + NIRI_INTEGRATION_END.len();
            let mut output = String::new();
            output.push_str(&config[..start_idx]);
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&managed_section);
            let suffix = config[end_bound..].trim_start_matches('\n');
            if !suffix.is_empty() {
                output.push_str(suffix);
                if !output.ends_with('\n') {
                    output.push('\n');
                }
            }
            Ok(output)
        }
        (None, None) => {
            let mut output = config.to_string();
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            if !output.trim().is_empty() {
                output.push('\n');
            }
            output.push_str(&managed_section);
            Ok(output)
        }
        _ => bail!("invalid niri config: found only one proj install marker"),
    }
}

fn with_trailing_newline(value: &str) -> String {
    if value.ends_with('\n') {
        value.to_string()
    } else {
        format!("{value}\n")
    }
}

fn init_project_config(project_dir: &Path) -> Result<PathBuf> {
    let toml_path = project_dir.join(".project.toml");
    if toml_path.exists() {
        bail!("{} already exists", toml_path.display());
    }

    let content = render_default_project_config(project_dir);
    fs::write(&toml_path, content)
        .with_context(|| format!("failed to write {}", toml_path.display()))?;
    Ok(toml_path)
}

fn ensure_project_config_exists(project_dir: &Path) -> Result<Option<PathBuf>> {
    let toml_path = project_dir.join(".project.toml");
    if toml_path.exists() {
        return Ok(None);
    }
    init_project_config(project_dir).map(Some)
}

fn render_default_project_config(_project_dir: &Path) -> String {
    "# name defaults to directory name\n# docs: https://github.com/mwaltzer/projd#configuration\n\nserver = \"npm run dev\"\n".to_string()
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

struct AutostartResponse {
    response: Response,
    daemon_was_started: bool,
}

fn request_with_autostart(
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

fn open_url_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(not(target_os = "macos"))]
    let cmd = "xdg-open";

    let _ = Command::new(cmd)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
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

fn detect_local_projd_binary() -> Option<PathBuf> {
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
const fn projd_binary_name() -> &'static str {
    "projd"
}

#[cfg(windows)]
const fn projd_binary_name() -> &'static str {
    "projd.exe"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn path_name_target_accepts_single_relative_name() {
        assert_eq!(path_name_target(Path::new("frontend")), Some("frontend"));
        assert_eq!(path_name_target(Path::new(".")), None);
        assert_eq!(path_name_target(Path::new("a/b")), None);
    }

    #[test]
    fn configured_project_roots_prefers_env_var() {
        let _guard = env_lock().lock().unwrap();
        let root = unique_temp_dir("proj-roots-env");
        fs::create_dir_all(&root).unwrap();
        let alpha = root.join("alpha");
        let beta = root.join("beta");
        fs::create_dir_all(&alpha).unwrap();
        fs::create_dir_all(&beta).unwrap();

        let previous_roots = std::env::var_os("PROJ_PROJECT_ROOTS");
        let previous_home = std::env::var_os("HOME");
        std::env::set_var(
            "PROJ_PROJECT_ROOTS",
            format!(" {}::{} ", alpha.display(), beta.display()),
        );
        std::env::set_var("HOME", "/tmp/ignored-home");

        let roots = configured_project_roots();
        assert_eq!(roots, vec![alpha, beta]);

        restore_env("PROJ_PROJECT_ROOTS", previous_roots);
        restore_env("HOME", previous_home);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn configured_project_roots_defaults_to_home_code() {
        let _guard = env_lock().lock().unwrap();
        let home = unique_temp_dir("proj-roots-home");
        fs::create_dir_all(&home).unwrap();

        let previous_roots = std::env::var_os("PROJ_PROJECT_ROOTS");
        let previous_home = std::env::var_os("HOME");
        std::env::remove_var("PROJ_PROJECT_ROOTS");
        std::env::set_var("HOME", &home);

        let roots = configured_project_roots();
        assert_eq!(roots, vec![home.join("Code")]);

        restore_env("PROJ_PROJECT_ROOTS", previous_roots);
        restore_env("HOME", previous_home);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_name_in_project_roots_returns_canonical_match() {
        let _guard = env_lock().lock().unwrap();
        let root = unique_temp_dir("proj-resolve-name");
        let project = root.join("frontend");
        fs::create_dir_all(&project).unwrap();

        let previous_roots = std::env::var_os("PROJ_PROJECT_ROOTS");
        std::env::set_var("PROJ_PROJECT_ROOTS", root.to_string_lossy().to_string());

        let found = resolve_name_in_project_roots("frontend");
        assert_eq!(found, Some(fs::canonicalize(project).unwrap()));

        restore_env("PROJ_PROJECT_ROOTS", previous_roots);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_project_config_exists_creates_default_toml() {
        let dir = unique_temp_dir("proj-init-create");
        fs::create_dir_all(&dir).unwrap();

        let created = ensure_project_config_exists(&dir).unwrap();
        assert!(created.is_some());

        let toml_path = dir.join(".project.toml");
        let content = fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("server = \"npm run dev\""));
        assert!(content.contains("# name defaults to directory name"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_project_config_exists_is_noop_when_present() {
        let dir = unique_temp_dir("proj-init-existing");
        fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join(".project.toml");
        fs::write(&toml_path, "name = \"demo\"\npath = \".\"\n").unwrap();

        let created = ensure_project_config_exists(&dir).unwrap();
        assert!(created.is_none());

        let content = fs::read_to_string(&toml_path).unwrap();
        assert_eq!(content, "name = \"demo\"\npath = \".\"\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_status_output_supports_json_mode() {
        let result = StatusResult {
            projects: vec![ProjectStatus {
                project: projd_types::ProjectRecord {
                    name: "demo".to_string(),
                    workspace: "demo".to_string(),
                    port: 3001,
                    path: "/tmp/demo".to_string(),
                },
                state: ProjectLifecycleState::Active,
                focused: true,
            }],
        };
        let output = format_status_output(&result, true).unwrap();
        assert!(output.contains("\"projects\""));
        assert!(output.contains("\"demo\""));
        assert!(!output.contains('\n'));
    }

    #[test]
    fn format_status_output_supports_text_mode() {
        let result = StatusResult {
            projects: vec![ProjectStatus {
                project: projd_types::ProjectRecord {
                    name: "demo".to_string(),
                    workspace: "demo".to_string(),
                    port: 3001,
                    path: "/tmp/demo".to_string(),
                },
                state: ProjectLifecycleState::Backgrounded,
                focused: false,
            }],
        };
        let output = format_status_output(&result, false).unwrap();
        assert!(output.contains("demo"));
        assert!(output.contains("state=backgrounded"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn status_cli_supports_watch_and_interval_flags() {
        let cli = Cli::try_parse_from([
            "proj",
            "status",
            "--json",
            "--watch",
            "--interval-ms",
            "750",
        ])
        .unwrap();
        match cli.command {
            Commands::Status {
                json,
                watch,
                interval_ms,
                ..
            } => {
                assert!(json);
                assert!(watch);
                assert_eq!(interval_ms, 750);
            }
            _ => panic!("expected status command"),
        }
    }

    #[test]
    fn logs_cli_supports_json_and_tail_flags() {
        let cli = Cli::try_parse_from(["proj", "logs", "demo", "--json", "--tail", "25"]).unwrap();
        match cli.command {
            Commands::Logs { json, tail, .. } => {
                assert!(json);
                assert_eq!(tail, Some(25));
            }
            _ => panic!("expected logs command"),
        }
    }

    #[test]
    fn up_cli_supports_workspace_override_flag() {
        let cli = Cli::try_parse_from(["proj", "up", "frontend", "--workspace", "5"]).unwrap();
        match cli.command {
            Commands::Up {
                path, workspace, ..
            } => {
                assert_eq!(path, Some(PathBuf::from("frontend")));
                assert_eq!(workspace.as_deref(), Some("5"));
            }
            _ => panic!("expected up command"),
        }
    }

    #[test]
    fn tail_content_lines_returns_last_n_lines() {
        let content = "line-1\nline-2\nline-3\n";
        assert_eq!(tail_content_lines(content, 2), "line-2\nline-3\n");
        assert_eq!(tail_content_lines(content, 5), content);
        assert_eq!(tail_content_lines(content, 0), "");
    }

    #[test]
    fn focus_cli_supports_autostart_flags() {
        let cli = Cli::try_parse_from(["proj", "focus", "frontend", "--no-autostart"]).unwrap();
        match cli.command {
            Commands::Focus {
                name,
                autostart,
                no_autostart,
            } => {
                assert_eq!(name, "frontend");
                assert!(autostart);
                assert!(no_autostart);
                assert!(!resolve_autostart(autostart, no_autostart));
            }
            _ => panic!("expected focus command"),
        }
    }

    #[test]
    fn install_niri_cli_supports_config_and_interval_flags() {
        let cli = Cli::try_parse_from([
            "proj",
            "install",
            "niri",
            "--config",
            "/tmp/niri/config.kdl",
            "--interval-ms",
            "750",
        ])
        .unwrap();
        match cli.command {
            Commands::Install { command } => match command {
                InstallCommand::Niri {
                    config,
                    interval_ms,
                } => {
                    assert_eq!(config, Some(PathBuf::from("/tmp/niri/config.kdl")));
                    assert_eq!(interval_ms, 750);
                }
            },
            _ => panic!("expected install niri command"),
        }
    }

    #[test]
    fn write_managed_install_section_is_idempotent() {
        let source = "input {\n  keyboard {}\n}\n";
        let first = write_managed_install_section(source, "binds {}\n").unwrap();
        let second = write_managed_install_section(&first, "binds {}\n").unwrap();
        assert_eq!(first, second);
        assert!(second.contains(NIRI_INTEGRATION_START));
        assert!(second.contains(NIRI_INTEGRATION_END));
    }

    #[test]
    fn render_niri_integration_fragment_mentions_focus_and_status_watch() {
        let fragment = render_niri_integration_fragment(Path::new("/tmp/status-watch.sh"), 1000);
        assert!(fragment.contains("proj focus <project>"));
        assert!(fragment.contains("status-watch.sh"));
        assert!(fragment.contains("--interval-ms 1000"));
    }

    #[test]
    fn ping_autostart_defaults_true_and_supports_disable_flags() {
        let default_cli = Cli::try_parse_from(["proj", "ping"]).unwrap();
        match default_cli.command {
            Commands::Ping {
                autostart,
                no_autostart,
            } => {
                assert!(autostart);
                assert!(!no_autostart);
            }
            _ => panic!("expected ping command"),
        }

        let no_autostart_cli = Cli::try_parse_from(["proj", "ping", "--no-autostart"]).unwrap();
        match no_autostart_cli.command {
            Commands::Ping {
                autostart,
                no_autostart,
            } => {
                assert!(autostart);
                assert!(no_autostart);
                assert!(!resolve_autostart(autostart, no_autostart));
            }
            _ => panic!("expected ping command"),
        }

        let explicit_false_cli =
            Cli::try_parse_from(["proj", "ping", "--autostart=false"]).unwrap();
        match explicit_false_cli.command {
            Commands::Ping {
                autostart,
                no_autostart,
            } => {
                assert!(!autostart);
                assert!(!no_autostart);
                assert!(!resolve_autostart(autostart, no_autostart));
            }
            _ => panic!("expected ping command"),
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env(key: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("projd-proj-{label}-{nanos}"))
    }
}
