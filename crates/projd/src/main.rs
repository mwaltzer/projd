use anyhow::{bail, Context, Result};
use clap::Parser;
use projd_types::{
    default_niri_config_path, default_socket_path, default_state_path, DownParams, ListResult,
    PersistedState, ProjectRecord, Request, Response, UpParams, UpResult, METHOD_DOWN, METHOD_LIST,
    METHOD_PING, METHOD_SHUTDOWN, METHOD_UP, NIRI_MANAGED_END, NIRI_MANAGED_START,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "projd", version, about = "Project daemon for proj CLI")]
struct Args {
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long)]
    niri_config: Option<PathBuf>,
}

fn main() -> Result<()> {
    init_logging();
    let args = Args::parse();
    let socket_path = args.socket.unwrap_or_else(default_socket_path);
    let state_path = args
        .state
        .or_else(|| std::env::var_os("PROJD_STATE_PATH").map(PathBuf::from))
        .unwrap_or_else(default_state_path);
    let niri_config_path = args
        .niri_config
        .or_else(|| std::env::var_os("PROJD_NIRI_CONFIG").map(PathBuf::from))
        .unwrap_or_else(default_niri_config_path);
    let mut app_state = AppState::load(state_path, niri_config_path)?;

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create socket directory: {}", parent.display()))?;
    }

    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .with_context(|| format!("failed to remove stale socket: {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind socket: {}", socket_path.display()))?;
    listener
        .set_nonblocking(true)
        .context("failed to set listener as non-blocking")?;

    info!("projd listening on {}", socket_path.display());
    let running = Arc::new(AtomicBool::new(true));

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(err) = handle_client(stream, running.clone(), &mut app_state) {
                    error!("client handling failed: {err:#}");
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => {
                warn!("accept error: {err}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    info!("projd shutdown complete");
    Ok(())
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("PROJD_LOG")
                .or_else(|_| std::env::var("RUST_LOG"))
                .unwrap_or_else(|_| "info".to_string()),
        )
        .try_init();
}

fn handle_client(
    stream: UnixStream,
    running: Arc<AtomicBool>,
    app_state: &mut AppState,
) -> Result<()> {
    let reader = BufReader::new(
        stream
            .try_clone()
            .context("failed to clone client stream")?,
    );
    let mut writer = BufWriter::new(stream);

    for line in reader.lines() {
        let line = line.context("failed reading client request")?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(err) => {
                let response = Response::err(0, format!("invalid request JSON: {err}"));
                write_response(&mut writer, &response)?;
                continue;
            }
        };

        let (response, should_shutdown) = handle_request(&request, app_state);
        write_response(&mut writer, &response)?;

        if should_shutdown {
            running.store(false, Ordering::SeqCst);
            break;
        }
    }

    Ok(())
}

fn write_response(writer: &mut BufWriter<UnixStream>, response: &Response) -> Result<()> {
    serde_json::to_writer(&mut *writer, response).context("failed to serialize response")?;
    writer.write_all(b"\n").context("failed to write newline")?;
    writer.flush().context("failed to flush response")?;
    Ok(())
}

fn handle_request(request: &Request, app_state: &mut AppState) -> (Response, bool) {
    match request.method.as_str() {
        METHOD_PING => (
            Response::ok(
                request.id,
                json!({
                    "pong": true,
                    "daemon": "projd",
                    "version": env!("CARGO_PKG_VERSION")
                }),
            ),
            false,
        ),
        METHOD_SHUTDOWN => (Response::ok(request.id, json!({"stopping": true})), true),
        METHOD_UP => match parse_params::<UpParams>(&request.params)
            .and_then(|params| app_state.up(params))
        {
            Ok(result) => (
                Response::ok(
                    request.id,
                    serde_json::to_value(result).unwrap_or_else(|_| json!({})),
                ),
                false,
            ),
            Err(err) => (Response::err(request.id, err.to_string()), false),
        },
        METHOD_DOWN => {
            match parse_params::<DownParams>(&request.params)
                .and_then(|params| app_state.down(params))
            {
                Ok(project) => (
                    Response::ok(
                        request.id,
                        serde_json::to_value(project).unwrap_or_else(|_| json!({})),
                    ),
                    false,
                ),
                Err(err) => (Response::err(request.id, err.to_string()), false),
            }
        }
        METHOD_LIST => {
            let result = app_state.list();
            (
                Response::ok(
                    request.id,
                    serde_json::to_value(result).unwrap_or_else(|_| json!({})),
                ),
                false,
            )
        }
        method => (
            Response::err(request.id, format!("unknown method: {method}")),
            false,
        ),
    }
}

fn parse_params<T: DeserializeOwned>(params: &serde_json::Value) -> Result<T> {
    serde_json::from_value(params.clone()).context("invalid request params")
}

#[derive(Debug)]
struct AppState {
    projects: BTreeMap<String, ProjectRecord>,
    state_path: PathBuf,
    niri_config_path: PathBuf,
}

impl AppState {
    fn load(state_path: PathBuf, niri_config_path: PathBuf) -> Result<Self> {
        let mut projects = BTreeMap::new();
        if state_path.exists() {
            let raw = fs::read_to_string(&state_path)
                .with_context(|| format!("failed to read state file: {}", state_path.display()))?;
            if !raw.trim().is_empty() {
                let persisted: PersistedState =
                    serde_json::from_str(&raw).context("failed to parse persisted state")?;
                for project in persisted.projects {
                    if projects.contains_key(&project.name) {
                        bail!("duplicate project name in state: {}", project.name);
                    }
                    projects.insert(project.name.clone(), project);
                }
            }
        }

        Ok(Self {
            projects,
            state_path,
            niri_config_path,
        })
    }

    fn up(&mut self, params: UpParams) -> Result<UpResult> {
        let project_dir = fs::canonicalize(&params.path)
            .with_context(|| format!("failed to resolve project path: {}", params.path))?;
        if !project_dir.is_dir() {
            bail!("project path is not a directory: {}", project_dir.display());
        }

        let project_cfg = load_project_config(&project_dir)?;
        let project_path = path_to_string(&project_cfg.path);

        if let Some(existing) = self.projects.get(&project_cfg.name) {
            if existing.path == project_path {
                return Ok(UpResult {
                    project: existing.clone(),
                    created: false,
                });
            }
            bail!(
                "project '{}' is already registered with path {}",
                project_cfg.name,
                existing.path
            );
        }

        if let Some(conflict) = self
            .projects
            .values()
            .find(|project| project.path == project_path)
        {
            bail!(
                "path '{}' is already registered by project '{}'",
                project_path,
                conflict.name
            );
        }

        let project = ProjectRecord {
            name: project_cfg.name.clone(),
            path: project_path,
            workspace: project_cfg.name,
            port: self.allocate_port()?,
        };

        let previous = self.projects.clone();
        self.projects.insert(project.name.clone(), project.clone());
        if let Err(err) = self.sync() {
            self.projects = previous;
            return Err(err);
        }

        Ok(UpResult {
            project,
            created: true,
        })
    }

    fn down(&mut self, params: DownParams) -> Result<ProjectRecord> {
        if !self.projects.contains_key(&params.name) {
            bail!("project '{}' is not registered", params.name);
        }

        let previous = self.projects.clone();
        let removed = self
            .projects
            .remove(&params.name)
            .expect("checked presence above");
        if let Err(err) = self.sync() {
            self.projects = previous;
            return Err(err);
        }

        Ok(removed)
    }

    fn list(&self) -> ListResult {
        ListResult {
            projects: self.projects.values().cloned().collect(),
        }
    }

    fn allocate_port(&self) -> Result<u16> {
        let used: HashSet<u16> = self.projects.values().map(|project| project.port).collect();
        for port in 3001..=3999 {
            if !used.contains(&port) {
                return Ok(port);
            }
        }
        bail!("no available ports in range 3001..3999")
    }

    fn sync(&self) -> Result<()> {
        self.write_niri_config()?;
        self.persist_state()
    }

    fn persist_state(&self) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create state directory: {}", parent.display())
            })?;
        }
        let state = PersistedState {
            projects: self.projects.values().cloned().collect(),
        };
        let data =
            serde_json::to_string_pretty(&state).context("failed to serialize daemon state")?;
        fs::write(&self.state_path, data).with_context(|| {
            format!("failed to write state file: {}", self.state_path.display())
        })?;
        Ok(())
    }

    fn write_niri_config(&self) -> Result<()> {
        if let Some(parent) = self.niri_config_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create niri config directory: {}",
                    parent.display()
                )
            })?;
        }

        let current = if self.niri_config_path.exists() {
            fs::read_to_string(&self.niri_config_path).with_context(|| {
                format!(
                    "failed to read niri config file: {}",
                    self.niri_config_path.display()
                )
            })?
        } else {
            String::new()
        };

        let managed_fragment = render_niri_fragment(&self.projects);
        let updated = write_managed_section(&current, &managed_fragment)?;
        fs::write(&self.niri_config_path, updated).with_context(|| {
            format!(
                "failed to write niri config file: {}",
                self.niri_config_path.display()
            )
        })?;
        Ok(())
    }
}

#[derive(Debug)]
struct LoadedProjectConfig {
    name: String,
    path: PathBuf,
}

#[derive(Debug)]
struct ProjectConfigFields {
    name: String,
    path: String,
}

fn load_project_config(project_dir: &Path) -> Result<LoadedProjectConfig> {
    let toml_path = project_dir.join(".project.toml");
    if !toml_path.exists() {
        bail!("missing project config: expected {}", toml_path.display());
    }

    let raw = fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;
    let parsed =
        parse_project_toml(&raw).context("invalid .project.toml (expected top-level name/path)")?;

    let name = parsed.name.trim().to_string();
    if name.is_empty() {
        bail!("project name in .project.toml cannot be empty");
    }

    let normalized_path = normalize_project_path(&parsed.path, project_dir)?;
    Ok(LoadedProjectConfig {
        name,
        path: normalized_path,
    })
}

fn parse_project_toml(raw: &str) -> Result<ProjectConfigFields> {
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = parse_toml_scalar(value.trim());
        match key {
            "name" => name = Some(value),
            "path" => path = Some(value),
            _ => {}
        }
    }

    let name = name.ok_or_else(|| anyhow::anyhow!("missing top-level 'name' field"))?;
    let path = path.ok_or_else(|| anyhow::anyhow!("missing top-level 'path' field"))?;
    Ok(ProjectConfigFields { name, path })
}

fn parse_toml_scalar(value: &str) -> String {
    let without_comment = value
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim();
    parse_quoted_scalar(without_comment)
}

fn parse_quoted_scalar(value: &str) -> String {
    let unquoted = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    unquoted.trim().to_string()
}

fn normalize_project_path(raw_path: &str, base_dir: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(raw_path);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        base_dir.join(expanded)
    };

    fs::canonicalize(&candidate).with_context(|| {
        format!(
            "failed to resolve configured project path: {}",
            candidate.display()
        )
    })
}

fn expand_tilde(raw_path: &str) -> PathBuf {
    if raw_path == "~" || raw_path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            if raw_path == "~" {
                return home;
            }
            return home.join(raw_path.trim_start_matches("~/"));
        }
    }

    PathBuf::from(raw_path)
}

fn render_niri_fragment(projects: &BTreeMap<String, ProjectRecord>) -> String {
    let mut rendered = String::from("// generated by projd\n");
    for project in projects.values() {
        let workspace = escape_kdl_string(&project.workspace);
        let title_tag = escape_kdl_string(&format!("[proj:{}]", project.name));
        rendered.push_str(&format!("workspace \"{workspace}\"\n"));
        rendered.push_str("window-rule {\n");
        rendered.push_str(&format!("  match title=\"{title_tag}\"\n"));
        rendered.push_str(&format!("  open-on-workspace \"{workspace}\"\n"));
        rendered.push_str("}\n");
    }
    rendered
}

fn escape_kdl_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_managed_section(config: &str, managed_fragment: &str) -> Result<String> {
    let managed_section = format!(
        "{start}\n{fragment}{end}\n",
        start = NIRI_MANAGED_START,
        fragment = with_trailing_newline(managed_fragment),
        end = NIRI_MANAGED_END
    );

    let start = config.find(NIRI_MANAGED_START);
    let end = config.find(NIRI_MANAGED_END);

    match (start, end) {
        (Some(start_idx), Some(end_idx)) => {
            if end_idx < start_idx {
                bail!("invalid niri config: managed marker end appears before start");
            }
            let end_bound = end_idx + NIRI_MANAGED_END.len();
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
        _ => bail!("invalid niri config: found only one projd managed marker"),
    }
}

fn with_trailing_newline(value: &str) -> String {
    if value.ends_with('\n') {
        value.to_string()
    } else {
        format!("{value}\n")
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_managed_section_appends_when_markers_are_missing() {
        let original = "input {\n  keyboard {}\n}\n";
        let updated = write_managed_section(original, "// generated by projd\n").unwrap();
        assert!(updated.contains(NIRI_MANAGED_START));
        assert!(updated.contains(NIRI_MANAGED_END));
    }

    #[test]
    fn write_managed_section_replaces_existing_section() {
        let original = format!(
            "{start}\nold content\n{end}\n",
            start = NIRI_MANAGED_START,
            end = NIRI_MANAGED_END
        );
        let updated = write_managed_section(&original, "new content\n").unwrap();
        assert!(updated.contains("new content"));
        assert!(!updated.contains("old content"));
    }

    #[test]
    fn write_managed_section_rejects_partial_markers() {
        let original = format!("{start}\nmissing end marker\n", start = NIRI_MANAGED_START);
        let err = write_managed_section(&original, "anything\n").unwrap_err();
        assert!(err
            .to_string()
            .contains("found only one projd managed marker"));
    }

    #[test]
    fn allocate_port_skips_existing_ports() {
        let mut projects = BTreeMap::new();
        projects.insert(
            "a".to_string(),
            ProjectRecord {
                name: "a".to_string(),
                path: "/tmp/a".to_string(),
                workspace: "a".to_string(),
                port: 3001,
            },
        );
        let state = AppState {
            projects,
            state_path: PathBuf::from("/tmp/state.json"),
            niri_config_path: PathBuf::from("/tmp/config.kdl"),
        };
        assert_eq!(state.allocate_port().unwrap(), 3002);
    }

    #[test]
    fn load_project_config_resolves_relative_path_from_toml() {
        let base = unique_temp_dir("load-project-config-toml");
        fs::create_dir_all(&base).unwrap();
        fs::write(
            base.join(".project.toml"),
            "name = \"demo\"\npath = \".\"\n",
        )
        .unwrap();

        let loaded = load_project_config(&base).unwrap();
        assert_eq!(loaded.name, "demo");
        assert_eq!(loaded.path, fs::canonicalize(&base).unwrap());

        let _ = fs::remove_dir_all(&base);
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("projd-{label}-{nanos}"))
    }
}
