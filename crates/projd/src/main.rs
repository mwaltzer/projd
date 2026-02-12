use anyhow::{bail, Context, Result};
use clap::Parser;
use projd_types::{
    default_niri_config_path, default_socket_path, default_state_path, DownParams, ListResult,
    LogsParams, LogsResult, NameParams, PersistedState, ProcessLogs, ProjectLifecycleState,
    ProjectRecord, ProjectStatus, Request, Response, StatusParams, StatusResult, UpParams,
    UpResult, METHOD_DOWN, METHOD_LIST, METHOD_LOGS, METHOD_PEEK, METHOD_PING, METHOD_RESUME,
    METHOD_SHUTDOWN, METHOD_STATUS, METHOD_SUSPEND, METHOD_SWITCH, METHOD_UP, NIRI_MANAGED_END,
    NIRI_MANAGED_START,
};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
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
        METHOD_SHUTDOWN => match app_state.shutdown() {
            Ok(()) => (Response::ok(request.id, json!({"stopping": true})), true),
            Err(err) => (Response::err(request.id, err.to_string()), false),
        },
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
        METHOD_SWITCH => match parse_params::<NameParams>(&request.params)
            .and_then(|params| app_state.switch(&params.name))
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
        METHOD_SUSPEND => match parse_params::<NameParams>(&request.params)
            .and_then(|params| app_state.suspend(&params.name))
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
        METHOD_RESUME => match parse_params::<NameParams>(&request.params)
            .and_then(|params| app_state.resume(&params.name))
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
        METHOD_PEEK => match parse_params::<NameParams>(&request.params)
            .and_then(|params| app_state.peek(&params.name))
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
        METHOD_STATUS => match (if request.params.is_null() {
            Ok(StatusParams { name: None })
        } else {
            parse_params::<StatusParams>(&request.params)
        })
        .and_then(|params| app_state.status(params.name.as_deref()))
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
        METHOD_LOGS => match parse_params::<LogsParams>(&request.params)
            .and_then(|params| app_state.logs(params))
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
    focused_project: Option<String>,
    suspended_projects: HashSet<String>,
    state_path: PathBuf,
    niri_config_path: PathBuf,
    logs_path: PathBuf,
    runtime_processes: BTreeMap<String, Vec<RuntimeProcess>>,
}

#[derive(Debug)]
struct RuntimeProcess {
    name: String,
    log_path: PathBuf,
    child: Child,
}

#[derive(Debug)]
struct LoadedProjectConfig {
    name: String,
    path: PathBuf,
    runtime: RuntimeConfig,
}

#[derive(Debug, Default)]
struct RuntimeConfig {
    server: Option<ServerRuntimeConfig>,
    agents: Vec<NamedCommandConfig>,
    terminals: Vec<NamedCommandConfig>,
    editor: Option<EditorRuntimeConfig>,
    browser_urls: Vec<String>,
    depends_on: Vec<DependencyTarget>,
}

#[derive(Debug)]
struct ServerRuntimeConfig {
    command: String,
    cwd: PathBuf,
    port_env: String,
    ready_pattern: Option<String>,
}

#[derive(Debug)]
struct NamedCommandConfig {
    name: String,
    command: String,
    cwd: PathBuf,
}

#[derive(Debug)]
struct EditorRuntimeConfig {
    command: String,
    cwd: PathBuf,
}

#[derive(Debug)]
struct RuntimeSpawnSpec {
    name: String,
    command: String,
    cwd: PathBuf,
    env: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
enum DependencyTarget {
    Name(String),
    Path(PathBuf),
}

impl AppState {
    fn load(state_path: PathBuf, niri_config_path: PathBuf) -> Result<Self> {
        let mut projects = BTreeMap::new();
        let mut focused_project: Option<String> = None;
        let mut suspended_projects = HashSet::new();
        let logs_path = state_path
            .parent()
            .map(|path| path.join("logs"))
            .unwrap_or_else(|| projd_types::default_data_dir().join("logs"));
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
                if let Some(name) = persisted.focused_project {
                    if projects.contains_key(&name) {
                        focused_project = Some(name);
                    }
                }
                for name in persisted.suspended_projects {
                    if projects.contains_key(&name) {
                        suspended_projects.insert(name);
                    }
                }
            }
        }

        if focused_project
            .as_ref()
            .is_some_and(|name| suspended_projects.contains(name))
        {
            focused_project = None;
        }
        if focused_project.is_none() {
            focused_project = projects
                .keys()
                .find(|name| !suspended_projects.contains(*name))
                .cloned();
        }

        Ok(Self {
            projects,
            focused_project,
            suspended_projects,
            state_path,
            niri_config_path,
            logs_path,
            runtime_processes: BTreeMap::new(),
        })
    }

    fn up(&mut self, params: UpParams) -> Result<UpResult> {
        let mut resolving_paths = HashSet::new();
        self.up_internal(params, &mut resolving_paths)
    }

    fn up_internal(
        &mut self,
        params: UpParams,
        resolving_paths: &mut HashSet<PathBuf>,
    ) -> Result<UpResult> {
        let project_dir = fs::canonicalize(&params.path)
            .with_context(|| format!("failed to resolve project path: {}", params.path))?;
        if !project_dir.is_dir() {
            bail!("project path is not a directory: {}", project_dir.display());
        }
        if !resolving_paths.insert(project_dir.clone()) {
            bail!(
                "dependency cycle detected while resolving {}",
                project_dir.display()
            );
        }

        let result = self.up_internal_once(project_dir.clone(), resolving_paths);
        resolving_paths.remove(&project_dir);
        result
    }

    fn up_internal_once(
        &mut self,
        project_dir: PathBuf,
        resolving_paths: &mut HashSet<PathBuf>,
    ) -> Result<UpResult> {
        let project_cfg = load_project_config(&project_dir)?;
        self.ensure_dependencies_for(&project_cfg, resolving_paths)?;

        let project_path = path_to_string(&project_cfg.path);

        if let Some(existing) = self.projects.get(&project_cfg.name) {
            if existing.path == project_path {
                let existing = existing.clone();
                self.ensure_runtime_for_project(&existing, &project_cfg)?;
                return Ok(UpResult {
                    project: existing,
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
        let previous_focus = self.focused_project.clone();
        self.projects.insert(project.name.clone(), project.clone());
        if self.focused_project.is_none() {
            self.focused_project = Some(project.name.clone());
        }
        if let Err(err) = self.sync() {
            self.projects = previous;
            self.focused_project = previous_focus;
            return Err(err);
        }
        if let Err(err) = self.start_runtime_for_project(&project, &project_cfg.runtime) {
            self.projects = previous;
            self.focused_project = previous_focus;
            self.suspended_projects.remove(&project.name);
            let _ = self.stop_runtime_for_project(&project.name);
            let _ = self.sync();
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
        self.stop_runtime_for_project(&params.name)?;

        let previous = self.projects.clone();
        let previous_focus = self.focused_project.clone();
        let previous_suspended = self.suspended_projects.clone();
        let removed = self
            .projects
            .remove(&params.name)
            .expect("checked presence above");
        self.suspended_projects.remove(&params.name);
        if self.focused_project.as_deref() == Some(params.name.as_str()) {
            self.focused_project = self
                .projects
                .keys()
                .find(|name| !self.suspended_projects.contains(*name))
                .cloned();
        }
        if let Err(err) = self.sync() {
            self.projects = previous;
            self.focused_project = previous_focus;
            self.suspended_projects = previous_suspended;
            return Err(err);
        }

        Ok(removed)
    }

    fn list(&self) -> ListResult {
        ListResult {
            projects: self.projects.values().cloned().collect(),
        }
    }

    fn switch(&mut self, name: &str) -> Result<ProjectStatus> {
        let project = self.project_by_name(name)?.clone();
        if self.suspended_projects.contains(name) {
            bail!(
                "project '{}' is suspended; resume it before switching",
                name
            );
        }

        let previous_focus = self.focused_project.clone();
        focus_workspace_in_niri(&project.workspace)?;
        self.focused_project = Some(name.to_string());
        if let Err(err) = self.persist_state() {
            self.focused_project = previous_focus;
            return Err(err);
        }
        Ok(self.project_status(&project))
    }

    fn suspend(&mut self, name: &str) -> Result<ProjectStatus> {
        let project = self.project_by_name(name)?.clone();
        let previous_focus = self.focused_project.clone();
        let previous_suspended = self.suspended_projects.clone();
        self.suspended_projects.insert(name.to_string());
        if self.focused_project.as_deref() == Some(name) {
            self.focused_project = self
                .projects
                .keys()
                .find(|project_name| {
                    project_name.as_str() != name
                        && !self.suspended_projects.contains(project_name.as_str())
                })
                .cloned();
        }
        if let Err(err) = self.persist_state() {
            self.focused_project = previous_focus;
            self.suspended_projects = previous_suspended;
            return Err(err);
        }
        Ok(self.project_status(&project))
    }

    fn resume(&mut self, name: &str) -> Result<ProjectStatus> {
        let project = self.project_by_name(name)?.clone();
        if !self.suspended_projects.contains(name) {
            bail!("project '{}' is not suspended", name);
        }

        let previous_focus = self.focused_project.clone();
        let previous_suspended = self.suspended_projects.clone();
        focus_workspace_in_niri(&project.workspace)?;
        self.suspended_projects.remove(name);
        self.focused_project = Some(name.to_string());
        if let Err(err) = self.persist_state() {
            self.focused_project = previous_focus;
            self.suspended_projects = previous_suspended;
            return Err(err);
        }
        Ok(self.project_status(&project))
    }

    fn peek(&mut self, name: &str) -> Result<ProjectStatus> {
        self.refresh_focused_project_from_niri();
        let project = self.project_by_name(name)?.clone();
        Ok(self.project_status(&project))
    }

    fn status(&mut self, name: Option<&str>) -> Result<StatusResult> {
        self.refresh_focused_project_from_niri();
        if let Some(name) = name {
            let project = self.project_by_name(name)?.clone();
            return Ok(StatusResult {
                projects: vec![self.project_status(&project)],
            });
        }

        Ok(StatusResult {
            projects: self
                .projects
                .values()
                .map(|project| self.project_status(project))
                .collect(),
        })
    }

    fn logs(&self, params: LogsParams) -> Result<LogsResult> {
        self.project_by_name(&params.name)?;
        let mut logs = Vec::new();

        if let Some(process) = params.process {
            let path = self.log_file_path(&params.name, &process);
            if !path.exists() {
                bail!(
                    "no logs for project '{}' process '{}'",
                    params.name,
                    process
                );
            }
            logs.push(ProcessLogs {
                process,
                path: path_to_string(&path),
                content: fs::read_to_string(&path)
                    .with_context(|| format!("failed to read log file: {}", path.display()))?,
            });
            return Ok(LogsResult {
                project: params.name,
                logs,
            });
        }

        let project_log_dir = self.project_logs_dir(&params.name);
        if project_log_dir.exists() {
            let mut entries = fs::read_dir(&project_log_dir)
                .with_context(|| format!("failed to read {}", project_log_dir.display()))?
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.path().extension().and_then(|ext| ext.to_str()) == Some("log")
                })
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let process = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                logs.push(ProcessLogs {
                    process,
                    path: path_to_string(&path),
                    content: fs::read_to_string(&path)
                        .with_context(|| format!("failed to read log file: {}", path.display()))?,
                });
            }
        }

        Ok(LogsResult {
            project: params.name,
            logs,
        })
    }

    fn shutdown(&mut self) -> Result<()> {
        let names: Vec<String> = self.runtime_processes.keys().cloned().collect();
        let mut failures = Vec::new();
        for name in names {
            if let Err(err) = self.stop_runtime_for_project(&name) {
                failures.push(format!("{name}: {err}"));
            }
        }
        if !failures.is_empty() {
            bail!(
                "failed to stop one or more runtime processes: {}",
                failures.join("; ")
            );
        }
        Ok(())
    }

    fn project_by_name(&self, name: &str) -> Result<&ProjectRecord> {
        self.projects
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("project '{}' is not registered", name))
    }

    fn project_status(&self, project: &ProjectRecord) -> ProjectStatus {
        let suspended = self.suspended_projects.contains(project.name.as_str());
        let focused = !suspended && self.focused_project.as_deref() == Some(project.name.as_str());
        let state = if suspended {
            ProjectLifecycleState::Suspended
        } else if focused {
            ProjectLifecycleState::Active
        } else {
            ProjectLifecycleState::Backgrounded
        };

        ProjectStatus {
            project: project.clone(),
            state,
            focused,
        }
    }

    fn refresh_focused_project_from_niri(&mut self) {
        let Some(workspace) = focused_workspace_from_niri() else {
            return;
        };

        if self.projects.contains_key(&workspace) {
            self.focused_project = Some(workspace);
        }
    }

    fn ensure_runtime_for_project(
        &mut self,
        project: &ProjectRecord,
        config: &LoadedProjectConfig,
    ) -> Result<()> {
        if self
            .runtime_processes
            .get(project.name.as_str())
            .is_some_and(|processes| !processes.is_empty())
        {
            return Ok(());
        }
        self.start_runtime_for_project(project, &config.runtime)
    }

    fn ensure_dependencies_for(
        &mut self,
        config: &LoadedProjectConfig,
        resolving_paths: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        for dependency in &config.runtime.depends_on {
            match dependency {
                DependencyTarget::Name(name) => {
                    let project = self.project_by_name(name)?.clone();
                    let dependency_cfg = load_project_config(Path::new(&project.path))
                        .with_context(|| format!("failed to load dependency '{}' config", name))?;
                    self.ensure_runtime_for_project(&project, &dependency_cfg)?;
                }
                DependencyTarget::Path(path) => {
                    if let Some(existing) = self
                        .projects
                        .values()
                        .find(|project| Path::new(&project.path) == path)
                        .cloned()
                    {
                        let dependency_cfg = load_project_config(Path::new(&existing.path))
                            .with_context(|| {
                                format!("failed to load dependency config at {}", path.display())
                            })?;
                        self.ensure_runtime_for_project(&existing, &dependency_cfg)?;
                    } else {
                        let _ = self.up_internal(
                            UpParams {
                                path: path_to_string(path),
                            },
                            resolving_paths,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn start_runtime_for_project(
        &mut self,
        project: &ProjectRecord,
        config: &RuntimeConfig,
    ) -> Result<()> {
        let specs = build_runtime_spawn_specs(project, config)?;
        if specs.is_empty() {
            self.runtime_processes.remove(&project.name);
            return Ok(());
        }

        let mut browser_specs = Vec::new();
        let mut non_browser_specs = Vec::new();
        for spec in specs {
            if is_browser_process_name(&spec.name) {
                browser_specs.push(spec);
            } else {
                non_browser_specs.push(spec);
            }
        }

        let mut started = Vec::new();
        for spec in non_browser_specs {
            match self.spawn_runtime_process(project, spec) {
                Ok(process) => started.push(process),
                Err(err) => {
                    for process in &mut started {
                        let _ = terminate_child(&mut process.child, Duration::from_millis(500));
                    }
                    return Err(err);
                }
            }
        }

        if !browser_specs.is_empty() {
            if let Some(pattern) = config
                .server
                .as_ref()
                .and_then(|server| server.ready_pattern.as_deref())
            {
                let Some(server_process) =
                    started.iter_mut().find(|process| process.name == "server")
                else {
                    for process in &mut started {
                        let _ = terminate_child(&mut process.child, Duration::from_millis(500));
                    }
                    bail!("server.ready_pattern is configured but no server process was started");
                };
                if let Err(err) =
                    wait_for_server_ready(server_process, pattern, runtime_ready_timeout())
                {
                    for process in &mut started {
                        let _ = terminate_child(&mut process.child, Duration::from_millis(500));
                    }
                    return Err(err);
                }
            }

            for spec in browser_specs {
                match self.spawn_runtime_process(project, spec) {
                    Ok(process) => started.push(process),
                    Err(err) => {
                        for process in &mut started {
                            let _ = terminate_child(&mut process.child, Duration::from_millis(500));
                        }
                        return Err(err);
                    }
                }
            }
        }

        self.runtime_processes.insert(project.name.clone(), started);
        Ok(())
    }

    fn spawn_runtime_process(
        &self,
        project: &ProjectRecord,
        spec: RuntimeSpawnSpec,
    ) -> Result<RuntimeProcess> {
        let log_path = self.log_file_path(&project.name, &spec.name);
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log dir {}", parent.display()))?;
        }
        let mut child = Command::new("sh")
            .arg("-lc")
            .arg(&spec.command)
            .current_dir(&spec.cwd)
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn process '{}' for project '{}'",
                    spec.name, project.name
                )
            })?;

        attach_process_logs(&mut child, &log_path)?;
        thread::sleep(Duration::from_millis(80));
        if let Some(status) = child
            .try_wait()
            .context("failed to check child process status after spawn")?
        {
            if !status.success() {
                bail!(
                    "process '{}' for project '{}' exited immediately with status {}",
                    spec.name,
                    project.name,
                    status
                );
            }
        }

        Ok(RuntimeProcess {
            name: spec.name,
            log_path,
            child,
        })
    }

    fn stop_runtime_for_project(&mut self, name: &str) -> Result<()> {
        let Some(mut processes) = self.runtime_processes.remove(name) else {
            return Ok(());
        };
        let mut failures = Vec::new();
        let mut remaining = Vec::new();
        for mut process in processes.drain(..) {
            if let Err(err) = terminate_child(&mut process.child, Duration::from_secs(2)) {
                failures.push(format!(
                    "{} ({}): {err}",
                    process.name,
                    process.log_path.display()
                ));
                remaining.push(process);
            }
        }
        if !remaining.is_empty() {
            self.runtime_processes.insert(name.to_string(), remaining);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("failed to stop runtime processes: {}", failures.join("; "))
        }
    }

    fn project_logs_dir(&self, project_name: &str) -> PathBuf {
        self.logs_path.join(sanitize_log_component(project_name))
    }

    fn log_file_path(&self, project_name: &str, process_name: &str) -> PathBuf {
        self.project_logs_dir(project_name)
            .join(format!("{}.log", sanitize_log_component(process_name)))
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
        let mut suspended_projects: Vec<String> = self.suspended_projects.iter().cloned().collect();
        suspended_projects.sort();
        let state = PersistedState {
            projects: self.projects.values().cloned().collect(),
            focused_project: self
                .focused_project
                .clone()
                .filter(|name| self.projects.contains_key(name)),
            suspended_projects,
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

#[derive(Debug, Deserialize)]
struct RawProjectConfig {
    name: String,
    path: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    server: Option<RawServerConfig>,
    #[serde(default)]
    agents: Vec<RawNamedCommandConfig>,
    #[serde(default)]
    terminals: Vec<RawTerminalConfig>,
    #[serde(default)]
    editor: Option<RawEditorConfig>,
    #[serde(default)]
    browser: Option<RawBrowserConfig>,
}

#[derive(Debug, Deserialize)]
struct RawServerConfig {
    command: String,
    #[serde(default)]
    port_env: Option<String>,
    #[serde(default)]
    ready_pattern: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawNamedCommandConfig {
    name: String,
    command: String,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawTerminalConfig {
    name: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEditorConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawBrowserConfig {
    #[serde(default)]
    urls: Vec<String>,
}

fn load_project_config(project_dir: &Path) -> Result<LoadedProjectConfig> {
    let toml_path = project_dir.join(".project.toml");
    if !toml_path.exists() {
        bail!("missing project config: expected {}", toml_path.display());
    }

    let raw = fs::read_to_string(&toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;
    let parsed: RawProjectConfig =
        toml::from_str(&raw).context("invalid .project.toml (failed to parse TOML)")?;

    let name = parsed.name.trim().to_string();
    if name.is_empty() {
        bail!("project name in .project.toml cannot be empty");
    }

    let normalized_path = normalize_project_path(&parsed.path, project_dir)?;
    let runtime = build_runtime_config(&parsed, &normalized_path)?;
    Ok(LoadedProjectConfig {
        name,
        path: normalized_path,
        runtime,
    })
}

fn build_runtime_config(parsed: &RawProjectConfig, project_path: &Path) -> Result<RuntimeConfig> {
    let mut runtime = RuntimeConfig {
        depends_on: parsed
            .depends_on
            .iter()
            .map(|item| resolve_dependency_target(item, project_path))
            .collect::<Result<Vec<_>>>()?,
        ..RuntimeConfig::default()
    };

    if let Some(server) = &parsed.server {
        let command = non_empty_field(&server.command, "server.command")?;
        let port_env = server
            .port_env
            .as_deref()
            .unwrap_or("PORT")
            .trim()
            .to_string();
        if port_env.is_empty() {
            bail!("server.port_env cannot be empty");
        }
        let ready_pattern = server
            .ready_pattern
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        runtime.server = Some(ServerRuntimeConfig {
            command,
            cwd: resolve_runtime_cwd(server.cwd.as_deref(), project_path)?,
            port_env,
            ready_pattern,
        });
    }

    for agent in &parsed.agents {
        runtime.agents.push(NamedCommandConfig {
            name: non_empty_field(&agent.name, "agents[].name")?,
            command: non_empty_field(&agent.command, "agents[].command")?,
            cwd: resolve_runtime_cwd(agent.cwd.as_deref(), project_path)?,
        });
    }

    for terminal in &parsed.terminals {
        let default_shell = std::env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
        runtime.terminals.push(NamedCommandConfig {
            name: non_empty_field(&terminal.name, "terminals[].name")?,
            command: terminal
                .command
                .as_deref()
                .map(|value| non_empty_field(value, "terminals[].command"))
                .transpose()?
                .unwrap_or(default_shell),
            cwd: resolve_runtime_cwd(terminal.cwd.as_deref(), project_path)?,
        });
    }

    if let Some(editor) = &parsed.editor {
        let command = non_empty_field(&editor.command, "editor.command")?;
        runtime.editor = Some(EditorRuntimeConfig {
            command: build_shell_command_with_args(&command, &editor.args),
            cwd: resolve_runtime_cwd(editor.cwd.as_deref(), project_path)?,
        });
    }

    if let Some(browser) = &parsed.browser {
        runtime.browser_urls = browser
            .urls
            .iter()
            .map(|url| non_empty_field(url, "browser.urls[]"))
            .collect::<Result<Vec<_>>>()?;
    }

    Ok(runtime)
}

fn non_empty_field(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn resolve_runtime_cwd(raw: Option<&str>, project_path: &Path) -> Result<PathBuf> {
    let raw = raw.unwrap_or(".");
    let expanded = expand_tilde(raw);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        project_path.join(expanded)
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("failed to resolve cwd path: {}", candidate.display()))?;
    if !canonical.is_dir() {
        bail!("runtime cwd is not a directory: {}", canonical.display());
    }
    Ok(canonical)
}

fn resolve_dependency_target(raw: &str, project_path: &Path) -> Result<DependencyTarget> {
    let value = non_empty_field(raw, "depends_on[]")?;
    if looks_like_path_dependency(&value) {
        let expanded = expand_tilde(&value);
        let candidate = if expanded.is_absolute() {
            expanded
        } else {
            project_path.join(expanded)
        };
        let canonical = fs::canonicalize(&candidate).with_context(|| {
            format!(
                "failed to resolve dependency path in depends_on[]: {}",
                candidate.display()
            )
        })?;
        if !canonical.is_dir() {
            bail!(
                "depends_on[] path is not a directory: {}",
                canonical.display()
            );
        }
        return Ok(DependencyTarget::Path(canonical));
    }

    Ok(DependencyTarget::Name(value))
}

fn looks_like_path_dependency(raw: &str) -> bool {
    raw.starts_with('/')
        || raw.starts_with("./")
        || raw.starts_with("../")
        || raw == "."
        || raw == ".."
        || raw.starts_with("~/")
        || raw == "~"
        || raw.contains('/')
}

fn build_runtime_spawn_specs(
    project: &ProjectRecord,
    config: &RuntimeConfig,
) -> Result<Vec<RuntimeSpawnSpec>> {
    let mut specs = Vec::new();
    let mut seen = HashSet::new();
    let port_value = project.port.to_string();
    let base_env = vec![
        ("PORT".to_string(), port_value.clone()),
        ("PROJ_NAME".to_string(), project.name.clone()),
    ];

    if let Some(server) = &config.server {
        let mut env = base_env.clone();
        if server.port_env != "PORT" {
            env.push((server.port_env.clone(), port_value.clone()));
        }
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: "server".to_string(),
                command: server.command.clone(),
                cwd: server.cwd.clone(),
                env,
            },
        )?;
    }

    for agent in &config.agents {
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: format!("agent-{}", agent.name),
                command: agent.command.clone(),
                cwd: agent.cwd.clone(),
                env: base_env.clone(),
            },
        )?;
    }

    for terminal in &config.terminals {
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: format!("terminal-{}", terminal.name),
                command: terminal.command.clone(),
                cwd: terminal.cwd.clone(),
                env: base_env.clone(),
            },
        )?;
    }

    if let Some(editor) = &config.editor {
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: "editor".to_string(),
                command: editor.command.clone(),
                cwd: editor.cwd.clone(),
                env: base_env.clone(),
            },
        )?;
    }

    for (index, url) in config.browser_urls.iter().enumerate() {
        let command = format!(
            "{} {}",
            browser_open_command(),
            quote_shell_arg(&interpolate_port(url, project.port))
        );
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: format!("browser-{}", index + 1),
                command,
                cwd: PathBuf::from(&project.path),
                env: base_env.clone(),
            },
        )?;
    }

    Ok(specs)
}

fn push_runtime_spec(
    specs: &mut Vec<RuntimeSpawnSpec>,
    seen: &mut HashSet<String>,
    spec: RuntimeSpawnSpec,
) -> Result<()> {
    if !seen.insert(spec.name.clone()) {
        bail!("duplicate runtime process name '{}'", spec.name);
    }
    specs.push(spec);
    Ok(())
}

fn interpolate_port(value: &str, port: u16) -> String {
    let replacement = port.to_string();
    value.replace("${PORT}", &replacement)
}

fn build_shell_command_with_args(command: &str, args: &[String]) -> String {
    let mut rendered = quote_shell_arg(command);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(quote_shell_arg(arg).as_str());
    }
    rendered
}

fn is_browser_process_name(name: &str) -> bool {
    name.starts_with("browser-")
}

fn runtime_ready_timeout() -> Duration {
    if let Ok(raw) = std::env::var("PROJD_READY_TIMEOUT_MS") {
        if let Ok(parsed) = raw.trim().parse::<u64>() {
            return Duration::from_millis(parsed);
        }
    }
    Duration::from_secs(15)
}

fn wait_for_server_ready(
    process: &mut RuntimeProcess,
    ready_pattern: &str,
    timeout: Duration,
) -> Result<()> {
    let matcher =
        Regex::new(ready_pattern).context("invalid server.ready_pattern (regex parse failed)")?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(&process.log_path) {
            if matcher.is_match(&content) {
                return Ok(());
            }
        }

        if let Some(status) = process
            .child
            .try_wait()
            .context("failed while checking server process status")?
        {
            bail!(
                "server process exited before ready_pattern '{}' matched (status {})",
                ready_pattern,
                status
            );
        }

        thread::sleep(Duration::from_millis(50));
    }

    bail!(
        "timed out waiting for server.ready_pattern '{}' in {}",
        ready_pattern,
        process.log_path.display()
    )
}

fn browser_open_command() -> String {
    if let Ok(custom) = std::env::var("PROJD_BROWSER_CMD") {
        if !custom.trim().is_empty() {
            return custom;
        }
    }
    if let Ok(custom) = std::env::var("BROWSER") {
        if !custom.trim().is_empty() {
            return custom;
        }
    }
    #[cfg(target_os = "macos")]
    {
        return "open".to_string();
    }
    #[cfg(not(target_os = "macos"))]
    {
        "xdg-open".to_string()
    }
}

fn quote_shell_arg(raw: &str) -> String {
    if raw.is_empty() {
        return "''".to_string();
    }
    if raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:@".contains(ch))
    {
        return raw.to_string();
    }
    format!("'{}'", raw.replace('\'', "'\"'\"'"))
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

fn attach_process_logs(child: &mut Child, log_path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("failed to open log file: {}", log_path.display()))?;
    let shared = Arc::new(Mutex::new(file));

    if let Some(stdout) = child.stdout.take() {
        spawn_log_copy_thread(stdout, shared.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_copy_thread(stderr, shared);
    }
    Ok(())
}

fn spawn_log_copy_thread<R>(mut reader: R, file: Arc<Mutex<File>>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => size,
                Err(_) => break,
            };
            let mut file = match file.lock() {
                Ok(file) => file,
                Err(_) => break,
            };
            if file.write_all(&buffer[..read]).is_err() {
                break;
            }
        }
    });
}

fn terminate_child(child: &mut Child, grace_period: Duration) -> Result<()> {
    if child
        .try_wait()
        .context("failed to check process status")?
        .is_some()
    {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // SIGTERM gives spawned processes a chance to flush and exit cleanly.
        let signal_status = unsafe { libc::kill(pid, libc::SIGTERM) };
        if signal_status != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err).context("failed to send SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        child.kill().context("failed to terminate process")?;
    }

    let deadline = Instant::now() + grace_period;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .context("failed waiting for process exit")?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }

    child.kill().context("failed to send SIGKILL")?;
    let _ = child.wait();
    Ok(())
}

fn sanitize_log_component(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.trim_matches('_').is_empty() {
        "process".to_string()
    } else {
        output
    }
}

fn focus_workspace_in_niri(workspace: &str) -> Result<()> {
    let output = Command::new("niri")
        .arg("msg")
        .arg("action")
        .arg("focus-workspace")
        .arg(workspace)
        .output()
        .with_context(|| {
            format!("failed to execute niri focus command for workspace '{workspace}'")
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        bail!("niri focus command failed for workspace '{workspace}'");
    }

    bail!("niri focus command failed for workspace '{workspace}': {stderr}")
}

fn focused_workspace_from_niri() -> Option<String> {
    let output = Command::new("niri")
        .arg("msg")
        .arg("--json")
        .arg("focused-workspace")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    find_workspace_name(&value)
}

fn find_workspace_name(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("name").and_then(Value::as_str) {
                if !name.trim().is_empty() {
                    return Some(name.to_string());
                }
            }

            for child in map.values() {
                if let Some(name) = find_workspace_name(child) {
                    return Some(name);
                }
            }
            None
        }
        Value::Array(items) => {
            for item in items {
                if let Some(name) = find_workspace_name(item) {
                    return Some(name);
                }
            }
            None
        }
        _ => None,
    }
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
            focused_project: None,
            suspended_projects: HashSet::new(),
            state_path: PathBuf::from("/tmp/state.json"),
            niri_config_path: PathBuf::from("/tmp/config.kdl"),
            logs_path: PathBuf::from("/tmp/logs"),
            runtime_processes: BTreeMap::new(),
        };
        assert_eq!(state.allocate_port().unwrap(), 3002);
    }

    #[test]
    fn find_workspace_name_handles_nested_json_shape() {
        let payload = json!({
            "Ok": {
                "FocusedWorkspace": {
                    "id": 1,
                    "name": "frontend"
                }
            }
        });

        let found = find_workspace_name(&payload);
        assert_eq!(found.as_deref(), Some("frontend"));
    }

    #[test]
    fn project_status_marks_suspended_over_focus() {
        let project = ProjectRecord {
            name: "demo".to_string(),
            path: "/tmp/demo".to_string(),
            workspace: "demo".to_string(),
            port: 3001,
        };
        let mut projects = BTreeMap::new();
        projects.insert(project.name.clone(), project.clone());
        let mut suspended = HashSet::new();
        suspended.insert(project.name.clone());

        let state = AppState {
            projects,
            focused_project: Some(project.name.clone()),
            suspended_projects: suspended,
            state_path: PathBuf::from("/tmp/state.json"),
            niri_config_path: PathBuf::from("/tmp/config.kdl"),
            logs_path: PathBuf::from("/tmp/logs"),
            runtime_processes: BTreeMap::new(),
        };

        let status = state.project_status(&project);
        assert_eq!(status.state, ProjectLifecycleState::Suspended);
        assert!(!status.focused);
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

    #[test]
    fn load_project_config_parses_runtime_sections() {
        let base = unique_temp_dir("load-project-config-runtime");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(base.join("app")).unwrap();
        fs::create_dir_all(base.join("shared")).unwrap();
        fs::write(
            base.join(".project.toml"),
            "name = \"demo\"\n\
path = \".\"\n\
depends_on = [\"./shared\", \"existing-project\"]\n\
\n\
[server]\n\
command = \"npm run dev\"\n\
port_env = \"APP_PORT\"\n\
ready_pattern = \"ready on\"\n\
cwd = \".\"\n\
\n\
[[agents]]\n\
name = \"watcher\"\n\
command = \"echo watcher\"\n\
cwd = \".\"\n\
\n\
[editor]\n\
command = \"code\"\n\
args = [\".\"]\n\
cwd = \".\"\n\
\n\
[browser]\n\
urls = [\"http://localhost:${PORT}\"]\n",
        )
        .unwrap();

        let loaded = load_project_config(&base).unwrap();
        let runtime = loaded.runtime;
        assert_eq!(runtime.server.as_ref().unwrap().port_env, "APP_PORT");
        assert_eq!(
            runtime.server.as_ref().unwrap().ready_pattern.as_deref(),
            Some("ready on")
        );
        assert_eq!(runtime.depends_on.len(), 2);
        assert!(matches!(runtime.depends_on[0], DependencyTarget::Path(_)));
        assert!(matches!(
            runtime.depends_on[1],
            DependencyTarget::Name(ref name) if name == "existing-project"
        ));
        assert_eq!(runtime.agents.len(), 1);
        assert_eq!(runtime.editor.as_ref().unwrap().command, "code .");
        assert_eq!(runtime.browser_urls, vec!["http://localhost:${PORT}"]);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sanitize_log_component_replaces_unsafe_characters() {
        assert_eq!(sanitize_log_component("agent-alpha"), "agent-alpha");
        assert_eq!(sanitize_log_component("agent alpha"), "agent_alpha");
        assert_eq!(sanitize_log_component(".."), "process");
    }

    #[test]
    fn interpolate_port_replaces_placeholder_tokens() {
        assert_eq!(
            interpolate_port("http://localhost:${PORT}/health", 3210),
            "http://localhost:3210/health"
        );
        assert_eq!(interpolate_port("no-port", 3210), "no-port");
    }

    #[test]
    fn resolve_dependency_target_supports_name_and_relative_path() {
        let base = unique_temp_dir("resolve-dependency-target");
        let dep_dir = base.join("dep");
        fs::create_dir_all(&dep_dir).unwrap();

        let name_target = resolve_dependency_target("api", &base).unwrap();
        assert!(matches!(name_target, DependencyTarget::Name(ref name) if name == "api"));

        let path_target = resolve_dependency_target("./dep", &base).unwrap();
        assert!(matches!(
            path_target,
            DependencyTarget::Path(ref path) if path == &fs::canonicalize(&dep_dir).unwrap()
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_state_restores_lifecycle_fields() {
        let base = unique_temp_dir("load-state-lifecycle");
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("state.json");
        let niri_config_path = base.join("config.kdl");
        let persisted = PersistedState {
            projects: vec![
                ProjectRecord {
                    name: "frontend".to_string(),
                    path: "/tmp/frontend".to_string(),
                    workspace: "frontend".to_string(),
                    port: 3001,
                },
                ProjectRecord {
                    name: "api".to_string(),
                    path: "/tmp/api".to_string(),
                    workspace: "api".to_string(),
                    port: 3002,
                },
            ],
            focused_project: Some("api".to_string()),
            suspended_projects: vec!["frontend".to_string(), "missing".to_string()],
        };
        fs::write(&state_path, serde_json::to_string(&persisted).unwrap()).unwrap();

        let loaded = AppState::load(state_path, niri_config_path).unwrap();
        assert_eq!(loaded.focused_project.as_deref(), Some("api"));
        assert!(loaded.suspended_projects.contains("frontend"));
        assert!(!loaded.suspended_projects.contains("missing"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_state_rejects_suspended_focus_and_falls_back() {
        let base = unique_temp_dir("load-state-fallback-focus");
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("state.json");
        let niri_config_path = base.join("config.kdl");
        let persisted = PersistedState {
            projects: vec![
                ProjectRecord {
                    name: "a".to_string(),
                    path: "/tmp/a".to_string(),
                    workspace: "a".to_string(),
                    port: 3001,
                },
                ProjectRecord {
                    name: "b".to_string(),
                    path: "/tmp/b".to_string(),
                    workspace: "b".to_string(),
                    port: 3002,
                },
            ],
            focused_project: Some("a".to_string()),
            suspended_projects: vec!["a".to_string()],
        };
        fs::write(&state_path, serde_json::to_string(&persisted).unwrap()).unwrap();

        let loaded = AppState::load(state_path, niri_config_path).unwrap();
        assert_eq!(loaded.focused_project.as_deref(), Some("b"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn persist_state_writes_lifecycle_fields() {
        let base = unique_temp_dir("persist-state-lifecycle");
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("state.json");
        let niri_config_path = base.join("config.kdl");

        let mut projects = BTreeMap::new();
        projects.insert(
            "frontend".to_string(),
            ProjectRecord {
                name: "frontend".to_string(),
                path: "/tmp/frontend".to_string(),
                workspace: "frontend".to_string(),
                port: 3001,
            },
        );
        projects.insert(
            "api".to_string(),
            ProjectRecord {
                name: "api".to_string(),
                path: "/tmp/api".to_string(),
                workspace: "api".to_string(),
                port: 3002,
            },
        );

        let mut suspended_projects = HashSet::new();
        suspended_projects.insert("frontend".to_string());

        let state = AppState {
            projects,
            focused_project: Some("api".to_string()),
            suspended_projects,
            state_path: state_path.clone(),
            niri_config_path,
            logs_path: base.join("logs"),
            runtime_processes: BTreeMap::new(),
        };
        state.persist_state().unwrap();

        let stored: PersistedState = serde_json::from_str(&fs::read_to_string(state_path).unwrap())
            .expect("failed to deserialize persisted state");
        assert_eq!(stored.focused_project.as_deref(), Some("api"));
        assert_eq!(stored.suspended_projects, vec!["frontend".to_string()]);

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
