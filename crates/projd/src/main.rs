use anyhow::{bail, Context, Result};
use clap::Parser;
use projd_types::{
    default_niri_config_path, default_socket_path, default_state_path, DownParams, FocusResult,
    ListResult, LogsParams, LogsResult, NameParams, PersistedState, ProcessLogs,
    ProjectLifecycleState, ProjectRecord, ProjectStatus, Request, Response, StatusParams,
    StatusResult, UpParams, UpResult, METHOD_DOWN, METHOD_FOCUS, METHOD_LIST, METHOD_LOGS,
    METHOD_PEEK, METHOD_PING, METHOD_RESUME, METHOD_SHUTDOWN, METHOD_STATUS, METHOD_SUSPEND,
    METHOD_SWITCH, METHOD_UP, NIRI_MANAGED_END, NIRI_MANAGED_START,
};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

const DEFAULT_ROUTER_PORT: u16 = 48080;
const ROUTER_HEADER_LIMIT_BYTES: usize = 64 * 1024;
const ROUTER_MAX_CONCURRENT_STREAMS: usize = 256;
const ROUTER_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(name = "projd", version, about = "Project daemon for proj CLI")]
struct Args {
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long)]
    niri_config: Option<PathBuf>,
    #[arg(long)]
    router_port: Option<u16>,
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
    let router_port = args
        .router_port
        .or_else(router_port_from_env)
        .unwrap_or(DEFAULT_ROUTER_PORT);
    let router_routes = Arc::new(Mutex::new(BTreeMap::new()));
    let mut app_state = AppState::load(
        state_path,
        niri_config_path,
        router_port,
        router_routes.clone(),
    )?;
    app_state.sync_router_routes()?;

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create socket directory: {}", parent.display()))?;
    }

    let router_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), router_port);
    let router_listener = TcpListener::bind(router_addr)
        .with_context(|| format!("failed to bind router socket: {router_addr}"))?;
    router_listener
        .set_nonblocking(true)
        .context("failed to set router listener as non-blocking")?;

    let listener = bind_daemon_socket(&socket_path)?;
    listener
        .set_nonblocking(true)
        .context("failed to set listener as non-blocking")?;

    info!("projd listening on {}", socket_path.display());
    let running = Arc::new(AtomicBool::new(true));
    let router_running = running.clone();
    let router_handle = thread::spawn(move || {
        run_host_router(router_listener, router_routes, router_running, router_port)
    });

    while running.load(Ordering::SeqCst) {
        app_state.poll_runtime_events();
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
    let _ = router_handle.join();
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

fn bind_daemon_socket(socket_path: &Path) -> Result<UnixListener> {
    match UnixListener::bind(socket_path) {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            if daemon_is_reachable(socket_path) {
                bail!(
                    "failed to bind socket: {} (another projd instance is already running)",
                    socket_path.display()
                );
            }
            if socket_path.exists() {
                fs::remove_file(socket_path).with_context(|| {
                    format!("failed to remove stale socket: {}", socket_path.display())
                })?;
            }
            UnixListener::bind(socket_path)
                .with_context(|| format!("failed to bind socket: {}", socket_path.display()))
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to bind socket: {}", socket_path.display()))
        }
    }
}

fn daemon_is_reachable(socket_path: &Path) -> bool {
    let stream = match UnixStream::connect(socket_path) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let mut writer = BufWriter::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return false,
    });
    let mut reader = BufReader::new(stream);
    let ping = Request {
        id: 0,
        method: METHOD_PING.to_string(),
        params: Value::Null,
    };

    if serde_json::to_writer(&mut writer, &ping).is_err() {
        return false;
    }
    if writer.write_all(b"\n").is_err() || writer.flush().is_err() {
        return false;
    }

    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return false;
    }
    serde_json::from_str::<Response>(&line)
        .map(|response| response.ok)
        .unwrap_or(false)
}

fn router_port_from_env() -> Option<u16> {
    let raw = std::env::var("PROJD_ROUTER_PORT").ok()?;
    raw.trim().parse::<u16>().ok()
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

fn run_host_router(
    listener: TcpListener,
    routes: Arc<Mutex<BTreeMap<String, u16>>>,
    running: Arc<AtomicBool>,
    router_port: u16,
) {
    info!("projd host router listening on 127.0.0.1:{router_port}");
    let active_streams = Arc::new(AtomicUsize::new(0));
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let in_flight = active_streams.fetch_add(1, Ordering::SeqCst);
                if in_flight >= ROUTER_MAX_CONCURRENT_STREAMS {
                    active_streams.fetch_sub(1, Ordering::SeqCst);
                    warn!(
                        "router dropped incoming connection: too many active streams (limit={ROUTER_MAX_CONCURRENT_STREAMS})"
                    );
                    let _ =
                        write_http_error(&mut stream, "503 Service Unavailable", "router is busy");
                    continue;
                }
                let routes = routes.clone();
                let active_streams = active_streams.clone();
                thread::spawn(move || {
                    let _guard = RouterStreamGuard::new(active_streams);
                    if let Err(err) = handle_host_router_stream(stream, routes) {
                        warn!("host router stream failed: {err:#}");
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => {
                warn!("host router accept error: {err}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

struct RouterStreamGuard {
    active_streams: Arc<AtomicUsize>,
}

impl RouterStreamGuard {
    fn new(active_streams: Arc<AtomicUsize>) -> Self {
        Self { active_streams }
    }
}

impl Drop for RouterStreamGuard {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_host_router_stream(
    mut client: TcpStream,
    routes: Arc<Mutex<BTreeMap<String, u16>>>,
) -> Result<()> {
    client
        .set_read_timeout(Some(ROUTER_HEADER_TIMEOUT))
        .context("failed to configure router header timeout")?;
    let initial = match read_http_head(&mut client) {
        Ok(initial) => initial,
        Err(err)
            if caused_by_io_error_kind(&err, io::ErrorKind::TimedOut)
                || caused_by_io_error_kind(&err, io::ErrorKind::WouldBlock) =>
        {
            write_http_error(
                &mut client,
                "408 Request Timeout",
                "request header timed out",
            )?;
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    client
        .set_read_timeout(None)
        .context("failed to clear router header timeout")?;
    let Some(host) = extract_host_header(&initial) else {
        write_http_error(&mut client, "400 Bad Request", "missing host header")?;
        return Ok(());
    };
    let Some(route_key) = localhost_route_key_from_host(&host) else {
        write_http_error(&mut client, "404 Not Found", "unknown project host route")?;
        return Ok(());
    };
    let backend_port = {
        let locked = routes
            .lock()
            .map_err(|_| anyhow::anyhow!("router route table lock poisoned"))?;
        locked.get(&route_key).copied()
    };
    let Some(backend_port) = backend_port else {
        write_http_error(&mut client, "404 Not Found", "unknown project host route")?;
        return Ok(());
    };

    let mut backend = match TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port)) {
        Ok(stream) => stream,
        Err(err) => {
            warn!(
                "router backend connect failed for host '{}': 127.0.0.1:{} ({err})",
                host, backend_port
            );
            write_http_error(&mut client, "502 Bad Gateway", "backend is not reachable")?;
            return Ok(());
        }
    };
    backend
        .write_all(&initial)
        .context("failed to write request preface to backend")?;

    let mut client_reader = client
        .try_clone()
        .context("failed to clone client stream for request forwarding")?;
    let mut backend_writer = backend
        .try_clone()
        .context("failed to clone backend stream for request forwarding")?;
    let forward = thread::spawn(move || {
        let copy_result = io::copy(&mut client_reader, &mut backend_writer);
        let _ = backend_writer.shutdown(Shutdown::Write);
        copy_result
    });

    io::copy(&mut backend, &mut client).context("failed to forward backend response")?;
    let _ = client.shutdown(Shutdown::Write);

    match forward.join() {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err).context("failed to forward client request body to backend"),
        Err(_) => bail!("host router forwarding thread panicked"),
    }
}

fn caused_by_io_error_kind(err: &anyhow::Error, kind: io::ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == kind)
    })
}

fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .context("failed to read client request")?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > ROUTER_HEADER_LIMIT_BYTES {
            bail!("request header exceeds {} bytes", ROUTER_HEADER_LIMIT_BYTES);
        }
    }

    if head.is_empty() {
        bail!("empty request");
    }
    Ok(head)
}

fn write_http_error(stream: &mut TcpStream, status: &str, message: &str) -> Result<()> {
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("failed to write router error response")
}

fn extract_host_header(request_head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(request_head).ok()?;
    text.split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("host") {
                Some(value.trim().to_ascii_lowercase())
            } else {
                None
            }
        })
        .filter(|host| !host.is_empty())
}

fn localhost_route_key_from_host(host: &str) -> Option<String> {
    let without_port = host
        .split_once(':')
        .map(|(left, _)| left)
        .unwrap_or(host)
        .trim_end_matches('.')
        .trim()
        .to_ascii_lowercase();
    without_port
        .strip_suffix(".localhost")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
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
        METHOD_FOCUS => match parse_params::<NameParams>(&request.params)
            .and_then(|params| app_state.focus(&params.name))
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
    browser_profile_root: PathBuf,
    router_port: u16,
    router_routes: Arc<Mutex<BTreeMap<String, u16>>>,
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
    workspace: Option<String>,
    runtime: RuntimeConfig,
}

#[derive(Debug, Default)]
struct RuntimeConfig {
    server: Option<ServerRuntimeConfig>,
    agents: Vec<NamedCommandConfig>,
    terminals: Vec<NamedCommandConfig>,
    editor: Option<EditorRuntimeConfig>,
    browser_command: Option<String>,
    browser_urls: Vec<String>,
    browser_isolate_profile: bool,
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

#[derive(Debug, Default)]
struct RuntimeStartOutcome {
    started_processes: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
enum DependencyTarget {
    Name(String),
    Path(PathBuf),
}

impl AppState {
    fn load(
        state_path: PathBuf,
        niri_config_path: PathBuf,
        router_port: u16,
        router_routes: Arc<Mutex<BTreeMap<String, u16>>>,
    ) -> Result<Self> {
        let mut projects = BTreeMap::new();
        let mut focused_project: Option<String> = None;
        let mut suspended_projects = HashSet::new();
        let logs_path = state_path
            .parent()
            .map(|path| path.join("logs"))
            .unwrap_or_else(|| projd_types::default_data_dir().join("logs"));
        let browser_profile_root = state_path
            .parent()
            .map(|path| path.join("browser-profiles"))
            .unwrap_or_else(|| projd_types::default_data_dir().join("browser-profiles"));
        fs::create_dir_all(&browser_profile_root).with_context(|| {
            format!(
                "failed to create browser profile root: {}",
                browser_profile_root.display()
            )
        })?;
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
            browser_profile_root,
            router_port,
            router_routes,
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
        let workspace_override = params
            .workspace
            .as_deref()
            .map(|workspace| validate_workspace_name(workspace, "up.workspace"))
            .transpose()?;
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

        let result =
            self.up_internal_once(project_dir.clone(), workspace_override, resolving_paths);
        resolving_paths.remove(&project_dir);
        result
    }

    fn up_internal_once(
        &mut self,
        project_dir: PathBuf,
        workspace_override: Option<String>,
        resolving_paths: &mut HashSet<PathBuf>,
    ) -> Result<UpResult> {
        let project_cfg = load_project_config(&project_dir)?;
        let project_name = project_cfg.name.clone();
        self.ensure_dependencies_for(&project_cfg, resolving_paths)?;
        let desired_workspace = resolved_project_workspace(
            &project_name,
            project_cfg.workspace.as_deref(),
            workspace_override.as_deref(),
        )?;
        self.ensure_workspace_available(&project_name, &desired_workspace)?;

        let project_path = path_to_string(&project_cfg.path);

        if let Some(existing) = self.projects.get(&project_name) {
            if existing.path == project_path {
                let mut existing = existing.clone();
                if existing.workspace != desired_workspace {
                    let previous_projects = self.projects.clone();
                    existing.workspace = desired_workspace;
                    self.projects.insert(project_name.clone(), existing.clone());
                    if let Err(err) = self.sync() {
                        self.projects = previous_projects;
                        return Err(err);
                    }
                }
                let mut activation_warnings = Vec::new();
                self.activate_project_in_niri(&existing, &mut activation_warnings);
                let mut runtime = self.ensure_runtime_for_project(&existing, &project_cfg)?;
                activation_warnings.append(&mut runtime.warnings);
                return Ok(UpResult {
                    project: existing,
                    created: false,
                    local_host: project_local_host(&project_name),
                    local_origin: project_local_origin(&project_name, self.router_port),
                    started_processes: runtime.started_processes,
                    warnings: activation_warnings,
                });
            }
            bail!(
                "project '{}' is already registered with path {}",
                project_name,
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
            name: project_name.clone(),
            path: project_path,
            workspace: desired_workspace,
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
        let mut activation_warnings = Vec::new();
        self.activate_project_in_niri(&project, &mut activation_warnings);

        let runtime = match self.start_runtime_for_project(&project, &project_cfg.runtime) {
            Ok(runtime) => runtime,
            Err(err) => {
                self.projects = previous;
                self.focused_project = previous_focus;
                self.suspended_projects.remove(&project.name);
                let _ = self.stop_runtime_for_project(&project.name);
                let _ = self.sync();
                return Err(err);
            }
        };
        let mut runtime = runtime;
        activation_warnings.append(&mut runtime.warnings);

        Ok(UpResult {
            project,
            created: true,
            local_host: project_local_host(&project_name),
            local_origin: project_local_origin(&project_name, self.router_port),
            started_processes: runtime.started_processes,
            warnings: activation_warnings,
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

    fn focus(&mut self, name: &str) -> Result<FocusResult> {
        let project = self.project_by_name(name)?.clone();
        if self.suspended_projects.contains(name) {
            bail!("project '{}' is suspended; resume it before focusing", name);
        }

        let mut warnings = Vec::new();
        let mut workspace_focused = false;
        let mut windows_surfaced = false;

        let previous_focus = self.focused_project.clone();
        match focus_workspace_in_niri(&project.workspace) {
            Ok(()) => {
                workspace_focused = true;
                self.focused_project = Some(project.name.clone());
                if let Err(err) = self.persist_state() {
                    self.focused_project = previous_focus;
                    warnings.push(format!("failed to persist focused project: {err}"));
                }
            }
            Err(err) => warnings.push(format!(
                "failed to focus niri workspace '{}': {err}",
                project.workspace
            )),
        }

        match surface_window_in_niri(&project.workspace) {
            Ok(surface_result) => {
                windows_surfaced = surface_result;
                if !surface_result {
                    warnings.push(format!(
                        "no window surfaced in workspace '{}'; workspace may not have visible windows yet",
                        project.workspace
                    ));
                }
            }
            Err(err) => warnings.push(format!(
                "failed to surface windows in workspace '{}': {err}",
                project.workspace
            )),
        }

        Ok(FocusResult {
            status: self.project_status(&project),
            workspace_focused,
            windows_surfaced,
            warnings,
        })
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

    fn poll_runtime_events(&mut self) {
        let project_names: Vec<String> = self.runtime_processes.keys().cloned().collect();
        for project_name in project_names {
            let Some(mut processes) = self.runtime_processes.remove(&project_name) else {
                continue;
            };

            let mut still_running = Vec::new();
            for mut process in processes.drain(..) {
                match process.child.try_wait() {
                    Ok(Some(status)) => {
                        let workspace_name = self
                            .projects
                            .get(&project_name)
                            .map(|project| project.workspace.clone())
                            .unwrap_or_else(|| project_name.clone());
                        let context = RuntimeExitNotification {
                            project_name: project_name.clone(),
                            workspace_name,
                            process_name: process.name.clone(),
                            success: status.success(),
                            exit_status: status.to_string(),
                        };
                        if should_notify_runtime_exit(&context) {
                            if let Err(err) = send_runtime_exit_notification(&context) {
                                warn!(
                                    "failed to send runtime exit notification for project '{}', process '{}': {err}",
                                    context.project_name, context.process_name
                                );
                            }
                        }
                    }
                    Ok(None) => still_running.push(process),
                    Err(err) => {
                        warn!(
                            "failed to poll runtime process status for project '{}', process '{}': {err}",
                            project_name, process.name
                        );
                        still_running.push(process);
                    }
                }
            }

            if !still_running.is_empty() {
                self.runtime_processes.insert(project_name, still_running);
            }
        }
    }

    fn project_by_name(&self, name: &str) -> Result<&ProjectRecord> {
        self.projects
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("project '{}' is not registered", name))
    }

    fn ensure_workspace_available(&self, project_name: &str, workspace: &str) -> Result<()> {
        if let Some(conflict) = self
            .projects
            .iter()
            .find(|(name, project)| name.as_str() != project_name && project.workspace == workspace)
        {
            bail!(
                "workspace '{}' is already assigned to project '{}'",
                workspace,
                conflict.0
            );
        }
        Ok(())
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
    ) -> Result<RuntimeStartOutcome> {
        if let Some(processes) = self.runtime_processes.get(project.name.as_str()) {
            if !processes.is_empty() {
                return Ok(RuntimeStartOutcome {
                    started_processes: processes
                        .iter()
                        .map(|process| process.name.clone())
                        .collect(),
                    warnings: Vec::new(),
                });
            }
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
                    let _ = self.ensure_runtime_for_project(&project, &dependency_cfg)?;
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
                        let _ = self.ensure_runtime_for_project(&existing, &dependency_cfg)?;
                    } else {
                        let _ = self.up_internal(
                            UpParams {
                                path: path_to_string(path),
                                workspace: None,
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
    ) -> Result<RuntimeStartOutcome> {
        let specs = build_runtime_spawn_specs(
            project,
            config,
            &self.browser_profile_root,
            self.router_port,
        )?;
        if specs.is_empty() {
            self.runtime_processes.remove(&project.name);
            return Ok(RuntimeStartOutcome::default());
        }

        let mut browser_specs = Vec::new();
        let mut non_browser_specs = Vec::new();
        let mut warnings = Vec::new();
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
                        let message = err.to_string();
                        warn!(
                            "browser launch failed for project '{}': {message}",
                            project.name
                        );
                        warnings.push(message);
                    }
                }
            }
        }

        let started_processes = started
            .iter()
            .map(|process| process.name.clone())
            .collect::<Vec<_>>();
        self.runtime_processes.insert(project.name.clone(), started);
        Ok(RuntimeStartOutcome {
            started_processes,
            warnings,
        })
    }

    fn activate_project_in_niri(&mut self, project: &ProjectRecord, warnings: &mut Vec<String>) {
        if let Err(err) = reload_niri_config_in_niri() {
            warnings.push(format!("failed to reload niri config: {err}"));
        }

        if let Err(err) = focus_workspace_in_niri(&project.workspace) {
            warnings.push(format!(
                "failed to focus niri workspace '{}': {err}",
                project.workspace
            ));
            return;
        }

        self.focused_project = Some(project.name.clone());
        if let Err(err) = self.persist_state() {
            warnings.push(format!("failed to persist focused project: {err}"));
        }
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
        self.persist_state()?;
        self.sync_router_routes()
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

    fn sync_router_routes(&self) -> Result<()> {
        let routes = compute_router_routes(&self.projects)?;
        let mut shared = self
            .router_routes
            .lock()
            .map_err(|_| anyhow::anyhow!("router route table lock poisoned"))?;
        *shared = routes;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct RawProjectConfig {
    name: String,
    path: String,
    #[serde(default)]
    workspace: Option<String>,
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
    command: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default = "default_true")]
    isolate_profile: bool,
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
    let workspace = parsed
        .workspace
        .as_deref()
        .map(|value| validate_workspace_name(value, "workspace"))
        .transpose()?;

    let normalized_path = normalize_project_path(&parsed.path, project_dir)?;
    let runtime = build_runtime_config(&parsed, &normalized_path)?;
    Ok(LoadedProjectConfig {
        name,
        path: normalized_path,
        workspace,
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
        runtime.browser_command = browser
            .command
            .as_deref()
            .map(|value| non_empty_field(value, "browser.command"))
            .transpose()?;
        runtime.browser_urls = browser
            .urls
            .iter()
            .map(|url| non_empty_field(url, "browser.urls[]"))
            .collect::<Result<Vec<_>>>()?;
        runtime.browser_isolate_profile = browser.isolate_profile;
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

fn validate_workspace_name(value: &str, field: &str) -> Result<String> {
    non_empty_field(value, field)
}

fn resolved_project_workspace(
    project_name: &str,
    config_workspace: Option<&str>,
    override_workspace: Option<&str>,
) -> Result<String> {
    if let Some(workspace) = override_workspace {
        return validate_workspace_name(workspace, "up.workspace");
    }
    if let Some(workspace) = config_workspace {
        return validate_workspace_name(workspace, "workspace");
    }
    Ok(project_name.to_string())
}

fn default_true() -> bool {
    true
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

fn compute_router_routes(
    projects: &BTreeMap<String, ProjectRecord>,
) -> Result<BTreeMap<String, u16>> {
    let mut routes = BTreeMap::new();
    let mut owners = BTreeMap::new();
    for project in projects.values() {
        let route_key = project_local_route_key(&project.name);
        if let Some(existing) = owners.get(&route_key) {
            bail!(
                "router host collision: projects '{}' and '{}' both map to '{}.localhost'",
                existing,
                project.name,
                route_key
            );
        }
        owners.insert(route_key.clone(), project.name.clone());
        routes.insert(route_key, project.port);
    }
    Ok(routes)
}

fn project_local_route_key(project_name: &str) -> String {
    let mut label = String::with_capacity(project_name.len());
    for ch in project_name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            label.push(ch.to_ascii_lowercase());
        } else {
            label.push('-');
        }
    }
    let label = label.trim_matches('-');
    if label.is_empty() {
        "project".to_string()
    } else {
        label.to_string()
    }
}

fn project_local_host(project_name: &str) -> String {
    format!("{}.localhost", project_local_route_key(project_name))
}

fn project_local_origin(project_name: &str, router_port: u16) -> String {
    let host = project_local_host(project_name);
    if router_port == 80 {
        format!("http://{host}")
    } else {
        format!("http://{host}:{router_port}")
    }
}

fn build_runtime_spawn_specs(
    project: &ProjectRecord,
    config: &RuntimeConfig,
    browser_profile_root: &Path,
    router_port: u16,
) -> Result<Vec<RuntimeSpawnSpec>> {
    let mut specs = Vec::new();
    let mut seen = HashSet::new();
    let interpolation = RuntimeInterpolation::new(project, router_port);
    let port_value = interpolation.port.to_string();
    let base_env = vec![
        ("PORT".to_string(), port_value.clone()),
        ("PROJ_NAME".to_string(), project.name.clone()),
        ("PROJ_HOST".to_string(), interpolation.project_host.clone()),
        (
            "PROJ_ORIGIN".to_string(),
            interpolation.project_origin.clone(),
        ),
        ("PROJ_URL".to_string(), interpolation.project_origin.clone()),
        (
            "PROJ_ROUTER_PORT".to_string(),
            interpolation.router_port.to_string(),
        ),
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
        let interpolated_url = interpolate_runtime_value(url, &interpolation);
        let open_command = config
            .browser_command
            .as_deref()
            .map(ToString::to_string)
            .unwrap_or_else(browser_open_command);
        let open_command = interpolate_runtime_value(&open_command, &interpolation);
        let profile_dir = browser_profile_dir(browser_profile_root, &project.name);
        let command = build_browser_launch_command(
            &open_command,
            &interpolated_url,
            &profile_dir,
            config.browser_isolate_profile,
        );
        let env = browser_runtime_env(
            &base_env,
            &profile_dir,
            &interpolated_url,
            config.browser_isolate_profile,
        )?;
        push_runtime_spec(
            &mut specs,
            &mut seen,
            RuntimeSpawnSpec {
                name: format!("browser-{}", index + 1),
                command,
                cwd: PathBuf::from(&project.path),
                env,
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

#[derive(Debug, Clone)]
struct RuntimeInterpolation {
    project_name: String,
    port: u16,
    router_port: u16,
    project_host: String,
    project_origin: String,
}

impl RuntimeInterpolation {
    fn new(project: &ProjectRecord, router_port: u16) -> Self {
        let project_host = project_local_host(&project.name);
        let project_origin = project_local_origin(&project.name, router_port);
        Self {
            project_name: project.name.clone(),
            port: project.port,
            router_port,
            project_host,
            project_origin,
        }
    }
}

fn interpolate_runtime_value(value: &str, interpolation: &RuntimeInterpolation) -> String {
    let port = interpolation.port.to_string();
    let router_port = interpolation.router_port.to_string();
    value
        .replace("${PORT}", &port)
        .replace("${PROJ_NAME}", &interpolation.project_name)
        .replace("${PROJ_HOST}", &interpolation.project_host)
        .replace("${PROJ_ORIGIN}", &interpolation.project_origin)
        .replace("${PROJ_URL}", &interpolation.project_origin)
        .replace("${PROJ_ROUTER_PORT}", &router_port)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserFamily {
    Chromium,
    Firefox,
    Other,
}

fn browser_profile_dir(root: &Path, project_name: &str) -> PathBuf {
    root.join(sanitize_log_component(project_name))
}

fn browser_runtime_env(
    base_env: &[(String, String)],
    profile_dir: &Path,
    url: &str,
    isolate_profile: bool,
) -> Result<Vec<(String, String)>> {
    let mut env = base_env.to_vec();
    env.push((
        "PROJ_BROWSER_PROFILE_DIR".to_string(),
        profile_dir.display().to_string(),
    ));
    env.push(("PROJ_BROWSER_URL".to_string(), url.to_string()));
    if isolate_profile {
        let config_home = profile_dir.join("config");
        let cache_home = profile_dir.join("cache");
        let data_home = profile_dir.join("data");
        fs::create_dir_all(&config_home).with_context(|| {
            format!(
                "failed to create browser XDG config dir: {}",
                config_home.display()
            )
        })?;
        fs::create_dir_all(&cache_home).with_context(|| {
            format!(
                "failed to create browser XDG cache dir: {}",
                cache_home.display()
            )
        })?;
        fs::create_dir_all(&data_home).with_context(|| {
            format!(
                "failed to create browser XDG data dir: {}",
                data_home.display()
            )
        })?;
        env.push((
            "XDG_CONFIG_HOME".to_string(),
            config_home.display().to_string(),
        ));
        env.push((
            "XDG_CACHE_HOME".to_string(),
            cache_home.display().to_string(),
        ));
        env.push(("XDG_DATA_HOME".to_string(), data_home.display().to_string()));
    }

    Ok(env)
}

fn build_browser_launch_command(
    open_command: &str,
    url: &str,
    profile_dir: &Path,
    isolate_profile: bool,
) -> String {
    let mut command = open_command.trim().to_string();
    if isolate_profile {
        let profile_dir = profile_dir.display().to_string();
        match browser_family_for_command(&command) {
            BrowserFamily::Chromium => {
                if !command_has_flag(&command, "--new-window") {
                    command.push_str(" --new-window");
                }
                if !command_has_flag(&command, "--new-instance") {
                    command.push_str(" --new-instance");
                }
                if !command_has_flag_or_assigned_value(&command, "--user-data-dir") {
                    command.push_str(" --user-data-dir=");
                    command.push_str(&quote_shell_arg(&profile_dir));
                }
            }
            BrowserFamily::Firefox => {
                if !command_has_flag(&command, "--new-window") {
                    command.push_str(" --new-window");
                }
                if !command_has_flag(&command, "--no-remote") {
                    command.push_str(" --no-remote");
                }
                if !command_has_flag_or_assigned_value(&command, "--profile")
                    && !command_has_flag_or_assigned_value(&command, "-profile")
                    && !command_has_flag(&command, "-P")
                {
                    command.push_str(" --profile ");
                    command.push_str(&quote_shell_arg(&profile_dir));
                }
            }
            BrowserFamily::Other => {}
        }
    }

    command.push(' ');
    command.push_str(&quote_shell_arg(url));
    command
}

fn browser_family_for_command(command: &str) -> BrowserFamily {
    let Some(raw_executable) = command
        .split_whitespace()
        .next()
        .map(|token| token.trim_matches(|ch| ch == '\'' || ch == '"'))
    else {
        return BrowserFamily::Other;
    };
    let Some(executable_name) = Path::new(raw_executable)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase())
    else {
        return BrowserFamily::Other;
    };

    if executable_name.contains("firefox")
        || executable_name.contains("librewolf")
        || executable_name.contains("waterfox")
        || executable_name.contains("floorp")
    {
        return BrowserFamily::Firefox;
    }

    if executable_name.contains("chrom")
        || executable_name.contains("chrome")
        || executable_name.contains("brave")
        || executable_name.contains("vivaldi")
        || executable_name.contains("edge")
        || executable_name.contains("helium")
        || executable_name.contains("electron")
    {
        return BrowserFamily::Chromium;
    }

    BrowserFamily::Other
}

fn command_has_flag(command: &str, flag: &str) -> bool {
    command.split_whitespace().any(|token| token == flag)
}

fn command_has_flag_or_assigned_value(command: &str, flag: &str) -> bool {
    let assigned_prefix = format!("{flag}=");
    command
        .split_whitespace()
        .any(|token| token == flag || token.starts_with(&assigned_prefix))
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
        let title_pattern = escape_kdl_string(&project_title_match_pattern(&project.name));
        rendered.push_str(&format!("workspace \"{workspace}\"\n"));
        rendered.push_str("window-rule {\n");
        rendered.push_str(&format!("  match title=\"{title_pattern}\"\n"));
        rendered.push_str(&format!("  open-on-workspace \"{workspace}\"\n"));
        rendered.push_str("}\n");
    }
    rendered
}

fn project_title_match_pattern(project_name: &str) -> String {
    format!(r"^\[proj:{}\]$", regex::escape(project_name))
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

#[derive(Debug)]
struct RuntimeExitNotification {
    project_name: String,
    workspace_name: String,
    process_name: String,
    success: bool,
    exit_status: String,
}

fn niri_binary() -> String {
    std::env::var("PROJD_NIRI_BIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "niri".to_string())
}

fn notifier_binary() -> String {
    std::env::var("PROJD_NOTIFY_BIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "notify-send".to_string())
}

fn focus_workspace_in_niri(workspace: &str) -> Result<()> {
    let output = Command::new(niri_binary())
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

fn surface_window_in_niri(workspace: &str) -> Result<bool> {
    let Some(workspace_id) = workspace_id_from_niri(workspace) else {
        return Ok(false);
    };
    let Some(window_id) = active_or_first_window_id_from_niri(workspace_id) else {
        return Ok(false);
    };
    let window_id_arg = window_id.to_string();
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("action")
        .arg("focus-window")
        .arg("--id")
        .arg(&window_id_arg)
        .output()
        .with_context(|| {
            format!("failed to execute niri focus-window command in workspace '{workspace}'")
        })?;
    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.contains("NoWindowFocused") || stderr.contains("no window") {
        return Ok(false);
    }
    if stderr.is_empty() {
        bail!("niri focus-window command failed in workspace '{workspace}'");
    }
    bail!("niri focus-window command failed in workspace '{workspace}': {stderr}");
}

fn workspace_id_from_niri(workspace: &str) -> Option<u64> {
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("--json")
        .arg("workspaces")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let workspaces = value.as_array()?;
    workspaces.iter().find_map(|item| {
        let object = item.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != workspace {
            return None;
        }
        object.get("id")?.as_u64()
    })
}

fn workspace_index_from_niri(workspace: &str) -> Option<u64> {
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("--json")
        .arg("workspaces")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let workspaces = value.as_array()?;
    workspaces.iter().find_map(|item| {
        let object = item.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != workspace {
            return None;
        }
        object.get("idx")?.as_u64()
    })
}

fn active_or_first_window_id_from_niri(workspace_id: u64) -> Option<u64> {
    if let Some(active) = active_window_id_from_niri_workspace(workspace_id) {
        return Some(active);
    }
    first_window_id_from_niri_workspace(workspace_id)
}

fn active_window_id_from_niri_workspace(workspace_id: u64) -> Option<u64> {
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("--json")
        .arg("workspaces")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let workspaces = value.as_array()?;
    workspaces.iter().find_map(|item| {
        let object = item.as_object()?;
        if object.get("id")?.as_u64()? != workspace_id {
            return None;
        }
        object.get("active_window_id").and_then(Value::as_u64)
    })
}

fn first_window_id_from_niri_workspace(workspace_id: u64) -> Option<u64> {
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("--json")
        .arg("windows")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let windows = value.as_array()?;
    windows.iter().find_map(|item| {
        let object = item.as_object()?;
        if object.get("workspace_id")?.as_u64()? != workspace_id {
            return None;
        }
        object.get("id")?.as_u64()
    })
}

fn reload_niri_config_in_niri() -> Result<()> {
    let output = Command::new(niri_binary())
        .arg("msg")
        .arg("action")
        .arg("load-config-file")
        .output()
        .context("failed to execute niri config reload command")?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        bail!("niri config reload command failed");
    }

    bail!("niri config reload command failed: {stderr}")
}

fn focused_workspace_from_niri() -> Option<String> {
    let output = Command::new(niri_binary())
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

fn send_runtime_exit_notification(context: &RuntimeExitNotification) -> Result<()> {
    let title = format!(
        "{}: {}",
        context.project_name,
        if context.success {
            "process exited"
        } else {
            "process failed"
        }
    );
    let workspace = format_workspace_for_notification(
        &context.workspace_name,
        workspace_index_from_niri(&context.workspace_name),
    );
    let body = format!(
        "workspace: {workspace}\nprocess: {}\nstatus: {}",
        context.process_name, context.exit_status
    );
    let output = Command::new(notifier_binary())
        .arg(title)
        .arg(body)
        .output()
        .context("failed to execute desktop notifier")?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        bail!("desktop notifier exited with status {}", output.status);
    }
    bail!(
        "desktop notifier exited with status {}: {stderr}",
        output.status
    );
}

fn format_workspace_for_notification(workspace_name: &str, index: Option<u64>) -> String {
    match index {
        Some(index) => format!("{workspace_name} (#{index})"),
        None => workspace_name.to_string(),
    }
}

fn should_notify_runtime_exit(context: &RuntimeExitNotification) -> bool {
    if !context.success {
        return true;
    }
    context.process_name == "server" || context.process_name.starts_with("agent-")
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
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Mutex, OnceLock};
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
    fn project_title_match_pattern_escapes_regex_specials() {
        let pattern = project_title_match_pattern("context-systems.v2+alpha");
        assert_eq!(pattern, r"^\[proj:context\-systems\.v2\+alpha\]$");
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
            browser_profile_root: PathBuf::from("/tmp/browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
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
            browser_profile_root: PathBuf::from("/tmp/browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
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
workspace = \"5\"\n\
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
command = \"helium\"\n\
urls = [\"http://localhost:${PORT}\"]\n",
        )
        .unwrap();

        let loaded = load_project_config(&base).unwrap();
        assert_eq!(loaded.workspace.as_deref(), Some("5"));
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
        assert_eq!(runtime.browser_command.as_deref(), Some("helium"));
        assert_eq!(runtime.browser_urls, vec!["http://localhost:${PORT}"]);
        assert!(runtime.browser_isolate_profile);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sanitize_log_component_replaces_unsafe_characters() {
        assert_eq!(sanitize_log_component("agent-alpha"), "agent-alpha");
        assert_eq!(sanitize_log_component("agent alpha"), "agent_alpha");
        assert_eq!(sanitize_log_component(".."), "process");
    }

    #[test]
    fn resolved_project_workspace_prefers_override_then_config_then_name() {
        let from_override = resolved_project_workspace("demo", Some("cfg"), Some("7")).unwrap();
        let from_config = resolved_project_workspace("demo", Some("cfg"), None).unwrap();
        let from_name = resolved_project_workspace("demo", None, None).unwrap();
        assert_eq!(from_override, "7");
        assert_eq!(from_config, "cfg");
        assert_eq!(from_name, "demo");
    }

    #[test]
    fn resolved_project_workspace_rejects_empty_workspace() {
        let err = resolved_project_workspace("demo", Some("   "), None).unwrap_err();
        assert!(err.to_string().contains("workspace cannot be empty"));
    }

    #[test]
    fn interpolate_runtime_value_replaces_port_placeholder_tokens() {
        let project = ProjectRecord {
            name: "demo".to_string(),
            path: "/tmp/demo".to_string(),
            workspace: "demo".to_string(),
            port: 3210,
        };
        let interpolation = RuntimeInterpolation::new(&project, DEFAULT_ROUTER_PORT);
        assert_eq!(
            interpolate_runtime_value("http://localhost:${PORT}/health", &interpolation),
            "http://localhost:3210/health"
        );
        assert_eq!(
            interpolate_runtime_value("no-port", &interpolation),
            "no-port"
        );
    }

    #[test]
    fn project_local_origin_uses_router_port() {
        assert_eq!(
            project_local_host("Context Systems"),
            "context-systems.localhost"
        );
        assert_eq!(
            project_local_origin("Context Systems", 48080),
            "http://context-systems.localhost:48080"
        );
        assert_eq!(
            project_local_origin("Context Systems", 80),
            "http://context-systems.localhost"
        );
    }

    #[test]
    fn interpolate_runtime_value_replaces_router_tokens() {
        let project = ProjectRecord {
            name: "frontend".to_string(),
            path: "/tmp/frontend".to_string(),
            workspace: "frontend".to_string(),
            port: 3301,
        };
        let interpolation = RuntimeInterpolation::new(&project, 48080);
        let rendered = interpolate_runtime_value(
            "host=${PROJ_HOST} origin=${PROJ_ORIGIN} name=${PROJ_NAME} port=${PORT} router=${PROJ_ROUTER_PORT}",
            &interpolation,
        );
        assert_eq!(
            rendered,
            "host=frontend.localhost origin=http://frontend.localhost:48080 name=frontend port=3301 router=48080"
        );
    }

    #[test]
    fn localhost_route_key_from_host_parses_localhost_hosts() {
        assert_eq!(
            localhost_route_key_from_host("frontend.localhost:48080"),
            Some("frontend".to_string())
        );
        assert_eq!(
            localhost_route_key_from_host("frontend.localhost."),
            Some("frontend".to_string())
        );
        assert_eq!(localhost_route_key_from_host("localhost"), None);
    }

    #[test]
    fn compute_router_routes_rejects_colliding_project_names() {
        let mut projects = BTreeMap::new();
        projects.insert(
            "foo-bar".to_string(),
            ProjectRecord {
                name: "foo-bar".to_string(),
                path: "/tmp/foo-bar".to_string(),
                workspace: "foo-bar".to_string(),
                port: 3001,
            },
        );
        projects.insert(
            "foo_bar".to_string(),
            ProjectRecord {
                name: "foo_bar".to_string(),
                path: "/tmp/foo_bar".to_string(),
                workspace: "foo_bar".to_string(),
                port: 3002,
            },
        );
        let err = compute_router_routes(&projects).unwrap_err();
        assert!(err.to_string().contains("router host collision"));
    }

    #[test]
    fn build_runtime_spawn_specs_prefers_project_browser_command() {
        let project = ProjectRecord {
            name: "demo".to_string(),
            path: "/tmp/demo".to_string(),
            workspace: "demo".to_string(),
            port: 3001,
        };
        let config = RuntimeConfig {
            browser_command: Some("helium".to_string()),
            browser_urls: vec!["http://localhost:${PORT}".to_string()],
            browser_isolate_profile: true,
            ..RuntimeConfig::default()
        };

        let specs = build_runtime_spawn_specs(
            &project,
            &config,
            Path::new("/tmp/browser-profiles"),
            DEFAULT_ROUTER_PORT,
        )
        .unwrap();
        let browser = specs
            .iter()
            .find(|spec| spec.name == "browser-1")
            .expect("missing browser spawn spec");
        assert!(browser.command.contains("helium"));
        assert!(browser.command.contains("--new-window"));
        assert!(browser.command.contains("--new-instance"));
        assert!(browser.command.contains("--user-data-dir="));
        assert!(browser.command.contains("http://localhost:3001"));
        assert!(browser
            .env
            .iter()
            .any(|(key, _)| key == "PROJ_BROWSER_PROFILE_DIR"));
        assert!(browser
            .env
            .iter()
            .any(|(key, value)| key == "PROJ_BROWSER_URL" && value == "http://localhost:3001"));
        assert!(browser.env.iter().any(|(key, _)| key == "XDG_CONFIG_HOME"));
        assert!(browser.env.iter().any(|(key, _)| key == "XDG_CACHE_HOME"));
        assert!(browser.env.iter().any(|(key, _)| key == "XDG_DATA_HOME"));
    }

    #[test]
    fn build_runtime_spawn_specs_respects_browser_isolation_opt_out() {
        let project = ProjectRecord {
            name: "demo".to_string(),
            path: "/tmp/demo".to_string(),
            workspace: "demo".to_string(),
            port: 3001,
        };
        let config = RuntimeConfig {
            browser_command: Some("helium".to_string()),
            browser_urls: vec!["http://localhost:${PORT}".to_string()],
            browser_isolate_profile: false,
            ..RuntimeConfig::default()
        };

        let specs = build_runtime_spawn_specs(
            &project,
            &config,
            Path::new("/tmp/browser-profiles"),
            DEFAULT_ROUTER_PORT,
        )
        .unwrap();
        let browser = specs
            .iter()
            .find(|spec| spec.name == "browser-1")
            .expect("missing browser spawn spec");
        assert_eq!(browser.command, "helium http://localhost:3001");
        assert!(!browser.env.iter().any(|(key, _)| key == "XDG_CONFIG_HOME"));
        assert!(!browser.env.iter().any(|(key, _)| key == "XDG_CACHE_HOME"));
        assert!(!browser.env.iter().any(|(key, _)| key == "XDG_DATA_HOME"));
    }

    #[test]
    fn build_browser_launch_command_adds_firefox_isolation_flags() {
        let profile_dir = PathBuf::from("/tmp/projd-browser-profile");
        let command =
            build_browser_launch_command("firefox", "http://localhost:3001", &profile_dir, true);
        assert!(command.contains("--new-window"));
        assert!(command.contains("--no-remote"));
        assert!(command.contains("--profile"));
        assert!(command.contains("http://localhost:3001"));
    }

    #[test]
    fn build_browser_launch_command_keeps_other_commands_unchanged() {
        let profile_dir = PathBuf::from("/tmp/projd-browser-profile");
        let command =
            build_browser_launch_command("xdg-open", "http://localhost:3001", &profile_dir, true);
        assert_eq!(command, "xdg-open http://localhost:3001");
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

        let loaded = AppState::load(
            state_path,
            niri_config_path,
            DEFAULT_ROUTER_PORT,
            Arc::new(Mutex::new(BTreeMap::new())),
        )
        .unwrap();
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

        let loaded = AppState::load(
            state_path,
            niri_config_path,
            DEFAULT_ROUTER_PORT,
            Arc::new(Mutex::new(BTreeMap::new())),
        )
        .unwrap();
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
            browser_profile_root: base.join("browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_processes: BTreeMap::new(),
        };
        state.persist_state().unwrap();

        let stored: PersistedState = serde_json::from_str(&fs::read_to_string(state_path).unwrap())
            .expect("failed to deserialize persisted state");
        assert_eq!(stored.focused_project.as_deref(), Some("api"));
        assert_eq!(stored.suspended_projects, vec!["frontend".to_string()]);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn focus_reports_warnings_when_niri_commands_fail() {
        let _guard = env_lock().lock().unwrap();
        let previous_niri = std::env::var_os("PROJD_NIRI_BIN");
        std::env::set_var("PROJD_NIRI_BIN", "command-that-does-not-exist");

        let base = unique_temp_dir("focus-warnings");
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("state.json");
        let niri_config_path = base.join("config.kdl");
        let mut projects = BTreeMap::new();
        projects.insert(
            "demo".to_string(),
            ProjectRecord {
                name: "demo".to_string(),
                path: base.display().to_string(),
                workspace: "demo".to_string(),
                port: 3001,
            },
        );
        let mut state = AppState {
            projects,
            focused_project: None,
            suspended_projects: HashSet::new(),
            state_path,
            niri_config_path,
            logs_path: base.join("logs"),
            browser_profile_root: base.join("browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_processes: BTreeMap::new(),
        };

        let result = state.focus("demo").unwrap();
        assert!(!result.workspace_focused);
        assert!(!result.windows_surfaced);
        assert_eq!(result.status.project.name, "demo");
        assert!(!result.warnings.is_empty());

        restore_env("PROJD_NIRI_BIN", previous_niri);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn runtime_exit_notification_mentions_workspace_context() {
        let context = RuntimeExitNotification {
            project_name: "frontend".to_string(),
            workspace_name: "context-systems".to_string(),
            process_name: "server".to_string(),
            success: false,
            exit_status: std::process::ExitStatus::from_raw(256).to_string(),
        };

        let title = format!(
            "{}: {}",
            context.project_name,
            if context.success {
                "process exited"
            } else {
                "process failed"
            }
        );
        let workspace = format_workspace_for_notification(&context.workspace_name, Some(2));
        let body = format!(
            "workspace: {workspace}\nprocess: {}\nstatus: {}",
            context.process_name, context.exit_status
        );

        assert_eq!(title, "frontend: process failed");
        assert!(body.contains("workspace: context-systems (#2)"));
        assert!(body.contains("process: server"));
        assert!(body.contains("status: exit status: 1"));
    }

    #[test]
    fn format_workspace_for_notification_handles_optional_index() {
        assert_eq!(
            format_workspace_for_notification("context-systems", Some(2)),
            "context-systems (#2)"
        );
        assert_eq!(
            format_workspace_for_notification("context-systems", None),
            "context-systems"
        );
    }

    #[test]
    fn should_notify_runtime_exit_filters_successful_low_signal_processes() {
        let server_success = RuntimeExitNotification {
            project_name: "demo".to_string(),
            workspace_name: "demo".to_string(),
            process_name: "server".to_string(),
            success: true,
            exit_status: "exit status: 0".to_string(),
        };
        let agent_success = RuntimeExitNotification {
            project_name: "demo".to_string(),
            workspace_name: "demo".to_string(),
            process_name: "agent-indexer".to_string(),
            success: true,
            exit_status: "exit status: 0".to_string(),
        };
        let terminal_success = RuntimeExitNotification {
            project_name: "demo".to_string(),
            workspace_name: "demo".to_string(),
            process_name: "terminal-dev".to_string(),
            success: true,
            exit_status: "exit status: 0".to_string(),
        };
        let terminal_failure = RuntimeExitNotification {
            project_name: "demo".to_string(),
            workspace_name: "demo".to_string(),
            process_name: "terminal-dev".to_string(),
            success: false,
            exit_status: "exit status: 1".to_string(),
        };

        assert!(should_notify_runtime_exit(&server_success));
        assert!(should_notify_runtime_exit(&agent_success));
        assert!(!should_notify_runtime_exit(&terminal_success));
        assert!(should_notify_runtime_exit(&terminal_failure));
    }

    #[test]
    fn poll_runtime_events_handles_missing_notifier_without_panicking() {
        let _guard = env_lock().lock().unwrap();
        let previous_notifier = std::env::var_os("PROJD_NOTIFY_BIN");
        std::env::set_var("PROJD_NOTIFY_BIN", "command-that-does-not-exist");

        let base = unique_temp_dir("poll-runtime-events");
        fs::create_dir_all(&base).unwrap();
        let child = Command::new("sh")
            .arg("-lc")
            .arg("exit 1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut projects = BTreeMap::new();
        projects.insert(
            "demo".to_string(),
            ProjectRecord {
                name: "demo".to_string(),
                path: base.display().to_string(),
                workspace: "demo".to_string(),
                port: 3001,
            },
        );
        let mut runtime_processes = BTreeMap::new();
        runtime_processes.insert(
            "demo".to_string(),
            vec![RuntimeProcess {
                name: "server".to_string(),
                log_path: base.join("server.log"),
                child,
            }],
        );
        let mut state = AppState {
            projects,
            focused_project: None,
            suspended_projects: HashSet::new(),
            state_path: base.join("state.json"),
            niri_config_path: base.join("config.kdl"),
            logs_path: base.join("logs"),
            browser_profile_root: base.join("browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_processes,
        };

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            state.poll_runtime_events();
            if state.runtime_processes.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(state.runtime_processes.is_empty());

        restore_env("PROJD_NOTIFY_BIN", previous_notifier);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn poll_runtime_events_skips_clean_terminal_notifications() {
        let _guard = env_lock().lock().unwrap();
        let previous_notifier = std::env::var_os("PROJD_NOTIFY_BIN");

        let base = unique_temp_dir("poll-runtime-events-filtered");
        fs::create_dir_all(&base).unwrap();
        let notify_log = base.join("notify.log");
        let notify_script = base.join("notify.sh");
        fs::write(
            &notify_script,
            format!(
                "#!/usr/bin/env sh\nset -eu\nprintf '%s\\n' \"$1\" >> \"{}\"\n",
                notify_log.display()
            ),
        )
        .unwrap();
        let mut perms = fs::metadata(&notify_script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&notify_script, perms).unwrap();
        std::env::set_var("PROJD_NOTIFY_BIN", notify_script.display().to_string());

        let success_child = Command::new("sh")
            .arg("-lc")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let failure_child = Command::new("sh")
            .arg("-lc")
            .arg("exit 1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut projects = BTreeMap::new();
        projects.insert(
            "demo".to_string(),
            ProjectRecord {
                name: "demo".to_string(),
                path: base.display().to_string(),
                workspace: "demo".to_string(),
                port: 3001,
            },
        );
        let mut runtime_processes = BTreeMap::new();
        runtime_processes.insert(
            "demo".to_string(),
            vec![
                RuntimeProcess {
                    name: "terminal-dev".to_string(),
                    log_path: base.join("terminal.log"),
                    child: success_child,
                },
                RuntimeProcess {
                    name: "terminal-ci".to_string(),
                    log_path: base.join("terminal-ci.log"),
                    child: failure_child,
                },
            ],
        );
        let mut state = AppState {
            projects,
            focused_project: None,
            suspended_projects: HashSet::new(),
            state_path: base.join("state.json"),
            niri_config_path: base.join("config.kdl"),
            logs_path: base.join("logs"),
            browser_profile_root: base.join("browser-profiles"),
            router_port: DEFAULT_ROUTER_PORT,
            router_routes: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_processes,
        };

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            state.poll_runtime_events();
            if state.runtime_processes.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(state.runtime_processes.is_empty());

        let titles = fs::read_to_string(&notify_log).unwrap_or_default();
        assert_eq!(titles.lines().count(), 1);
        assert!(titles.contains("demo: process failed"));
        assert!(!titles.contains("process exited"));

        restore_env("PROJD_NOTIFY_BIN", previous_notifier);
        let _ = fs::remove_dir_all(&base);
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
        std::env::temp_dir().join(format!("projd-{label}-{nanos}"))
    }
}
