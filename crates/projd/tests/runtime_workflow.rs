use projd_types::{
    ListResult, LogsParams, LogsResult, Request, Response, UpParams, UpResult, METHOD_DOWN,
    METHOD_LIST, METHOD_LOGS, METHOD_PING, METHOD_SHUTDOWN, METHOD_UP,
};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct DaemonHarness {
    child: Child,
    root_dir: PathBuf,
    socket_path: PathBuf,
    state_path: PathBuf,
    niri_config_path: PathBuf,
    router_port: u16,
}

impl DaemonHarness {
    fn start() -> Self {
        Self::start_with_env(&[])
    }

    fn start_with_env(env: &[(String, String)]) -> Self {
        let root_dir = unique_temp_dir("runtime-workflow");
        let socket_path = root_dir.join("projd.sock");
        let state_path = root_dir.join("state.json");
        let niri_config_path = root_dir.join("niri").join("config.kdl");
        let router_port = allocate_router_port();

        fs::create_dir_all(niri_config_path.parent().expect("niri config parent path"))
            .expect("failed to create niri config directory");
        fs::write(&niri_config_path, "").expect("failed to seed niri config");

        let mut daemon_env = env.to_vec();
        daemon_env.push(("PROJD_ROUTER_PORT".to_string(), router_port.to_string()));
        let child = spawn_projd(&socket_path, &state_path, &niri_config_path, &daemon_env);
        let harness = Self {
            child,
            root_dir,
            socket_path,
            state_path,
            niri_config_path,
            router_port,
        };
        harness.wait_for_ping();
        harness
    }

    fn wait_for_ping(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(response) = request(&self.socket_path, METHOD_PING, Value::Null) {
                if response.ok {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for daemon to respond to ping");
    }

    fn create_runtime_project(&self, name: &str) -> PathBuf {
        let project_dir = self.root_dir.join(format!("project-{name}"));
        fs::create_dir_all(&project_dir).expect("failed to create project dir");

        write_executable_script(
            &project_dir.join("server.sh"),
            "#!/usr/bin/env sh\n\
echo \"server-start port=${PORT}\"\n\
trap 'echo \"server-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
        );
        write_executable_script(
            &project_dir.join("agent.sh"),
            "#!/usr/bin/env sh\n\
echo \"agent-start\"\n\
trap 'echo \"agent-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
        );

        fs::write(
            project_dir.join(".project.toml"),
            format!(
                "name = \"{name}\"\n\
path = \".\"\n\
\n\
[server]\n\
command = \"sh ./server.sh\"\n\
port_env = \"PORT\"\n\
cwd = \".\"\n\
\n\
[[agents]]\n\
name = \"alpha\"\n\
command = \"sh ./agent.sh\"\n\
cwd = \".\"\n"
            ),
        )
        .expect("failed to write .project.toml");

        project_dir
    }
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        let _ = request(&self.socket_path, METHOD_SHUTDOWN, Value::Null);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }

        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {}
        }

        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

#[test]
fn runtime_workflow_collects_logs_and_stops_processes() {
    let harness = DaemonHarness::start();
    let project_dir = harness.create_runtime_project("runtime-demo");

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .expect("failed to serialize up params"),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let up_result: UpResult = serde_json::from_value(up_response.result.unwrap()).unwrap();
    assert_eq!(up_result.project.port, 3001);
    assert_eq!(up_result.local_host, "runtime-demo.localhost");
    assert!(up_result
        .local_origin
        .starts_with("http://runtime-demo.localhost:"));

    let server_log = harness
        .root_dir
        .join("logs")
        .join("runtime-demo")
        .join("server.log");
    let agent_log = harness
        .root_dir
        .join("logs")
        .join("runtime-demo")
        .join("agent-alpha.log");
    wait_for_log_contains(&server_log, "server-start port=3001");
    wait_for_log_contains(&agent_log, "agent-start");

    let logs_response = request(
        &harness.socket_path,
        METHOD_LOGS,
        serde_json::to_value(LogsParams {
            name: "runtime-demo".to_string(),
            process: None,
        })
        .expect("failed to serialize logs params"),
    )
    .expect("logs request failed");
    assert!(logs_response.ok, "logs failed: {:?}", logs_response.error);

    let logs: LogsResult = serde_json::from_value(logs_response.result.unwrap()).unwrap();
    assert_eq!(logs.project, "runtime-demo");
    assert_eq!(logs.logs.len(), 2);
    assert!(logs.logs.iter().any(|entry| entry.process == "server"));
    assert!(logs.logs.iter().any(|entry| entry.process == "agent-alpha"));

    let single_response = request(
        &harness.socket_path,
        METHOD_LOGS,
        serde_json::to_value(LogsParams {
            name: "runtime-demo".to_string(),
            process: Some("server".to_string()),
        })
        .expect("failed to serialize logs params"),
    )
    .expect("single logs request failed");
    assert!(
        single_response.ok,
        "logs failed: {:?}",
        single_response.error
    );
    let single: LogsResult = serde_json::from_value(single_response.result.unwrap()).unwrap();
    assert_eq!(single.logs.len(), 1);
    assert!(single.logs[0].content.contains("server-start port=3001"));

    let down_response = request(
        &harness.socket_path,
        METHOD_DOWN,
        serde_json::json!({"name":"runtime-demo"}),
    )
    .expect("down request failed");
    assert!(down_response.ok, "down failed: {:?}", down_response.error);

    wait_for_log_contains(&server_log, "server-stop");
    wait_for_log_contains(&agent_log, "agent-stop");

    // After down, project is stopped but still registered
    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert_eq!(listed.projects.len(), 1);
    assert_eq!(listed.projects[0].name, "runtime-demo");
}

#[test]
fn runtime_workflow_rolls_back_on_spawn_failure() {
    let harness = DaemonHarness::start();
    let project_dir = harness.root_dir.join("project-broken-runtime");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"broken-runtime\"\n\
path = \".\"\n\
\n\
[server]\n\
command = \"command-that-does-not-exist-for-projd-tests\"\n\
cwd = \".\"\n",
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(!up_response.ok, "up unexpectedly succeeded");

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert!(listed.projects.is_empty());

    let niri_config = fs::read_to_string(&harness.niri_config_path).unwrap();
    assert!(!niri_config.contains("workspace \"broken-runtime\""));
    assert!(harness.state_path.exists());
}

#[test]
fn runtime_workflow_depends_on_path_starts_dependency_first() {
    let harness = DaemonHarness::start();
    let dep_dir = harness.root_dir.join("project-core-lib");
    let app_dir = harness.root_dir.join("project-app-ui");
    fs::create_dir_all(&dep_dir).unwrap();
    fs::create_dir_all(&app_dir).unwrap();

    write_executable_script(
        &dep_dir.join("server.sh"),
        "#!/usr/bin/env sh\n\
echo \"dep-start\"\n\
trap 'echo \"dep-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
    );
    write_executable_script(
        &app_dir.join("server.sh"),
        "#!/usr/bin/env sh\n\
echo \"app-start\"\n\
trap 'echo \"app-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
    );
    fs::write(
        dep_dir.join(".project.toml"),
        "name = \"core-lib\"\n\
path = \".\"\n\
\n\
[server]\n\
command = \"sh ./server.sh\"\n\
cwd = \".\"\n",
    )
    .unwrap();
    fs::write(
        app_dir.join(".project.toml"),
        format!(
            "name = \"app-ui\"\n\
path = \".\"\n\
depends_on = [\"{}\"]\n\
\n\
[server]\n\
command = \"sh ./server.sh\"\n\
cwd = \".\"\n",
            dep_dir.display()
        ),
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: app_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert_eq!(listed.projects.len(), 2);
    assert!(listed
        .projects
        .iter()
        .any(|project| project.name == "core-lib"));
    assert!(listed
        .projects
        .iter()
        .any(|project| project.name == "app-ui"));

    let dep_log = harness
        .root_dir
        .join("logs")
        .join("core-lib")
        .join("server.log");
    let app_log = harness
        .root_dir
        .join("logs")
        .join("app-ui")
        .join("server.log");
    wait_for_log_contains(&dep_log, "dep-start");
    wait_for_log_contains(&app_log, "app-start");

    let down_app = request(
        &harness.socket_path,
        METHOD_DOWN,
        serde_json::json!({"name":"app-ui"}),
    )
    .unwrap();
    assert!(down_app.ok);
    let down_dep = request(
        &harness.socket_path,
        METHOD_DOWN,
        serde_json::json!({"name":"core-lib"}),
    )
    .unwrap();
    assert!(down_dep.ok);
}

#[test]
fn runtime_workflow_ready_pattern_timeout_rolls_back_and_skips_browser() {
    let browser_events = unique_temp_dir("browser-events").join("events.log");
    fs::create_dir_all(browser_events.parent().unwrap()).unwrap();
    let browser_script = unique_temp_dir("browser-script").join("browser.sh");
    if let Some(parent) = browser_script.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    write_executable_script(
        &browser_script,
        format!(
            "#!/usr/bin/env sh\n\
echo \"$1\" >> {}\n",
            browser_events.display()
        )
        .as_str(),
    );

    let harness = DaemonHarness::start_with_env(&[
        (
            "PROJD_BROWSER_CMD".to_string(),
            format!("sh {}", browser_script.display()),
        ),
        ("PROJD_READY_TIMEOUT_MS".to_string(), "300".to_string()),
    ]);

    let project_dir = harness.root_dir.join("project-ready-timeout");
    fs::create_dir_all(&project_dir).unwrap();
    write_executable_script(
        &project_dir.join("server.sh"),
        "#!/usr/bin/env sh\n\
echo \"server-boot\"\n\
trap 'echo \"server-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
    );
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"ready-timeout\"\n\
path = \".\"\n\
\n\
[server]\n\
command = \"sh ./server.sh\"\n\
ready_pattern = \"never-ready\"\n\
cwd = \".\"\n\
\n\
[browser]\n\
urls = [\"http://localhost:${PORT}\"]\n",
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(!up_response.ok, "up unexpectedly succeeded");
    assert!(up_response
        .error
        .unwrap_or_default()
        .contains("timed out waiting for server.ready_pattern"));

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert!(listed.projects.is_empty());

    if browser_events.exists() {
        let content = fs::read_to_string(browser_events).unwrap();
        assert!(content.trim().is_empty());
    }
}

#[test]
fn runtime_workflow_browser_launch_failure_does_not_block_up() {
    let harness = DaemonHarness::start_with_env(&[(
        "PROJD_BROWSER_CMD".to_string(),
        "command-that-does-not-exist-for-projd-tests".to_string(),
    )]);
    let project_dir = harness.root_dir.join("project-browser-failure");
    fs::create_dir_all(&project_dir).unwrap();
    write_executable_script(
        &project_dir.join("server.sh"),
        "#!/usr/bin/env sh\n\
echo \"server-boot\"\n\
trap 'echo \"server-stop\"; exit 0' TERM INT\n\
while true; do sleep 0.1; done\n",
    );
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"browser-failure\"\n\
path = \".\"\n\
\n\
[server]\n\
command = \"sh ./server.sh\"\n\
cwd = \".\"\n\
\n\
[browser]\n\
urls = [\"http://localhost:${PORT}\"]\n",
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let server_log = harness
        .root_dir
        .join("logs")
        .join("browser-failure")
        .join("server.log");
    wait_for_log_contains(&server_log, "server-boot");

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert_eq!(listed.projects.len(), 1);
    assert_eq!(listed.projects[0].name, "browser-failure");

    let down_response = request(
        &harness.socket_path,
        METHOD_DOWN,
        serde_json::json!({"name":"browser-failure"}),
    )
    .unwrap();
    assert!(down_response.ok);
}

#[test]
fn runtime_workflow_routes_project_localhost_to_backend_port() {
    let harness = DaemonHarness::start();
    let project_dir = harness.root_dir.join("project-router");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"router-demo\"\n\
path = \".\"\n\
\n\
[browser]\n\
urls = [\"${PROJ_ORIGIN}\"]\n",
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);
    let up_result: UpResult = serde_json::from_value(up_response.result.unwrap()).unwrap();
    assert_eq!(up_result.local_host, "router-demo.localhost");
    assert_eq!(
        up_result.local_origin,
        format!("http://router-demo.localhost:{}", harness.router_port)
    );

    let backend_port = up_result.project.port;
    let (ready_tx, ready_rx) = mpsc::channel();
    let backend = thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", backend_port)).unwrap();
        ready_tx.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nrouter-works",
            )
            .unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", harness.router_port)).unwrap();
    client
        .write_all(
            format!(
                "GET /probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                up_result.local_host
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.contains("router-works"));
    backend.join().unwrap();
}

#[test]
fn runtime_workflow_router_returns_502_when_backend_missing() {
    let harness = DaemonHarness::start();
    let project_dir = harness.root_dir.join("project-router-missing-backend");
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"router-missing\"\n\
path = \".\"\n",
    )
    .unwrap();

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);
    let up_result: UpResult = serde_json::from_value(up_response.result.unwrap()).unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", harness.router_port)).unwrap();
    client
        .write_all(
            format!(
                "GET /probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                up_result.local_host
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.contains("502 Bad Gateway"));
}

#[test]
fn runtime_workflow_second_start_does_not_unlink_active_socket() {
    let harness = DaemonHarness::start();
    let mut second = spawn_projd(
        &harness.socket_path,
        &harness.state_path,
        &harness.niri_config_path,
        &[(
            "PROJD_ROUTER_PORT".to_string(),
            harness.router_port.to_string(),
        )],
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match second.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = second.kill();
                let _ = second.wait();
                panic!("second daemon start did not fail within timeout");
            }
            Err(err) => panic!("failed to poll second daemon process: {err}"),
        }
    };
    assert!(
        !status.success(),
        "second daemon start unexpectedly succeeded"
    );

    let ping_response = request(&harness.socket_path, METHOD_PING, Value::Null)
        .expect("first daemon socket became unreachable after second start attempt");
    assert!(
        ping_response.ok,
        "first daemon stopped responding after second start attempt"
    );
}

fn write_executable_script(path: &Path, content: &str) {
    fs::write(path, content).expect("failed to write script");
    let mut perms = fs::metadata(path)
        .expect("missing script metadata")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("failed to set executable permissions");
}

fn wait_for_log_contains(path: &Path, expected: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if content.contains(expected) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timed out waiting for '{}' in log file {}",
        expected,
        path.display()
    );
}

fn spawn_projd(
    socket_path: &Path,
    state_path: &Path,
    niri_config_path: &Path,
    env: &[(String, String)],
) -> Child {
    if let Some(projd_bin) = detect_projd_binary() {
        return Command::new(projd_bin)
            .arg("--socket")
            .arg(socket_path)
            .arg("--state")
            .arg(state_path)
            .arg("--niri-config")
            .arg(niri_config_path)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn projd binary");
    }

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("failed to locate workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf();

    Command::new("cargo")
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("projd")
        .arg("--")
        .arg("--socket")
        .arg(socket_path)
        .arg("--state")
        .arg(state_path)
        .arg("--niri-config")
        .arg(niri_config_path)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(workspace_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn projd via cargo fallback")
}

fn detect_projd_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_projd") {
        candidates.push(PathBuf::from(path));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(debug_dir) = current_exe.parent().and_then(Path::parent) {
            candidates.push(debug_dir.join(projd_binary_name()));
        }
    }

    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(
            PathBuf::from(target_dir)
                .join("debug")
                .join(projd_binary_name()),
        );
    }

    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug")
            .join(projd_binary_name()),
    );

    candidates.into_iter().find(|path| path.is_file())
}

#[cfg(unix)]
fn projd_binary_name() -> &'static str {
    "projd"
}

#[cfg(windows)]
fn projd_binary_name() -> &'static str {
    "projd.exe"
}

fn request(socket_path: &Path, method: &str, params: Value) -> Result<Response, String> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|err| format!("failed to connect to {}: {err}", socket_path.display()))?;
    let mut writer = BufWriter::new(
        stream
            .try_clone()
            .map_err(|err| format!("failed to clone socket stream: {err}"))?,
    );
    let mut reader = BufReader::new(stream);

    let request = Request {
        id: 1,
        method: method.to_string(),
        params,
    };

    serde_json::to_writer(&mut writer, &request)
        .map_err(|err| format!("failed to serialize request: {err}"))?;
    writer
        .write_all(b"\n")
        .map_err(|err| format!("failed to write request newline: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("failed to flush request: {err}"))?;

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| format!("failed to read daemon response: {err}"))?;
    if line.trim().is_empty() {
        return Err("daemon returned empty response".to_string());
    }

    serde_json::from_str::<Response>(&line)
        .map_err(|err| format!("failed to parse daemon response JSON: {err}"))
}

fn allocate_router_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("failed to allocate router port");
    listener.local_addr().unwrap().port()
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("projd-it-{label}-{nanos}"))
}
