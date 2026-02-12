use projd_types::{
    DownParams, ListResult, NameParams, ProjectLifecycleState, Request, Response, StatusParams,
    StatusResult, UpParams, UpResult, METHOD_DOWN, METHOD_LIST, METHOD_PEEK, METHOD_PING,
    METHOD_SHUTDOWN, METHOD_STATUS, METHOD_SUSPEND, METHOD_UP, NIRI_MANAGED_END,
    NIRI_MANAGED_START,
};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct DaemonHarness {
    child: Child,
    root_dir: PathBuf,
    socket_path: PathBuf,
    state_path: PathBuf,
    niri_config_path: PathBuf,
}

impl DaemonHarness {
    fn start(initial_niri_config: &str) -> Self {
        let root_dir = unique_temp_dir("niri-workflow");
        let socket_path = root_dir.join("projd.sock");
        let state_path = root_dir.join("state.json");
        let niri_config_path = root_dir.join("niri").join("config.kdl");
        let router_port = allocate_router_port();

        fs::create_dir_all(niri_config_path.parent().expect("niri config parent path"))
            .expect("failed to create niri config directory");
        fs::write(&niri_config_path, initial_niri_config).expect("failed to seed niri config");

        let child = spawn_projd(&socket_path, &state_path, &niri_config_path, router_port);

        let harness = Self {
            child,
            root_dir,
            socket_path,
            state_path,
            niri_config_path,
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

    fn create_project_dir(&self, name: &str) -> PathBuf {
        let project_dir = self.root_dir.join(format!("project-{name}"));
        fs::create_dir_all(&project_dir).expect("failed to create project directory");
        let toml = format!("name = \"{name}\"\npath = \".\"\n");
        fs::write(project_dir.join(".project.toml"), toml).expect("failed to write .project.toml");
        project_dir
    }
}

fn spawn_projd(
    socket_path: &Path,
    state_path: &Path,
    niri_config_path: &Path,
    router_port: u16,
) -> Child {
    if let Some(projd_bin) = detect_projd_binary() {
        return Command::new(projd_bin)
            .arg("--socket")
            .arg(socket_path)
            .arg("--state")
            .arg(state_path)
            .arg("--niri-config")
            .arg(niri_config_path)
            .env("PROJD_ROUTER_PORT", router_port.to_string())
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
        .env("PROJD_ROUTER_PORT", router_port.to_string())
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
fn niri_workflow_up_down_round_trip_updates_managed_section() {
    let harness = DaemonHarness::start("input {\n  keyboard {}\n}\n\nworkspace \"personal\"\n");
    let project_dir = harness.create_project_dir("frontend");

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
        })
        .expect("failed to serialize up params"),
    )
    .expect("up request failed");
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let up_result: UpResult =
        serde_json::from_value(up_response.result.expect("missing up result")).unwrap();
    assert!(up_result.created);
    assert_eq!(up_result.project.name, "frontend");
    assert_eq!(up_result.project.workspace, "frontend");
    assert_eq!(up_result.project.port, 3001);
    assert_eq!(up_result.local_host, "frontend.localhost");
    assert!(up_result
        .local_origin
        .starts_with("http://frontend.localhost:"));

    let status_response = request(
        &harness.socket_path,
        METHOD_STATUS,
        serde_json::to_value(StatusParams { name: None }).expect("failed to serialize status"),
    )
    .expect("status request failed");
    assert!(status_response.ok);
    let status_result: StatusResult =
        serde_json::from_value(status_response.result.expect("missing status result")).unwrap();
    assert_eq!(status_result.projects.len(), 1);
    assert_eq!(
        status_result.projects[0].state,
        ProjectLifecycleState::Active
    );
    assert!(status_result.projects[0].focused);

    let niri_after_up =
        fs::read_to_string(&harness.niri_config_path).expect("failed to read niri config");
    assert!(niri_after_up.contains("workspace \"personal\""));
    assert!(niri_after_up.contains(NIRI_MANAGED_START));
    assert!(niri_after_up.contains(NIRI_MANAGED_END));
    assert!(niri_after_up.contains("workspace \"frontend\""));
    assert!(niri_after_up.contains("open-on-workspace \"frontend\""));
    assert!(niri_after_up.contains(r#"match title="^\\[proj:frontend\\]$""#));

    let down_response = request(
        &harness.socket_path,
        METHOD_DOWN,
        serde_json::to_value(DownParams {
            name: "frontend".to_string(),
        })
        .expect("failed to serialize down params"),
    )
    .expect("down request failed");
    assert!(down_response.ok, "down failed: {:?}", down_response.error);

    let niri_after_down =
        fs::read_to_string(&harness.niri_config_path).expect("failed to read niri config");
    assert!(niri_after_down.contains("workspace \"personal\""));
    assert!(niri_after_down.contains(NIRI_MANAGED_START));
    assert!(niri_after_down.contains(NIRI_MANAGED_END));
    assert!(!niri_after_down.contains(r#"match title="^\\[proj:frontend\\]$""#));
    assert!(!niri_after_down.contains("open-on-workspace \"frontend\""));

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert!(listed.projects.is_empty());
}

#[test]
fn niri_workflow_rejects_partial_markers_without_registering_project() {
    let partial_markers = format!(
        "{start}\nstale managed content\n",
        start = NIRI_MANAGED_START
    );
    let harness = DaemonHarness::start(&partial_markers);
    let project_dir = harness.create_project_dir("broken");

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
        })
        .expect("failed to serialize up params"),
    )
    .expect("up request failed");
    assert!(!up_response.ok, "up unexpectedly succeeded");
    assert!(up_response
        .error
        .unwrap_or_default()
        .contains("found only one projd managed marker"));

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert!(listed.projects.is_empty());

    assert!(!harness.state_path.exists());

    let niri_after_failed_up =
        fs::read_to_string(&harness.niri_config_path).expect("failed to read niri config");
    assert_eq!(niri_after_failed_up, partial_markers);
}

#[test]
fn niri_workflow_suspend_transitions_project_state() {
    let harness = DaemonHarness::start("");
    let project_dir = harness.create_project_dir("suspend-demo");

    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
        })
        .expect("failed to serialize up params"),
    )
    .expect("up request failed");
    assert!(up_response.ok);

    let suspend_response = request(
        &harness.socket_path,
        METHOD_SUSPEND,
        serde_json::to_value(NameParams {
            name: "suspend-demo".to_string(),
        })
        .expect("failed to serialize suspend params"),
    )
    .expect("suspend request failed");
    assert!(suspend_response.ok);

    let peek_response = request(
        &harness.socket_path,
        METHOD_PEEK,
        serde_json::to_value(NameParams {
            name: "suspend-demo".to_string(),
        })
        .expect("failed to serialize peek params"),
    )
    .expect("peek request failed");
    assert!(peek_response.ok);
    let suspended =
        serde_json::from_value::<projd_types::ProjectStatus>(peek_response.result.unwrap())
            .unwrap();
    assert_eq!(suspended.state, ProjectLifecycleState::Suspended);
    assert!(!suspended.focused);
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
