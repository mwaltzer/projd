use projd_types::{
    DownParams, FocusResult, ListResult, NameParams, ProjectLifecycleState, Request, Response,
    StatusParams, StatusResult, UpParams, UpResult, METHOD_DOWN, METHOD_FOCUS, METHOD_LIST,
    METHOD_PEEK, METHOD_PING, METHOD_SHUTDOWN, METHOD_STATUS, METHOD_SUSPEND, METHOD_UNREGISTER,
    METHOD_UP, NIRI_MANAGED_END, NIRI_MANAGED_START,
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
        Self::start_with_env(initial_niri_config, &[])
    }

    fn start_with_env(initial_niri_config: &str, env: &[(String, String)]) -> Self {
        let root_dir = unique_temp_dir("niri-workflow");
        let socket_path = root_dir.join("projd.sock");
        let state_path = root_dir.join("state.json");
        let niri_config_path = root_dir.join("niri").join("config.kdl");
        let router_port = allocate_router_port();

        fs::create_dir_all(niri_config_path.parent().expect("niri config parent path"))
            .expect("failed to create niri config directory");
        fs::write(&niri_config_path, initial_niri_config).expect("failed to seed niri config");

        let mut daemon_env = env.to_vec();
        daemon_env.push(("PROJD_ROUTER_PORT".to_string(), router_port.to_string()));
        let child = spawn_projd(&socket_path, &state_path, &niri_config_path, &daemon_env);

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
            workspace: None,
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

    // After down, project is stopped but still registered — niri config skips stopped projects
    let niri_after_down =
        fs::read_to_string(&harness.niri_config_path).expect("failed to read niri config");
    assert!(niri_after_down.contains("workspace \"personal\""));
    assert!(niri_after_down.contains(NIRI_MANAGED_START));
    assert!(niri_after_down.contains(NIRI_MANAGED_END));
    assert!(!niri_after_down.contains("workspace \"frontend\""));
    assert!(!niri_after_down.contains(r#"match title="^\\[proj:frontend\\]$""#));

    let status_after_down = request(
        &harness.socket_path,
        METHOD_STATUS,
        serde_json::to_value(StatusParams { name: None }).expect("failed to serialize status"),
    )
    .expect("status request failed");
    assert!(status_after_down.ok);
    let status_result_down: StatusResult =
        serde_json::from_value(status_after_down.result.expect("missing status result")).unwrap();
    assert_eq!(status_result_down.projects.len(), 1);
    assert_eq!(
        status_result_down.projects[0].state,
        ProjectLifecycleState::Stopped
    );

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    assert_eq!(listed.projects.len(), 1);

    // Unregister fully removes the project
    let unregister_response = request(
        &harness.socket_path,
        METHOD_UNREGISTER,
        serde_json::to_value(DownParams {
            name: "frontend".to_string(),
        })
        .expect("failed to serialize unregister params"),
    )
    .expect("unregister request failed");
    assert!(
        unregister_response.ok,
        "unregister failed: {:?}",
        unregister_response.error
    );

    let niri_after_unregister =
        fs::read_to_string(&harness.niri_config_path).expect("failed to read niri config");
    assert!(niri_after_unregister.contains("workspace \"personal\""));
    assert!(!niri_after_unregister.contains(r#"match title="^\\[proj:frontend\\]$""#));
    assert!(!niri_after_unregister.contains("open-on-workspace \"frontend\""));

    let list_after_unregister =
        request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_after_unregister.ok);
    let listed_after: ListResult =
        serde_json::from_value(list_after_unregister.result.unwrap()).unwrap();
    assert!(listed_after.projects.is_empty());
}

#[test]
fn niri_workflow_up_uses_workspace_from_project_config() {
    let harness = DaemonHarness::start("");
    let project_dir = harness.create_project_dir("workspace-config");
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"workspace-config\"\npath = \".\"\nworkspace = \"5\"\n",
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
    .unwrap();
    assert!(up_response.ok, "up failed: {:?}", up_response.error);
    let up_result: UpResult = serde_json::from_value(up_response.result.unwrap()).unwrap();
    assert_eq!(up_result.project.workspace, "5");
}

#[test]
fn niri_workflow_up_workspace_override_wins_and_updates_existing_registration() {
    let harness = DaemonHarness::start("");
    let project_dir = harness.create_project_dir("workspace-override");
    fs::write(
        project_dir.join(".project.toml"),
        "name = \"workspace-override\"\npath = \".\"\nworkspace = \"5\"\n",
    )
    .unwrap();

    let first_up = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: Some("7".to_string()),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(first_up.ok, "first up failed: {:?}", first_up.error);
    let first_result: UpResult = serde_json::from_value(first_up.result.unwrap()).unwrap();
    assert_eq!(first_result.project.workspace, "7");
    assert!(first_result.created);

    let second_up = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: Some("9".to_string()),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(second_up.ok, "second up failed: {:?}", second_up.error);
    let second_result: UpResult = serde_json::from_value(second_up.result.unwrap()).unwrap();
    assert_eq!(second_result.project.workspace, "9");
    assert!(!second_result.created);

    let list_response = request(&harness.socket_path, METHOD_LIST, Value::Null).unwrap();
    assert!(list_response.ok);
    let listed: ListResult = serde_json::from_value(list_response.result.unwrap()).unwrap();
    let project = listed
        .projects
        .iter()
        .find(|project| project.name == "workspace-override")
        .expect("missing workspace-override project");
    assert_eq!(project.workspace, "9");
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
            workspace: None,
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
            workspace: None,
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

#[test]
fn niri_workflow_focus_returns_success_details() {
    let root = unique_temp_dir("niri-focus-success");
    fs::create_dir_all(&root).unwrap();
    let niri_script = root.join("niri-ok.sh");
    let niri_log = root.join("niri.log");
    fs::write(
        &niri_script,
        format!(
            "#!/usr/bin/env sh\n\
echo \"$*\" >> \"{}\"\n\
if [ \"$1\" = \"msg\" ] && [ \"$2\" = \"--json\" ] && [ \"$3\" = \"focused-workspace\" ]; then\n\
  echo '{{\"name\":\"focus-demo\"}}'\n\
fi\n\
if [ \"$1\" = \"msg\" ] && [ \"$2\" = \"--json\" ] && [ \"$3\" = \"workspaces\" ]; then\n\
  echo '[{{\"id\":42,\"name\":\"focus-demo\",\"active_window_id\":7}}]'\n\
fi\n\
if [ \"$1\" = \"msg\" ] && [ \"$2\" = \"--json\" ] && [ \"$3\" = \"windows\" ]; then\n\
  echo '[{{\"id\":7,\"workspace_id\":42}}]'\n\
fi\n\
exit 0\n",
            niri_log.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&niri_script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&niri_script, perms).unwrap();
    }

    let harness = DaemonHarness::start_with_env(
        "",
        &[(
            "PROJD_NIRI_BIN".to_string(),
            niri_script.display().to_string(),
        )],
    );
    let project_dir = harness.create_project_dir("focus-demo");
    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let focus_response = request(
        &harness.socket_path,
        METHOD_FOCUS,
        serde_json::to_value(NameParams {
            name: "focus-demo".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(
        focus_response.ok,
        "focus failed: {:?}",
        focus_response.error
    );
    let result: FocusResult = serde_json::from_value(focus_response.result.unwrap()).unwrap();
    assert!(result.workspace_focused);
    assert!(result.windows_surfaced);
    assert_eq!(result.status.project.name, "focus-demo");
    assert!(result.warnings.is_empty());

    let calls = fs::read_to_string(niri_log).unwrap();
    assert!(calls.contains("msg action focus-workspace focus-demo"));
    assert!(calls.contains("msg action focus-window --id 7"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn niri_workflow_focus_returns_warnings_when_niri_is_unavailable() {
    let harness = DaemonHarness::start_with_env(
        "",
        &[(
            "PROJD_NIRI_BIN".to_string(),
            "command-that-does-not-exist".to_string(),
        )],
    );
    let project_dir = harness.create_project_dir("focus-warn");
    let up_response = request(
        &harness.socket_path,
        METHOD_UP,
        serde_json::to_value(UpParams {
            path: project_dir.to_string_lossy().to_string(),
            workspace: None,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(up_response.ok, "up failed: {:?}", up_response.error);

    let focus_response = request(
        &harness.socket_path,
        METHOD_FOCUS,
        serde_json::to_value(NameParams {
            name: "focus-warn".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(
        focus_response.ok,
        "focus failed: {:?}",
        focus_response.error
    );
    let result: FocusResult = serde_json::from_value(focus_response.result.unwrap()).unwrap();
    assert!(!result.workspace_focused);
    assert!(!result.windows_surfaced);
    assert_eq!(result.status.project.name, "focus-warn");
    assert!(!result.warnings.is_empty());
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
