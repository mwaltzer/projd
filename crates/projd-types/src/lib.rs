pub mod client;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::path::PathBuf;

pub const METHOD_PING: &str = "ping";
pub const METHOD_SHUTDOWN: &str = "shutdown";
pub const METHOD_UP: &str = "up";
pub const METHOD_DOWN: &str = "down";
pub const METHOD_LIST: &str = "list";
pub const METHOD_SWITCH: &str = "switch";
pub const METHOD_FOCUS: &str = "focus";
pub const METHOD_SUSPEND: &str = "suspend";
pub const METHOD_RESUME: &str = "resume";
pub const METHOD_PEEK: &str = "peek";
pub const METHOD_STATUS: &str = "status";
pub const METHOD_LOGS: &str = "logs";
pub const METHOD_READ_CONFIG: &str = "read_config";
pub const METHOD_WRITE_CONFIG: &str = "write_config";
pub const METHOD_INIT_CONFIG: &str = "init_config";
pub const METHOD_REGISTER: &str = "register";
pub const METHOD_UNREGISTER: &str = "unregister";
pub const METHOD_BROWSE: &str = "browse";
pub const METHOD_WRITE_INIT_CONFIG: &str = "write_init_config";

pub const DEFAULT_ROUTER_PORT: u16 = 48080;

pub const NIRI_MANAGED_START: &str = "// === PROJD MANAGED START (do not edit) ===";
pub const NIRI_MANAGED_END: &str = "// === PROJD MANAGED END ===";
pub const NIRI_INTEGRATION_START: &str = "// === PROJD NIRI INTEGRATION START (do not edit) ===";
pub const NIRI_INTEGRATION_END: &str = "// === PROJD NIRI INTEGRATION END ===";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    #[must_use]
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpParams {
    pub path: String,
    #[serde(default)]
    pub workspace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusParams {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsParams {
    pub name: String,
    #[serde(default)]
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub name: String,
    pub path: String,
    pub workspace: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpResult {
    pub project: ProjectRecord,
    pub created: bool,
    #[serde(default)]
    pub local_host: String,
    #[serde(default)]
    pub local_origin: String,
    #[serde(default)]
    pub started_processes: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResult {
    pub projects: Vec<ProjectRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProjectLifecycleState {
    Active,
    Backgrounded,
    Suspended,
    Stopped,
}

impl ProjectLifecycleState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Backgrounded => "backgrounded",
            Self::Suspended => "suspended",
            Self::Stopped => "stopped",
        }
    }
}

impl std::fmt::Display for ProjectLifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatus {
    pub project: ProjectRecord,
    pub state: ProjectLifecycleState,
    pub focused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusResult {
    pub status: ProjectStatus,
    pub workspace_focused: bool,
    pub windows_surfaced: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub projects: Vec<ProjectStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLogs {
    pub process: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsResult {
    pub project: String,
    pub logs: Vec<ProcessLogs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadConfigParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadConfigResult {
    pub name: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteConfigParams {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteConfigResult {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfigParams {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfigResult {
    pub path: String,
    pub content: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteInitConfigParams {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteInitConfigResult {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResult {
    pub project: ProjectRecord,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseParams {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseEntry {
    pub name: String,
    pub path: String,
    pub has_project_toml: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseResult {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<BrowseEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub projects: Vec<ProjectRecord>,
    #[serde(default)]
    pub focused_project: Option<String>,
    #[serde(default)]
    pub suspended_projects: Vec<String>,
    #[serde(default)]
    pub stopped_projects: Vec<String>,
}

#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("projd.sock");
    }

    default_data_dir().join("projd.sock")
}

#[must_use]
pub fn default_data_dir() -> PathBuf {
    if let Some(data_dir) = dirs::data_local_dir() {
        return data_dir.join("projd");
    }

    PathBuf::from(".projd")
}

#[must_use]
pub fn default_state_path() -> PathBuf {
    default_data_dir().join("state.json")
}

#[must_use]
pub fn default_niri_config_path() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        return config_dir.join("niri").join("config.kdl");
    }

    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("niri")
            .join("config.kdl");
    }

    PathBuf::from(".config/niri/config.kdl")
}
