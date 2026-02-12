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
pub const METHOD_SUSPEND: &str = "suspend";
pub const METHOD_RESUME: &str = "resume";
pub const METHOD_PEEK: &str = "peek";
pub const METHOD_STATUS: &str = "status";
pub const METHOD_LOGS: &str = "logs";

pub const NIRI_MANAGED_START: &str = "// === PROJD MANAGED START (do not edit) ===";
pub const NIRI_MANAGED_END: &str = "// === PROJD MANAGED END ===";

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatus {
    pub project: ProjectRecord,
    pub state: ProjectLifecycleState,
    pub focused: bool,
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
pub struct PersistedState {
    pub projects: Vec<ProjectRecord>,
    #[serde(default)]
    pub focused_project: Option<String>,
    #[serde(default)]
    pub suspended_projects: Vec<String>,
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("projd.sock");
    }

    default_data_dir().join("projd.sock")
}

pub fn default_data_dir() -> PathBuf {
    if let Some(data_dir) = dirs::data_local_dir() {
        return data_dir.join("projd");
    }

    PathBuf::from(".projd")
}

pub fn default_state_path() -> PathBuf {
    default_data_dir().join("state.json")
}

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
