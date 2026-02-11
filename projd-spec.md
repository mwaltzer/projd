# projd Specification

## 1. Product Summary

`projd` is a project-first environment manager for the Niri compositor. It lets a developer run one command per project and get an isolated workspace with the expected tools: terminal, editor, browser, agents, and dev server.

The system has two binaries:
- `projd`: long-running daemon for orchestration and state.
- `proj`: CLI client for user commands.

Core value:
- Fast context switching across projects.
- Reliable workspace isolation.
- Zero manual port and window management.

## 2. Problem Statement

Developers running multiple projects in parallel lose time to:
- Repetitive startup sequences.
- Port collisions.
- Mixed browser sessions.
- Window sprawl across workspaces.
- Lack of project-scoped process lifecycle controls.

`projd` solves this by treating each project as a first-class runtime unit.

## 3. Goals and Non-Goals

### Goals
- Start, stop, suspend, and resume project environments with deterministic behavior.
- Route spawned windows to project-specific Niri workspaces.
- Auto-allocate and persist per-project ports.
- Track process state and expose it via CLI and Waybar.
- Preserve user-owned Niri config outside daemon-managed markers.

### Non-Goals
- General container orchestration.
- Language-specific build tooling.
- Cross-compositor support in v1 (Niri only).
- Full process sandboxing/security isolation.

## 4. Primary User Flows

1. Developer runs `proj up` in a repo.
2. Daemon resolves `.project.toml`, allocates resources, creates/updates Niri workspace rules, and starts configured processes.
3. User switches between projects using `proj switch <name>` or Waybar.
4. User inspects state with `proj status`, `proj list`, `proj peek`, `proj logs`.
5. User cleans up with `proj down <name>` or shuts down daemon.

## 5. Functional Requirements

### 5.1 Project Configuration
- Each project is configured by `.project.toml` in project root.
- `name` must be unique across registered projects.
- Project path is normalized to an absolute path at registration time.

### 5.2 Registry and Persistence
- Daemon keeps an in-memory registry of projects and process metadata.
- Registry is persisted to `~/.local/share/projd/state.json`.
- On daemon restart, state is restored and stale resources are reconciled.

### 5.3 Workspace Provisioning
- Each project maps to one Niri workspace named by project `name`.
- Daemon manages a marked section in Niri `config.kdl`.
- Managed section contains workspace declarations and window rules.
- Any content outside markers is never modified.

### 5.4 Window Routing
- Spawned windows must include tag: `[proj:<name>]` in title when possible.
- Window rules route tagged windows to workspace `<name>`.
- Apps that do not support title injection (for example some editor/browser modes) use fallback match strategy (app-id/title/profile).

### 5.5 Port Allocation
- Default allocatable range: `3001..3999`.
- Each active project may hold one primary allocated port.
- Daemon injects this value into configured env var (default: `PORT` or `server.port_env`).
- Port allocations persist across daemon restarts until project shutdown.

### 5.6 Process Orchestration
- Supported process classes:
  - `server` (single command with optional readiness detection).
  - `agents` (one or more commands).
  - `terminals` (interactive shell windows with optional startup commands).
  - `editor` (single editor launch configuration).
  - `browser` (one or more URLs, optionally interpolated with `${PORT}`).
- All child processes are tracked with PID and logical process name.
- `proj down` sends `SIGTERM`, waits grace period, then `SIGKILL`.

### 5.7 Readiness and Sequencing
- If `server.ready_pattern` is set, browser launches wait until pattern is observed in server output.
- `depends_on` projects are started before dependent project.
- Startup errors are surfaced with actionable messages.

### 5.8 Lifecycle States
Project state machine:
- `Stopped`
- `Starting`
- `Active`
- `Backgrounded`
- `Suspended`
- `Error`

Allowed transitions:
- `Stopped -> Starting -> Active`
- `Active <-> Backgrounded`
- `Active -> Suspended -> Active`
- `* -> Error` on unrecoverable failure
- `Active|Backgrounded|Suspended|Error -> Stopped`

### 5.9 Status, Logs, and Notifications
- `proj status` returns project details: state, workspace, port, processes.
- `proj logs <name> [process]` streams stdout/stderr from daemon-captured logs.
- Agent completion and server-ready events can trigger desktop notifications.
- Optional Waybar module shows summarized project state and supports click-to-switch.

## 6. `.project.toml` Schema

### 6.1 Required Keys
- `name`: string, unique identifier.
- `path`: absolute or tilde path resolved on registration.

### 6.2 Optional Keys
- `server`: object
  - `command`: string
  - `port_env`: string
  - `ready_pattern`: string (regex)
  - `cwd`: relative path
- `agents`: array of objects `{ name, command, cwd? }`
- `terminals`: array of objects `{ name, command?, cwd? }`
- `editor`: object `{ command, args?, workspace? }`
- `browser`: object `{ urls[], profile? }`
- `color`: enum `blue|red|amber|green|purple|pink|cyan|lime`
- `depends_on`: array of project paths or project names
- `output` (future): target display/output hint for multi-monitor setups

### 6.3 Example

```toml
name = "frontend"
path = "~/code/frontend"

[server]
command = "npm run dev"
port_env = "PORT"
ready_pattern = "ready on"
cwd = "."

[[agents]]
name = "claude"
command = "claude --project ."
cwd = "."

[[terminals]]
name = "git"

[editor]
command = "code"
args = ["."]

[browser]
urls = ["http://localhost:${PORT}", "https://github.com/org/frontend"]
profile = "frontend-dev"

color = "blue"
depends_on = ["~/code/api-backend"]
```

## 7. CLI Contract

Commands:

```text
proj init
proj up [path]
proj down <name>
proj switch <name>
proj list
proj status [name]
proj peek <name>
proj logs <name> [process]
proj suspend <name>
proj resume <name>
proj port <name>
proj config <name>
proj daemon start
proj daemon stop
proj daemon status
```

Behavior rules:
- All mutating commands return non-zero on failure.
- Error text should identify project name, failing subsystem, and suggested fix.
- `proj up` defaults to current working directory when no path is provided.

## 8. Daemon Architecture

Core modules:
- IPC server over Unix socket (`$XDG_RUNTIME_DIR/projd.sock` preferred, fallback to data dir).
- Registry and persistence.
- Port allocator.
- Niri config fragment generator and writer.
- Niri IPC client (focus workspace, query windows/workspaces, subscribe events).
- Process spawner and supervisor.
- Log sink and notification bridge.
- Waybar status endpoint.

Communication paths:
- CLI to daemon via JSON request/response over Unix socket.
- Daemon to Niri via config file update and Niri IPC socket.
- Daemon to child processes via spawn/kill/signal and env injection.

## 9. File System Layout

```text
~/.config/niri/config.kdl
~/.config/projd/config.toml
~/.local/share/projd/
  projd.sock
  projd.log
  state.json
  logs/
    <project>/
      <process>.log

<project-root>/.project.toml
```

## 10. Niri Config Management

Managed section markers:

```text
// === PROJD MANAGED START (do not edit) ===
...generated content...
// === PROJD MANAGED END ===
```

Requirements:
- Marker region is fully replaced on each regeneration.
- Missing markers are inserted safely.
- Malformed user config results in explicit error and no destructive overwrite.

## 11. Reliability, Safety, and Recovery

- Detect and reconcile stale sockets on startup.
- Detect stale port allocations and reclaim unavailable entries.
- Offer orphan-process cleanup after daemon crash.
- Graceful shutdown sequence persists state, signals children, closes socket.
- Optional restart policies for selected process types.

## 12. Observability

- Structured logs with project name, command, PID, and subsystem tags.
- Per-project process logs persisted to data directory.
- `proj status` and `proj peek` derive from live registry, not only persisted state.

## 13. Security Considerations

- Daemon executes user-provided commands from `.project.toml`; no privilege escalation is performed.
- Socket permissions should restrict access to local user by default.
- Path normalization and validation must prevent accidental cross-project collisions.

## 14. Performance Targets

- `proj up` command response: immediate acknowledgement (<200 ms) after request accepted.
- Typical single-project startup orchestration overhead: <2 seconds excluding app boot time.
- Registry operations are O(1) average lookup by project name.

## 15. Delivery Plan

### Phase 0: Foundation
- Rust workspace with `projd`, `proj`, and shared types crate.
- IPC ping/pong.
- Daemon autostart from CLI.

Exit criteria:
- `proj ping` works without manual daemon startup.

### Phase 1: Registry and Niri Config
- Parse `.project.toml`.
- Implement registry, persistence, port allocator.
- Generate and write Niri managed fragment.
- Implement `proj init`, `proj up` (config-only), `proj down`, `proj list`.

Exit criteria:
- Workspaces appear/disappear correctly in Niri via CLI commands.

### Phase 2: Process Runtime
- Spawn server, terminals, agents, editor, browser.
- Inject env vars and track PIDs.
- Implement kill lifecycle and crash detection.
- Implement dependency startup ordering.

Exit criteria:
- `proj up` starts full environment and `proj down` fully cleans up.

### Phase 3: Runtime Integration
- Niri IPC commands and event stream support.
- Implement `proj switch`, `proj suspend`, `proj resume`, `proj peek`.
- Maintain accurate active/backgrounded state.

Exit criteria:
- Switching and state reporting are accurate under repeated use.

### Phase 4: UX and Visibility
- Agent/server notifications.
- Waybar status output and click actions.
- `proj logs` streaming command.

Exit criteria:
- User can monitor and switch projects without manually searching windows.

### Phase 5: Hardening
- Browser profile isolation.
- Hot reload for `.project.toml`.
- Multi-monitor output pinning.
- Edge-case errors and cleanup improvements.

Exit criteria:
- Stable daily-driver operation with no frequent manual recovery.

## 16. Acceptance Checklist

A release candidate is acceptable when all are true:
- `proj init` creates valid starter config.
- `proj up` creates workspace, allocates port, launches configured processes.
- Browser URL interpolation with `${PORT}` works.
- `proj switch` focuses expected workspace.
- `proj status` shows accurate process and state data.
- `proj down` stops processes and frees port.
- Daemon restart restores state without corruption.
- Niri config outside managed markers remains unchanged.
- At least one failure-path test exists for each subsystem (IPC, config parse, spawn, port, Niri write).
