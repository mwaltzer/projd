# projd

`projd` is a project-first environment manager for the Niri compositor.

- `projd`: daemon
- `proj`: CLI client
- `projd-types`: shared IPC/types crate

## Getting started

```bash
mise run bootstrap
mise run build-link
mise run daemon-start
mise run ping
proj --help
```

`proj ping` autostarts `projd` if it is not running.
`mise run bootstrap` also installs `proj`/`projd` into `~/.cargo/bin`.

## First project onboarding

One-line setup from a new project root:

```bash
proj up
```

If `.project.toml` is missing, `proj up` now creates it automatically, starts `projd` if needed, and registers the project.
On Niri, `proj up` also attempts to reload Niri config and focus the project's workspace.
If Niri IPC is unavailable, `proj up` still succeeds and prints warnings.

Then verify current state:

```bash
proj status
proj list
```

Lifecycle controls:

```bash
proj switch <name>
proj suspend <name>
proj resume <name>
```

`proj up <name>` also works from any directory by resolving in this order:
1. Existing registered project name in `projd`
2. Local roots (`$PROJ_PROJECT_ROOTS`, colon-separated)
3. Default root `~/Code/<name>`

Niri config updates are scoped to:
`// === PROJD MANAGED START (do not edit) ===`
`// === PROJD MANAGED END ===`
Everything outside those markers is left untouched.

## Project config

Each project is configured with `.project.toml` in the project root.

Example:

```toml
name = "frontend"
path = "."

[server]
command = "npm run dev"
port_env = "PORT"
cwd = "."

[browser]
command = "helium"
urls = ["${PROJ_ORIGIN}"]
# optional; defaults to true
isolate_profile = true
```

`browser.command` is optional and project-local. If omitted, browser launch falls back to:
1. `PROJD_BROWSER_CMD`
2. `BROWSER`
3. platform default (`xdg-open` on Linux, `open` on macOS)

When `browser.isolate_profile = true` (default), `projd` auto-adds per-project isolation flags for common browser families (Chromium-like and Firefox-like) so `proj up` opens a fresh window tied to that project workspace. Set `isolate_profile = false` to keep raw browser command behavior.

Runtime env/template variables:
- `${PORT}`: project backend port (3001+ allocation)
- `${PROJ_NAME}`: project name
- `${PROJ_HOST}`: project hostname (`<project>.localhost`)
- `${PROJ_ORIGIN}`/`${PROJ_URL}`: project origin (`http://<project>.localhost:<router-port>`)
- `${PROJ_ROUTER_PORT}`: router listen port

`projd` runs a local host router and maps `Host: <project>.localhost` to the project backend port. Router port defaults to `48080` and can be overridden with `PROJD_ROUTER_PORT` (or `projd --router-port <port>`).

## Core commands

```bash
proj init
proj up [path|name]
proj down <name>
proj switch <name>
proj suspend <name>
proj resume <name>
proj peek <name>
proj status [name]
proj logs <name> [process]
proj list
proj ping
proj daemon start
proj daemon stop
proj daemon status
proj-tui
```

## Current scope

Implemented:
- Daemon IPC and autostart flow
- Registry + persistence at `~/.local/share/projd/state.json`
- Niri managed marker updates in `~/.config/niri/config.kdl`
- Niri workspace focus workflow via `proj switch`/`proj resume`
- Runtime state view via `proj peek` and `proj status`
- Persisted focus/suspend lifecycle state across daemon restarts
- Runtime process orchestration for `server`, `agents`, `terminals`, `editor`, and `browser` launch commands
- Per-process log capture and retrieval via `proj logs`
- Dependency startup for `depends_on` (path dependencies, plus already-registered name dependencies)
- Browser launch gating with `server.ready_pattern`
- Machine-readable status output via `proj status --json` (for Quickshell/Waybar integrations)
- Interactive terminal dashboard via `proj-tui`

Not implemented yet:
- Automatic discovery of non-registered name dependencies in `depends_on`
- Niri event-stream driven state reconciliation

## Development

For contributor/automation workflow details, see `AGENTS.md`.

Run the Niri workflow integration test with:

```bash
mise run test-integration
```

Run the terminal dashboard with:

```bash
mise run tui
```

## Full Suite Demo

A runnable end-to-end demo lives at `examples/full-suite`:

```bash
cd ~/Code/projd/examples/full-suite/app-suite
proj up
```

This starts:
- path dependency startup (`dep-service`)
- app server with `ready_pattern`
- agent process
- terminal process
- editor command
- browser URL launches

## Quickshell Integration

Use `proj status --json` as the polling source and call `proj switch <name>` for actions.

Example polling command:

```bash
proj status --json
```

This returns compact JSON shaped like:

```json
{"projects":[{"project":{"name":"frontend","path":"/home/me/Code/frontend","workspace":"frontend","port":3001},"state":"active","focused":true}]}
```
