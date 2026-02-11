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
```

`proj ping` autostarts `projd` if it is not running.

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
urls = ["http://localhost:${PORT}"]
```

## Core commands

```bash
proj init
proj up [path]
proj down <name>
proj list
proj ping
proj daemon start
proj daemon stop
proj daemon status
```

## Current scope

Implemented:
- Daemon IPC and autostart flow
- Registry + persistence at `~/.local/share/projd/state.json`
- Niri managed marker updates in `~/.config/niri/config.kdl`

Not implemented yet:
- Full process runtime orchestration (server/editor/browser/agents lifecycle)
- Niri IPC-driven workspace focus/state transitions

## Development

For contributor/automation workflow details, see `AGENTS.md`.
