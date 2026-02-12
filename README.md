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
urls = ["http://localhost:${PORT}"]
```

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

Not implemented yet:
- Automatic discovery of non-registered name dependencies in `depends_on`
- Niri event-stream driven state reconciliation

## Development

For contributor/automation workflow details, see `AGENTS.md`.

Run the Niri workflow integration test with:

```bash
mise run test-integration
```
