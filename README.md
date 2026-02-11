# projd

Rust workspace for:

- `projd`: daemon
- `proj`: CLI client
- `projd-types`: shared IPC types and socket path conventions

## Quick start

```bash
mise run bootstrap
mise run build
mise run ping
```

`proj ping` autostarts `projd` if it is not running.

## Build modes

- `mise run build` / `mise run test` use `cargo check` (no final linker step), which is reliable in restricted Codex sandboxes.
- `mise run build-link` / `mise run test-run` perform full build/test and require a complete host toolchain.
- Fresh environments may require one online `mise run bootstrap` first (or running inside network-enabled DevPod) so toolchains/crates can be installed.

Practical workflow:

1. In Codex/sandbox: `mise run build` and `mise run test`.
2. In host/DevPod CI-like runs: `mise run build-link` and `mise run test-run`.
3. In fresh environments: run one online bootstrap/install first.

## DevPod

This repo includes `.devcontainer/devcontainer.json`, so DevPod/devcontainer startup runs `./scripts/bootstrap-mise.sh` automatically.

## Current baseline

Phase 0 plus core Phase 1 command flow is implemented:

- Unix socket daemon (`$XDG_RUNTIME_DIR/projd.sock` preferred; fallback under local data dir)
- JSON line request/response protocol
- Methods: `ping`, `shutdown`, `up`, `down`, `list`
- CLI commands:
  - `proj init`
  - `proj up [path]`
  - `proj down <name>`
  - `proj list`
  - `proj ping`
  - `proj daemon start|stop|status`
- Project config: `.project.toml`
- Registry persistence at `~/.local/share/projd/state.json`
- Niri managed marker section updates in `~/.config/niri/config.kdl`
