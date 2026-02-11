# Agents: projd

This repo is Rust-first. Do not replace missing toolchains with alternate language implementations.

## Startup

Use mise task entrypoints first:

```bash
mise run bootstrap
mise run build
mise run test
```

In DevPod/devcontainer, bootstrap runs automatically via `postCreateCommand`.

`build`/`test` are compile-check tasks for sandbox reliability. Use `mise run build-link` and `mise run test-run` for full linker/runtime validation.
For fresh environments, do one online `mise run bootstrap` first (or use network-enabled DevPod) before running build/test tasks.

## Runtime commands

```bash
mise run daemon
mise run daemon-start
mise run daemon-status
mise run ping
mise run daemon-stop
```

## Notes

- Prefer editing `crates/projd` and `crates/proj` over adding one-off scripts.
- Keep IPC contract changes in `crates/projd-types`.
