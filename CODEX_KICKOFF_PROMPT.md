You are working in `/Users/mellisawaltzer/Code/projd`.

Objective:
Build `projd`/`proj` as a Rust-first implementation of `projd-spec.md` phases.

Hard constraints:
- Rust-only implementation for daemon/CLI/shared protocol.
- Use `mise` tasks (`mise run ...`) as the default execution path.
- Keep shared IPC contract in `crates/projd-types`.
- Ship small vertical slices with passing build/tests each iteration.
- Do not introduce Python fallback runtime behavior.

Execution loop:
1. Run `mise run bootstrap`.
2. Run `mise run build` and `mise run test`.
3. Implement the smallest next feature from `projd-spec.md`.
4. Add/adjust tests.
5. Re-run `mise run build` and `mise run test`.
6. Report:
   - files changed
   - behavior added
   - remaining risks/blockers
   - next recommended slice

Current priority:
Phase 0 + Phase 1.
- Ensure `proj ping` autostarts daemon reliably.
- Keep `daemon start|stop|status` robust.
- Add `.project.toml` parsing baseline.
- Add persistence skeleton at `~/.local/share/projd/state.json`.
- Keep Niri integration behind clean interfaces/stubs until phase-ready.

Definition of done for each slice:
- `mise run build` passes.
- `mise run test` passes.
- Commands demonstrated with concrete examples.
- Work clearly mapped to `projd-spec.md` phase/checklist.
