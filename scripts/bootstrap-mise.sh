#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v mise >/dev/null 2>&1; then
  echo "Installing mise..."
  curl -fsSL https://mise.run | sh
fi

export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"

mise trust "$ROOT_DIR" >/dev/null 2>&1 || true
mise install

echo "Installing proj/projd CLI binaries..."
if CARGO_NET_OFFLINE=false ./scripts/cargo-safe.sh install --path crates/proj --force \
  && CARGO_NET_OFFLINE=false ./scripts/cargo-safe.sh install --path crates/projd --force; then
  echo "Installed proj/projd to $HOME/.cargo/bin."
else
  echo "Warning: failed to install proj/projd automatically."
  echo "You can retry with: mise run install-cli"
fi

if [[ ":$PATH:" != *":$HOME/.cargo/bin:"* ]]; then
  echo "Note: $HOME/.cargo/bin is not in PATH for this shell."
  echo "Add this to ~/.zshrc:"
  echo "export PATH=\"$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.local/share/mise/shims:\$PATH\""
fi

echo "Bootstrap complete."
echo "Next: mise tasks ls"
