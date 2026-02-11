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

echo "Bootstrap complete."
echo "Next: mise tasks ls"
