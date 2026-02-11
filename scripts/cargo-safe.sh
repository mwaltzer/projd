#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if command -v cargo >/dev/null 2>&1; then
  CARGO_BIN="$(command -v cargo)"
else
  # Fallback for Codex sandbox where rust is available but PATH is partial.
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    CARGO_BIN="$HOME/.cargo/bin/cargo"
  else
    CARGO_BIN="$(find /nix/store -maxdepth 3 -type f -name cargo 2>/dev/null | sort | tail -n 1 || true)"
  fi
fi

if [ -z "${CARGO_BIN:-}" ] || [ ! -x "${CARGO_BIN:-}" ]; then
  echo "cargo not found."
  echo "Run: mise run bootstrap"
  exit 1
fi

export PATH="$(dirname "$CARGO_BIN"):$PATH"
# Avoid network attempts in restricted sandboxes when lock/deps are already present.
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

# On macOS, prefer Apple toolchain/SDK so linker can resolve system libs (e.g. -liconv).
if [ "$(uname -s)" = "Darwin" ]; then
  export CC="${CC:-/usr/bin/cc}"
  export CXX="${CXX:-/usr/bin/c++}"
  export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="${CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER:-/usr/bin/cc}"
  export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="${CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER:-/usr/bin/cc}"
  if [ -z "${SDKROOT:-}" ] && command -v xcrun >/dev/null 2>&1; then
    if sdk_path="$(xcrun --show-sdk-path 2>/dev/null)"; then
      export SDKROOT="$sdk_path"
    fi
  fi
fi

exec "$CARGO_BIN" "$@"
