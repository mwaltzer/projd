#!/usr/bin/env sh
set -eu

REPO="mwaltzer/projd"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux)  os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *)      echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  arch="x86_64" ;;
  aarch64|arm64)  arch="aarch64" ;;
  *)              echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARGET="${arch}-${os}"

# Determine install directory
if [ -d "${CARGO_HOME:-$HOME/.cargo}/bin" ]; then
  INSTALL_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

# Fetch latest release tag
echo "Fetching latest release..."
RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
if command -v curl > /dev/null 2>&1; then
  TAG=$(curl -fsSL "$RELEASE_URL" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
elif command -v wget > /dev/null 2>&1; then
  TAG=$(wget -qO- "$RELEASE_URL" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
else
  echo "Error: curl or wget required" >&2; exit 1
fi

if [ -z "$TAG" ]; then
  echo "Error: could not determine latest release" >&2; exit 1
fi

ARCHIVE="projd-${TAG}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"

echo "Downloading projd ${TAG} for ${TARGET}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if command -v curl > /dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/$ARCHIVE"
else
  wget -q "$DOWNLOAD_URL" -O "$TMPDIR/$ARCHIVE"
fi

echo "Installing to ${INSTALL_DIR}..."
tar -xzf "$TMPDIR/$ARCHIVE" -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/proj" "$INSTALL_DIR/projd" "$INSTALL_DIR/proj-tui"

echo "Installed: proj, projd, proj-tui -> ${INSTALL_DIR}"

# Check PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Note: add ${INSTALL_DIR} to your PATH" ;;
esac
