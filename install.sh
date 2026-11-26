#!/usr/bin/env sh
set -eu

REPO="larrykoo711/rax-cli"
BIN_NAME="rax"
INSTALL_DIR="${RAX_INSTALL_DIR:-/usr/local/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  darwin|linux) ;;
  *)
    echo "Unsupported OS: $OS (supported: darwin, linux)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH (supported: amd64, arm64)" >&2
    exit 1
    ;;
esac

VERSION="${RAX_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
if [ -z "$VERSION" ]; then
  echo "Failed to resolve latest rax-cli release version." >&2
  exit 1
fi

ASSET="${BIN_NAME}-${VERSION}-${OS}-${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${ASSET}..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_DIR}/${ASSET}"
curl -fsSL "${BASE_URL}/checksums.txt" -o "${TMP_DIR}/checksums.txt"

EXPECTED="$(grep " ${ASSET}\$" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
  echo "Checksum entry for ${ASSET} not found." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${TMP_DIR}/${ASSET}" | awk '{print $1}')"
else
  echo "Neither sha256sum nor shasum found to verify download integrity." >&2
  exit 1
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA-256 checksum mismatch for ${ASSET}!" >&2
  exit 1
fi

tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}"

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
elif command -v sudo >/dev/null 2>&1; then
  echo "Installing ${BIN_NAME} to ${INSTALL_DIR} (sudo required)..."
  sudo install -m 0755 "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
else
  LOCAL_BIN="${HOME}/.local/bin"
  mkdir -p "$LOCAL_BIN"
  install -m 0755 "${TMP_DIR}/${BIN_NAME}" "${LOCAL_BIN}/${BIN_NAME}"
  INSTALL_DIR="$LOCAL_BIN"
  echo "Note: ensure ${LOCAL_BIN} is in your PATH."
fi

echo "Installed $( "${INSTALL_DIR}/${BIN_NAME}" --version ) to ${INSTALL_DIR}/${BIN_NAME}"
