#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v0.1.0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/${VERSION}"
COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo 'dev')"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

TARGETS=(
  "darwin arm64"
  "darwin amd64"
  "linux amd64"
  "linux arm64"
)

LDFLAGS="-s -w -X main.version=${VERSION#v} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}"

for target in "${TARGETS[@]}"; do
  read -r GOOS GOARCH <<<"$target"
  STAGE="${DIST_DIR}/stage-${GOOS}-${GOARCH}"
  mkdir -p "$STAGE"
  echo "Building rax ${VERSION} for ${GOOS}/${GOARCH}..."
  (
    cd "$ROOT_DIR"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
      go build -trimpath -ldflags="$LDFLAGS" -o "${STAGE}/rax" ./cmd/rax
  )
  TARBALL="rax-${VERSION}-${GOOS}-${GOARCH}.tar.gz"
  tar -C "$STAGE" -czf "${DIST_DIR}/${TARBALL}" rax
  rm -rf "$STAGE"
done

(
  cd "$DIST_DIR"
  shasum -a 256 rax-${VERSION}-*.tar.gz > checksums.txt
)

echo "Built release artifacts in ${DIST_DIR}:"
cat "${DIST_DIR}/checksums.txt"
