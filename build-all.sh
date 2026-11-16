#!/usr/bin/env bash
# Build and package all supported vpncloud static binaries.
# Prevents missing a platform by iterating a single canonical target list.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGETS=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  armv7-unknown-linux-gnueabihf
  mipsel-unknown-linux-musl
  x86_64-pc-windows-gnu
)

for target in "${TARGETS[@]}"; do
  echo "============================================================"
  echo "[build-all] Building target: ${target}"
  echo "============================================================"
  ./build-static.sh "${target}"
done

echo "============================================================"
echo "[build-all] Packaging all builds (gz.sh)"
echo "============================================================"
./gz.sh

echo "============================================================"
echo "[build-all] Build artifacts"
echo "============================================================"
ls -lh build-linux-*/vpncloud-static-* build-windows-*/vpncloud-static-* 2>/dev/null || true

echo "============================================================"
echo "[build-all] Package artifacts"
echo "============================================================"
ls -lh gz/*.tar.gz 2>/dev/null || true

echo "[build-all] Done."
