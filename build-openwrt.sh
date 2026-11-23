#!/usr/bin/env bash
# Static cross-build for vpncloud (OpenWrt / mipsel-unknown-linux-musl)
# Produces a truly static binary (EXEC type, no dynamic interpreter)
#
# Usage:
#   ./build-openwrt.sh
#
# Output: build-linux-mipsel-unknown-linux-musl/vpncloud-static-mipsel-unknown-linux-musl

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="mipsel-unknown-linux-musl"
FEATURES="nat,websocket"
OUT_DIR="build-linux-${TARGET}"
BIN_NAME="vpncloud-static-${TARGET}"

echo "============================================================"
echo "[build-openwrt] Building target: ${TARGET}"
echo "============================================================"

# Cross-compiler setup
export CC_mipsel_unknown_linux_musl="${SCRIPT_DIR}/mipsel-musl-linker.sh"
export CC="${SCRIPT_DIR}/mipsel-musl-linker.sh"

echo "[1/4] Building release binary (nightly + build-std, static relocation)..."
# Key fix: -C relocation-model=static prevents generating a PIE (Position-Independent Executable)
# which requires a dynamic interpreter (/lib/ld.so.1) that OpenWrt doesn't have.
RUSTFLAGS="-C relocation-model=static" rustup run nightly cargo build --release \
    --target "${TARGET}" -Z build-std=core,alloc,std \
    --no-default-features --features "${FEATURES}"

BINARY="target/${TARGET}/release/vpncloud"
if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: expected binary not found at ${BINARY}" >&2
    exit 1
fi

echo "[2/4] Preparing output directory '${OUT_DIR}'..."
mkdir -p "${OUT_DIR}"

echo "[3/4] Copying binary..."
cp "${BINARY}" "${OUT_DIR}/${BIN_NAME}"

echo "[4/4] Stripping binary..."
/opt/musl/mipsel_le/mipsel-linux-muslsf-cross/bin/mipsel-linux-muslsf-strip \
    --strip-all -R .mdebug.abi32 -R .comment -R .note -R .note.gnu.build-id \
    "${OUT_DIR}/${BIN_NAME}" 2>/dev/null || true

echo
echo "Done: ${OUT_DIR}/${BIN_NAME}"
ls -lh "${OUT_DIR}/${BIN_NAME}"

# Verify static linking
if readelf -l "${OUT_DIR}/${BIN_NAME}" 2>/dev/null | grep -q "INTERP"; then
    echo "WARNING: Binary still has INTERP section (not fully static!)"
else
    echo "Verified: No INTERP section - truly statically linked"
fi