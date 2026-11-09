#!/usr/bin/env bash
# Static cross-build for vpncloud (with websocket / wss support)
#
# Usage:
#   ./build-static.sh [target]
#
# Examples:
#   ./build-static.sh x86_64-unknown-linux-musl      # -> build-linux-x86_64-unknown-linux-musl/
#   ./build-static.sh aarch64-unknown-linux-gnu      # -> build-linux-aarch64-unknown-linux-gnu/
#   ./build-static.sh armv7-unknown-linux-gnueabihf  # -> build-linux-armv7-unknown-linux-gnueabihf/
#   ./build-static.sh i686-unknown-linux-musl        # -> build-linux-i686-unknown-linux-musl/
#   ./build-static.sh mipsel-unknown-linux-musl      # -> build-linux-mipsel-unknown-linux-musl/  (nightly + build-std)
#   ./build-static.sh x86_64-pc-windows-gnu          # -> build-windows-x86_64-pc-windows-gnu/
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-x86_64-unknown-linux-musl}"
FEATURES="nat,websocket"

# 輸出目錄：build-linux-<target> / build-windows-<target>
case "$TARGET" in
    *pc-windows-gnu*) OUT_DIR="build-windows-${TARGET}" ;;
    *)                OUT_DIR="build-linux-${TARGET}"   ;;
esac
BIN_NAME="vpncloud-static-${TARGET}"

# 交叉編譯鏈接器
case "$TARGET" in
    *pc-windows-gnu*)
        if [[ "$TARGET" == *x86_64* ]]; then
            export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
            export CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++
            export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
        else
            export CC_i686_pc_windows_gnu=i686-w64-mingw32-gcc
            export CXX_i686_pc_windows_gnu=i686-w64-mingw32-g++
            export AR_i686_pc_windows_gnu=i686-w64-mingw32-ar
        fi
        ;;
    *aarch64*linux-gnu*)
        export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
        export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
        export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc-ar
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
        ;;
    *armv7*gnueabihf*)
        export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
        export CXX_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-g++
        export AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc-ar
        export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
        ;;
esac

echo "[1/4] Ensuring Rust target '${TARGET}' is available..."
# mipsel-unknown-linux-musl 沒有穩定版預建 target，需用 nightly + build-std，跳過 rustup 安裝
if [[ "$TARGET" == *mipsel-unknown-linux-musl ]]; then
    echo "  (mipsel-musl: skip rustup target add, use nightly + build-std)"
elif ! rustup target list --installed 2>/dev/null | grep -qx "${TARGET}"; then
    echo "Target '${TARGET}' not installed, installing..."
    rustup target add "${TARGET}"
fi

echo "[2/4] Building release binary (no-default-features, features=${FEATURES}, target=${TARGET})..."

# mipsel-unknown-linux-musl 沒有預建 rust-std，需用 nightly + build-std
if [[ "$TARGET" == *mipsel-unknown-linux-musl ]]; then
    export CC_mipsel_unknown_linux_musl="${SCRIPT_DIR}/mipsel-musl-linker.sh"
    export CC="${SCRIPT_DIR}/mipsel-musl-linker.sh"
    cargo +nightly build --release --target "${TARGET}" -Z build-std=core,alloc,std \
        --no-default-features --features "${FEATURES}"
else
    case "$TARGET" in
        *musl*|*linux-musl*)
            RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "${TARGET}" \
                --no-default-features --features "${FEATURES}"
            ;;
        *)
            cargo build --release --target "${TARGET}" \
                --no-default-features --features "${FEATURES}"
            ;;
    esac
fi

BINARY="target/${TARGET}/release/vpncloud"
case "$TARGET" in
    *windows*) BINARY="${BINARY}.exe" ;;
esac

if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: expected binary not found at ${BINARY}" >&2
    exit 1
fi

echo "[3/4] Preparing output directory '${OUT_DIR}'..."
mkdir -p "${OUT_DIR}"

echo "[4/4] Copying and stripping binary..."
cp "${BINARY}" "${OUT_DIR}/${BIN_NAME}"
case "$TARGET" in
    *windows*)
        x86_64-w64-mingw32-strip "${OUT_DIR}/${BIN_NAME}" 2>/dev/null \
        || i686-w64-mingw32-strip "${OUT_DIR}/${BIN_NAME}" 2>/dev/null \
        || strip "${OUT_DIR}/${BIN_NAME}" 2>/dev/null || true
        ;;
    *)
        strip "${OUT_DIR}/${BIN_NAME}" 2>/dev/null || true
        ;;
esac

echo
echo "Done: ${OUT_DIR}/${BIN_NAME}"
file "${OUT_DIR}/${BIN_NAME}" 2>/dev/null || true
