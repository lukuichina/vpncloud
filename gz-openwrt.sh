#!/bin/bash
# Package only the OpenWrt (mipsel) vpncloud binary
set -e
cd /root/github/vpncloud

mkdir -p gz

OUT_DIR="build-linux-mipsel-unknown-linux-musl"
BIN_NAME="vpncloud-static-mipsel-unknown-linux-musl"

if [ ! -f "${OUT_DIR}/${BIN_NAME}" ]; then
    echo "ERROR: Binary not found at ${OUT_DIR}/${BIN_NAME}" >&2
    echo "Run ./build-openwrt.sh first." >&2
    exit 1
fi

# Package only the OpenWrt binary
tar cvfz "gz/${OUT_DIR}.tar.gz" -C "${OUT_DIR}" "${BIN_NAME}"

echo "--- done ---"
ls -lh gz/${OUT_DIR}.tar.gz