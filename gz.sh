#!/bin/bash
set -e
cd /root/github/vpncloud
mkdir -p gz

# Format: tar cvfz gz/<build-dir>.tar.gz <binary>
# Each build-* dir contains exactly one stripped static binary

for dir in build-linux-aarch64-unknown-linux-gnu \
           build-linux-armv7-unknown-linux-gnueabihf \
           build-linux-mipsel-unknown-linux-musl \
           build-linux-x86_64-unknown-linux-musl; do
    bin=$(ls "$dir"/vpncloud-static-* 2>/dev/null | head -1)
    if [ -n "$bin" ]; then
        tar cvfz "gz/${dir}.tar.gz" -C "$dir" "$(basename "$bin")"
    fi
done

echo "--- done ---"
ls -lh gz/
