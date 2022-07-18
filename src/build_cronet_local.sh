#!/bin/sh
set -e

export TMPDIR="$PWD/tmp"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"
export DEPOT_TOOLS_WIN_TOOLCHAIN=0

ninja -C "out/Release" cronet cronet_static
./make-cronet-cgo-sdk.sh
