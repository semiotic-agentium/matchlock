#!/bin/bash
# Build the eBPF tracer as a static binary using Docker.
# Requires Docker with BuildKit.
#
# Output: ~/.cache/matchlock/ebpf-tracer (or OUTPUT_DIR/ebpf-tracer)
#
# Usage:
#   ./scripts/build-ebpf-tracer.sh
#   OUTPUT_DIR=/custom/path ./scripts/build-ebpf-tracer.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EBPF_DIR="$SCRIPT_DIR/../ebpf"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/.cache/matchlock}"

echo "Building eBPF tracer binary..."
cd "$EBPF_DIR" && DOCKER_BUILDKIT=1 docker build \
    --target output --output type=local,dest=./out .

mkdir -p "$OUTPUT_DIR"
cp out/ebpf-tracer "$OUTPUT_DIR/ebpf-tracer"
rm -rf out/
echo "eBPF tracer built: $OUTPUT_DIR/ebpf-tracer"
