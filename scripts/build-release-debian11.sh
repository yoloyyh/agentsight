#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT_DIR="${1:-/out}"

export NEXT_TELEMETRY_DISABLED="${NEXT_TELEMETRY_DISABLED:-1}"
export npm_config_update_notifier="${npm_config_update_notifier:-false}"

echo "[build] root=$ROOT_DIR"
echo "[build] out=$OUT_DIR"

cd "$ROOT_DIR"
make clean

cd "$ROOT_DIR/frontend"
npm ci
npm run build

cd "$ROOT_DIR"
make build-bpf
make build-rust

mkdir -p "$OUT_DIR/bpf" "$OUT_DIR/frontend" "$OUT_DIR/collector"
cp "$ROOT_DIR/collector/target/release/agentsight" "$OUT_DIR/collector/agentsight"
cp "$ROOT_DIR/bpf/process" "$OUT_DIR/bpf/process"
cp "$ROOT_DIR/bpf/sslsniff" "$OUT_DIR/bpf/sslsniff"
cp "$ROOT_DIR/bpf/stdiocap" "$OUT_DIR/bpf/stdiocap"
cp -a "$ROOT_DIR/frontend/dist" "$OUT_DIR/frontend/dist"

echo "[build] done"
