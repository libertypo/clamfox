#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[critical] Checking fail-closed phrasing invariants..."
if rg -n "Response signing failed \(continuing anyway\)" host/clamav_engine.py >/dev/null; then
  echo "ERROR: insecure signing fallback phrase detected in host/clamav_engine.py"
  exit 1
fi

echo "[critical] Checking for high-risk execution anti-patterns..."
if rg -n "shell=True|os\.system\(|subprocess\.Popen\(" host/*.py >/dev/null; then
  echo "ERROR: high-risk execution pattern detected in host/*.py"
  exit 1
fi

echo "[critical] Checking packaging placeholders are guarded..."
if ! rg -n "PLACEHOLDER_WASM_HASH" package.sh >/dev/null; then
  echo "ERROR: package.sh missing PLACEHOLDER_WASM_HASH guard"
  exit 1
fi

echo "[critical] All invariants passed."