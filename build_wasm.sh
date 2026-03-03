#!/bin/bash
# ClamFox WASM Build Script
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_DIR="$DIR/wasm-shield"
DIST_DIR="$DIR/wasm_shield"

echo "🦀 Building ClamFox Shield (WebAssembly)..."

# 1. Toolchain Check
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo not found. Please install Rust: https://rustup.rs"
    exit 1
fi

# 2. Add WASM Target (if possible)
rustup target add wasm32-unknown-unknown || echo "⚠️  Attempting build without rustup-managed target..."

# 3. Build release profile
cd "$WASM_DIR"
cargo build --target wasm32-unknown-unknown --release

# 4. Preparation for extension inclusion
# Note: we use the raw .wasm for manual loading in background.js
mkdir -p "$DIST_DIR"
cp "target/wasm32-unknown-unknown/release/clamfox_shield.wasm" "$DIST_DIR/"

echo "✅ WASM Build Complete: $DIST_DIR/clamfox_shield.wasm"
