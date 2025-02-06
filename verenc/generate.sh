#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_VERENC_PACKAGE="$ROOT_DIR/crates/verenc"
BINDINGS_DIR="$ROOT_DIR/verenc"

# Build the Rust VerEnc package in release mode
cargo build -p verenc --release

# Generate Go bindings
pushd "$RUST_VERENC_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
