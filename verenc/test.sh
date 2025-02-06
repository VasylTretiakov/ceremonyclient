#!/bin/bash
set -euxo pipefail

# Run tests for the verenc package. Takes care of linking the native VerEnc library.
# Assumes that the VerEnc library has been built by running the generate.sh script in the same directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/verenc"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link the native VerEnc library and execute tests
pushd "$NODE_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -lverenc -ldl -lm" \
	CGO_ENABLED=1 \
  go test "$@"
