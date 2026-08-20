#!/usr/bin/env bash
# Same non-deploy pipeline as loom-ci.toml. Does not build Docker or restart the service.
set -euo pipefail
cd "$(dirname "$0")/.."

run() {
  echo "$ $*"
  "$@"
}

run cargo fmt --check
run cargo clippy --locked -p loom -- -D warnings
run cargo test --locked -p loom
