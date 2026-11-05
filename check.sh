#!/usr/bin/env bash
# Everything a change must pass that needs no human: formatting, lints, the tests, a release build
# and what its build-info says, the shim, the runner's syntax and install.sh's. Run before
# pushing (`mise run check` runs this).
#
# CARGO_BUILD_JOBS defaults to 3. A set CARGO_TARGET_DIR is used for halti; the shim builds in
# SHIM_TARGET_DIR if that is set, else in its own target/.
set -euo pipefail
cd "$(dirname "$0")"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
target="${CARGO_TARGET_DIR:-target}"

step() { printf '\n== %s\n' "$*"; }

step format
cargo fmt --check
(cd box/shim && cargo fmt --check)

step clippy
cargo clippy --all-targets -- -D warnings

step tests
cargo test

step "release check"
cargo check --release

# The release profile without link-time optimisation: what a release build compiles, faster.
step "ci-release build"
cargo build --profile ci-release
bin="$target/ci-release/halti"
info="$("$bin" build-info)"
echo "$info"
if ! grep -qx 'debug_assertions=false halti_dev=false' <<<"$info"; then
  echo "check.sh: the ci-release build has the test hooks" >&2
  exit 1
fi
# Runs it with every test hook set (in a user namespace, so Linux only).
if [ "$(uname -s)" = Linux ]; then
  HALTI_RELEASE_BIN="$bin" cargo test --test release -- --ignored
fi

step shim
(
  cd box/shim
  if [ -n "${SHIM_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$SHIM_TARGET_DIR"
  else
    unset CARGO_TARGET_DIR
  fi
  cargo build
  cargo test
)

step "runner and install.sh"
node --check runner/runner.mjs
bash -n install.sh

step "all checks passed"
