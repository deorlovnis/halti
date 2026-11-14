#!/usr/bin/env bash
# Everything a change must pass that needs no human: formatting, lints, the tests, a release build
# and what its build-info says, the shim, and the syntax of the runner, install.sh,
# install-linux.sh (and its dry run) and macos-check.sh. Run before pushing (`mise run check` runs
# this). When every step passes with no changes to the files, it writes the commit it passed at to
# check-passed in the target folder: install-linux.sh installs only that commit.
#
# CARGO_BUILD_JOBS defaults to 3. A set CARGO_TARGET_DIR is used for halti; the shim builds in
# SHIM_TARGET_DIR if that is set, else in its own target/.
#
# `./check.sh refs [RANGE]` runs only the first step: no tracked file cites private planning
# (issue tracker IDs, milestone and plan codes, local design notes, decision records), and with a
# RANGE (`A..B`, or `B --not --remotes`) no commit message in it does either. The repo is public;
# those stay in the tracker. `./check.sh install-hook` makes git run it before every push.
set -euo pipefail
cd "$(dirname "$0")"

# Extended regexes without \b, so GNU and BSD grep read them alike. This file is the one place
# they may appear.
refs_patterns=(
  '(^|[^A-Za-z0-9])EMA-[0-9]+'
  'linear\.app'
  '(^|[^A-Za-z0-9])(M[0-9]b?|L[0-9]|H[0-9]|I[0-9]|T[0-9]) ·'
  '(^|[^A-Za-z0-9])M1b([^A-Za-z0-9]|$)'
  '(^|[^A-Za-z0-9])KR[0-9]+([^0-9]|$)'
  '[Pp]lan PR ?#?[0-9]'
  'halti-design|halti-verbs|/work/(halti-|eco/|pith-)'
  'docs/(box-design|TODO)|se-probe'
  '[Tt]rinity|interface register'
  "owner('s)? (decision|decided|asked|wants|answer)"
  'decided (on |by the owner )?20[0-9][0-9]-[0-9][0-9]'
)
refs() {
  local args=() p found=0
  for p in "${refs_patterns[@]}"; do args+=(-e "$p"); done
  if git grep -nIE "${args[@]}" -- . ':(exclude)check.sh'; then found=1; fi
  if [ -n "${1:-}" ]; then
    # shellcheck disable=SC2086 # RANGE is several git arguments on purpose.
    if git log --format='%h %s%n%b' $1 | grep -nE "${args[@]}"; then found=1; fi
  fi
  if [ "$found" = 1 ]; then
    echo "check.sh: the lines above cite private planning; keep that in the tracker" >&2
    return 1
  fi
}

case "${1:-}" in
  refs)
    refs "${2:-}"
    exit
    ;;
  install-hook)
    hook="$(git rev-parse --git-path hooks)/pre-push"
    cat >"$hook" <<'HOOK'
#!/usr/bin/env bash
# Installed by `./check.sh install-hook`: refuse a push whose files or commit messages cite
# private planning.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
zero=0000000000000000000000000000000000000000
while read -r _ local_sha _ remote_sha; do
  [ "$local_sha" = "$zero" ] && continue
  if [ "$remote_sha" = "$zero" ]; then range="$local_sha --not --remotes"; else range="$remote_sha..$local_sha"; fi
  ./check.sh refs "$range"
done
HOOK
    chmod +x "$hook"
    echo "installed $hook"
    exit
    ;;
  "") ;;
  *)
    echo "usage: ./check.sh [refs [RANGE] | install-hook]" >&2
    exit 2
    ;;
esac
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
target="${CARGO_TARGET_DIR:-target}"
# Absolute, since the release tests run the binary from other folders.
case "$target" in /*) ;; *) target="$PWD/$target" ;; esac
stamp="$target/check-passed"
rm -f "$stamp"

# The commit checked out, if the files have no changes since it; else nothing.
clean_head() {
  if [ -z "$(git status --porcelain)" ]; then git rev-parse HEAD; fi
}
head="$(clean_head)"

step() { printf '\n== %s\n' "$*"; }

step "no private references"
refs

step format
cargo fmt --all --check
(cd box/shim && cargo fmt --check)

step clippy
cargo clippy --workspace --all-targets -- -D warnings

step tests
cargo test --workspace

# Again with their output, to show which escape tests ran here and which were skipped.
step "escape tests"
cargo test --test sandbox -- --nocapture --test-threads=1 2>&1 | grep -oE 'escape test (ran|skipped): .*|test result: .*'

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

step "runner, install scripts and macos-check.sh"
node --check runner/runner.mjs
bash -n install.sh
bash -n install-linux.sh
./install-linux.sh --dry-run >/dev/null
bash -n macos-check.sh

if [ -n "$head" ] && [ "$(clean_head)" = "$head" ]; then
  echo "$head" >"$stamp"
fi
step "all checks passed"
