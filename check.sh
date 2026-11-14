#!/usr/bin/env bash
# Everything a change must pass that needs no human: formatting, lints, the tests, a release build
# and what its build-info says, the shim, and the syntax of the runner, install.sh,
# install-linux.sh (and its dry run) and macos-check.sh. Run before pushing (`mise run check` runs
# this). When every step passes with no changes to the files, it writes the commit it passed at to
# check-passed in the target folder: install-linux.sh installs only that commit.
#
# The release build's run with every test hook set and the escape tests need user namespaces. Where
# the system restricts them (Ubuntu 24.04 does, through AppArmor), they are not run: check.sh ends
# by listing what it could not run here and why, and writes those lines into check-passed after the
# commit, for install-linux.sh to name.
#
# CARGO_BUILD_JOBS defaults to 3. A set CARGO_TARGET_DIR is used for halti; the shim builds in
# SHIM_TARGET_DIR if that is set, else in its own target/.
#
# `./check.sh refs [RANGE]` runs only the first step: no tracked file cites private planning
# (issue tracker IDs, milestone and plan codes, local design notes, decision records), and with a
# RANGE (`A..B`, or `B --not --remotes`) no commit message in it does either. The repo is public;
# those stay in the tracker. `./check.sh install-hook` makes git run it before every push.
# `./check.sh userns [ARGS]` says why `unshare ARGS true` (`-Urm` by default) fails here, or nothing
# when it works.
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

# Why `unshare ARGS true` fails here, or nothing when it works.
userns_blocked() {
  local said
  if said="$(unshare "$@" true 2>&1)"; then return 0; fi
  if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
    echo "AppArmor restricts unprivileged user namespaces here"
  else
    echo "unshare $* fails here${said:+: ${said%%$'\n'*}}"
  fi
}

case "${1:-}" in
  refs)
    refs "${2:-}"
    exit
    ;;
  userns)
    shift
    if [ $# = 0 ]; then set -- -Urm; fi
    userns_blocked "$@"
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
    echo "usage: ./check.sh [refs [RANGE] | install-hook | userns [ARGS]]" >&2
    exit 2
    ;;
esac
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
target="${CARGO_TARGET_DIR:-target}"
# Absolute, since the release tests run the binary from other folders.
case "$target" in /*) ;; *) target="$PWD/$target" ;; esac
stamp="$target/check-passed"
rm -f "$stamp"
# What could not run here, with why: one line each.
not_run=()
# The tests of tests/release.rs that run the release build in a user namespace, in their order
# there; tests/install_linux.rs keeps this list true.
release_userns_tests=(
  the_home_folder_is_the_passwd_one
  no_variable_answers_an_approval
  no_variable_moves_the_index_the_policies_the_boxes_or_the_keychain
  without_a_passwd_home_nothing_runs
  no_variable_answers_a_passphrase
  no_variable_answers_sudo
)

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

# They are #[ignore]d, so they run only here, with their output, to show which ran and which parts
# were skipped. Linux only, and only where a box can be made.
step "escape tests"
why=""
if [ "$(uname -s)" = Linux ]; then why="$(userns_blocked -Urnm --pid --fork)"; fi
if [ -n "$why" ]; then
  echo "not run: $why"
  not_run+=("the escape tests of the sandbox engine, which only debug builds have ($why)")
else
  if ! said="$(cargo test --test sandbox -- --ignored --nocapture --test-threads=1 2>&1)"; then
    printf '%s\n' "$said"
    exit 1
  fi
  grep -oE 'escape test (ran|skipped): .*|test result: .*' <<<"$said"
  while IFS= read -r line; do
    not_run+=("escape test ${line#escape test skipped: }")
  done < <(grep -oE 'escape test skipped: .*' <<<"$said" || true)
fi

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
# Runs it with every test hook set, in a user namespace, so Linux only. Where none can be made,
# only the release tests that need none run.
if [ "$(uname -s)" = Linux ]; then
  why="$(userns_blocked -Urm)"
  if [ -z "$why" ]; then
    HALTI_RELEASE_BIN="$bin" cargo test --test release -- --ignored
  else
    skip=()
    for name in "${release_userns_tests[@]}"; do skip+=(--skip "$name"); done
    HALTI_RELEASE_BIN="$bin" cargo test --test release -- --ignored --exact "${skip[@]}"
    not_run+=("the ${#release_userns_tests[@]} release tests that run the release build with every test hook set ($why)")
  fi
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
  { echo "$head"; for line in ${not_run[@]+"${not_run[@]}"}; do echo "$line"; done; } >"$stamp"
fi
if [ ${#not_run[@]} = 0 ]; then
  step "all checks passed"
else
  step "all checks that ran passed; not run here:"
  printf '%s\n' "${not_run[@]}"
fi
