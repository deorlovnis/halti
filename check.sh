#!/usr/bin/env bash
# Everything a change must pass that needs no human: formatting, lints, the tests, a release build
# and what its build-info says, the shim, and the syntax of the runner, install.sh,
# install-linux.sh (and its dry run), box/to-disk.sh and macos-check.sh. Run before pushing
# (`mise run check` runs this). When every step passes with no changes to the files, it writes the
# commit it passed at to check-passed in the target folder: install-linux.sh installs only that
# commit. On a Rust older than Cargo.toml's rust-version it stops at once, in one line.
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
# `./check.sh userns` says why the release tests' `unshare -Urm` can't make a user namespace here,
# and `./check.sh userns box` why the debug halti (built first) can't make a box; each says nothing
# when it can.
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

# Whether AppArmor restricts unprivileged user namespaces here: 1 if it does, else 0 or nothing.
apparmor_userns() {
  sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null ||
    cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true
}

# Why CMD fails here, or nothing when it works: the last line it said. AppArmor is named only where
# it restricts user namespaces and CMD failed as that makes it fail: unshare(1) can't write its uid
# map, halti can't write its setgroups.
userns_blocked() {
  local said
  if said="$("$@" 2>&1)"; then return 0; fi
  said="${said##*$'\n'}"
  case "$said" in
    */proc/self/uid_map*"Operation not permitted"* | */proc/self/setgroups*"Permission denied"*)
      if [ "$(apparmor_userns)" = 1 ]; then
        echo "AppArmor restricts unprivileged user namespaces here"
        return 0
      fi
      ;;
  esac
  echo "${said:-$1 fails here}"
}

# Why the debug halti can't make a box here, or nothing when it can or fails some other way (the
# escape tests then run and say how). It asks halti, not unshare(1): the sandbox makes its
# namespaces with its own unshare(2), and AppArmor's limit is per program.
box_blocked() {
  local why
  why="$(userns_blocked "$target/debug/halti" box sh --engine sandbox -- true)"
  case "$why" in AppArmor* | *"making the box's namespaces"* | *"writing /proc/self/"*) echo "$why" ;; esac
}

# Whether version A is older than B, part by part; a missing part is 0.
older() {
  local IFS=. a b i
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    if [ "${a[i]:-0}" != "${b[i]:-0}" ]; then
      [ "${a[i]:-0}" -lt "${b[i]:-0}" ]
      return
    fi
  done
  return 1
}

# Fails, in one line, when the Rust here is older than Cargo.toml's rust-version. Cargo would say
# so in several lines, and one older than the 2024 edition fails on the manifest instead.
rust_new_enough() {
  local floor have
  floor="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)"
  if ! have="$("${RUSTC:-rustc}" --version 2>/dev/null)"; then
    echo "check.sh: no rustc here; halti needs Rust $floor or newer (rust-toolchain.toml pins the one it passes with)" >&2
    return 1
  fi
  have="${have#rustc }"
  have="${have%% *}"
  have="${have%%-*}"
  if older "$have" "$floor"; then
    echo "check.sh: Rust $have is older than $floor, the oldest that builds halti (rust-toolchain.toml pins the one it passes with)" >&2
    return 1
  fi
}

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
target="${CARGO_TARGET_DIR:-target}"
# Absolute, since the release tests run the binary from other folders.
case "$target" in /*) ;; *) target="$PWD/$target" ;; esac

case "${1:-}" in
  refs)
    refs "${2:-}"
    exit
    ;;
  userns)
    if [ "${2:-}" = box ]; then box_blocked; else userns_blocked unshare -Urm true; fi
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
    echo "usage: ./check.sh [refs [RANGE] | install-hook | userns [box]]" >&2
    exit 2
    ;;
esac
rust_new_enough
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
# The escape tests of tests/sandbox.rs, in their order there; tests/install_linux.rs keeps this list
# true. Where no box can be made, the tests step leaves them out.
escape_tests=(
  bash_and_claude_run_inside
  the_network_is_only_lo
  tcp_to_the_host_fails
  a_file_outside_the_bind_set_is_missing
  the_callers_folder_is_out_of_reach
  the_callers_environment_stays_out
  the_callers_fds_stay_out
  no_host_root_in_mountinfo
  every_proc_mount_is_read_only
  nothing_is_left_after_exit
  a_missing_or_unrunnable_command_says_so
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
# On Linux the escape tests run only where the debug halti can make a box.
box_why=""
if [ "$(uname -s)" = Linux ]; then
  cargo build --bin halti
  box_why="$(box_blocked)"
fi
if [ -z "$box_why" ]; then
  cargo test --workspace
else
  skip=()
  for name in "${escape_tests[@]}"; do skip+=(--skip "$name"); done
  cargo test --workspace -- --exact "${skip[@]}"
fi

# Again with their output, to show which escape tests ran here and which parts were skipped.
step "escape tests"
if [ -n "$box_why" ]; then
  echo "not run: $box_why"
  not_run+=("the escape tests of the sandbox engine, which only debug builds have ($box_why)")
else
  if ! said="$(cargo test --test sandbox -- --nocapture --test-threads=1 2>&1)"; then
    printf '%s\n' "$said"
    exit 1
  fi
  grep -oE 'escape test (ran|skipped): .*|test result: .*' <<<"$said"
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
  why="$(userns_blocked unshare -Urm true)"
  if [ -z "$why" ]; then
    HALTI_RELEASE_BIN="$bin" cargo test --test release -- --ignored
  else
    skip=()
    for name in "${release_userns_tests[@]}"; do skip+=(--skip "$name"); done
    HALTI_RELEASE_BIN="$bin" cargo test --test release -- --ignored --exact "${skip[@]}"
    not_run+=("the ${#release_userns_tests[@]} release tests that run the release build in a user namespace: that no test hook answers an approval, a passphrase or sudo for it (without a terminal it refuses) or moves its files, that it ignores HOME and XDG_* and takes its home from passwd, and that without a passwd home it runs nothing ($why)")
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
bash -n box/to-disk.sh
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
