#!/usr/bin/env bash
# The check only a Mac can run, as one command with one report: check.sh for this target, the
# tests that need hdiutil, the engine and door tests in real VMs, the Secure Enclave library, and
# the tests that need a finger. `mise run macos-check [BRANCH]` runs this.
#
#     ./macos-check.sh [--no-vm] [BRANCH]
#
# BRANCH is fetched from origin and checked out first (detached; refused with uncommitted
# changes), and the check then runs as that commit has it. --no-vm leaves out the tests that start
# VMs. The finger steps are asked about once, at the start, and run first; they are skipped in a
# VM, without an enrolled Touch ID, and when this isn't run from a terminal.
#
# Every step runs even when an earlier one failed, and a step that hangs is stopped. The report (the commit, the versions, each
# step's result and a failed step's output in full) is printed and saved under halti's store, in
# checks/. Everything here uses halti's own names, or a debug build's: where an install made by
# cred is found, its boxes, VMs and images are listed before and after, and a difference fails.
set -uo pipefail
cd "$(dirname "$0")"

usage() {
  echo "usage: ./macos-check.sh [--no-vm] [BRANCH]" >&2
  exit 2
}
vm=1
branch=
for arg in "$@"; do
  case "$arg" in
    --no-vm) vm=0 ;;
    -*) usage ;;
    *) [ -z "$branch" ] || usage; branch="$arg" ;;
  esac
done

# The branch's own macos-check.sh is the one that runs.
if [ -n "$branch" ]; then
  if [ -n "$(git status --porcelain)" ]; then
    echo "macos-check.sh: uncommitted changes here; commit or stash them before checking $branch" >&2
    exit 2
  fi
  git fetch --quiet origin "$branch" && git checkout --quiet --detach FETCH_HEAD || exit 2
  args=()
  [ "$vm" = 1 ] || args+=(--no-vm)
  MACOS_CHECK_BRANCH="$branch" exec ./macos-check.sh ${args[@]+"${args[@]}"}
fi

os="$(uname -s)"
store="$HOME/Library/Application Support/halti"
images="halti-agent halti-agent-jvm halti-agent-rust halti-browser"
work="$(mktemp -d "${TMPDIR:-/tmp}/halti-macos-check.XXXXXX")"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
commit="$(git rev-parse HEAD)"
report="$store/checks/$(date -u +%Y%m%dT%H%M%SZ)-${commit:0:7}.txt"
results=() # one "status|seconds|name|note" per step, in order
count=0
failed=0

# Whether Apple's container can run VMs now, or why not.
vm_ready() {
  command -v container >/dev/null 2>&1 || { echo "Apple's container isn't installed"; return 1; }
  container system status >/dev/null 2>&1 || { echo "container's system isn't running (container system start)"; return 1; }
}

# Whether a finger can be asked for, or why not.
finger_ready() {
  [ "$os" = Darwin ] || { echo "not macOS"; return 1; }
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" != 1 ] || { echo "this Mac is a VM (kern.hv_vmm_present=1)"; return 1; }
  bioutil -c 2>/dev/null | grep -qE '[1-9][0-9]* biometric template' || { echo "no Touch ID is enrolled"; return 1; }
  [ -t 0 ] || { echo "not run from a terminal"; return 1; }
}

# What an install made by cred has that this check must leave as it is: its boxes with their
# state and policy, its VMs and its images. Nothing when there is no such install.
cred_state() {
  command -v cred >/dev/null 2>&1 || return 0
  cred box ls 2>/dev/null | awk 'NR > 1 { print "box", $1, $2, $3 }'
  if vm_ready >/dev/null; then
    container ls -a 2>/dev/null | awk '$1 ~ /^cred-/ { print "vm", $1, $2, $5 }'
    container image ls 2>/dev/null | awk '$1 ~ /^cred-/ { print "image", $1, $2, $3 }'
  fi
}

step() {
  local name="$1" log status=pass start=$SECONDS
  shift
  count=$((count + 1))
  log="$work/$count.log"
  printf '\n== %s\n' "$name"
  if ! "$@" 2>&1 | tee "$log"; then
    status=FAIL
    failed=1
  fi
  results+=("$status|$((SECONDS - start))|$name|")
}

skip() {
  count=$((count + 1))
  printf '\n== %s\nskipped: %s\n' "$1" "$2"
  results+=("skipped|0|$1|$2")
}

# Run a command for at most $1 seconds, then stop it and everything it started and fail: a test
# that hangs must still end in a report. The command gets its own process group for that, so
# Ctrl-C is passed on to it.
limit() {
  perl -e '
    my $seconds = shift;
    defined(my $pid = fork) or die "fork: $!\n";
    if (!$pid) { setpgrp(0, 0); exec @ARGV or die "$ARGV[0]: $!\n"; }
    my $late = 0;
    my $stop = sub { kill "TERM", -$pid; sleep 2; kill "KILL", -$pid; };
    $SIG{ALRM} = sub { $late = 1; print STDERR "\nstopped: still running after $seconds seconds\n"; $stop->(); };
    $SIG{INT} = $SIG{TERM} = $stop;
    alarm $seconds;
    1 while waitpid($pid, 0) == -1 && $!{EINTR};
    exit($late || $? & 127 ? 1 : $? >> 8);
  ' "$@"
}

store_tests() {
  limit 600 cargo test --bin halti boxes:: && limit 600 cargo test --test e2e box_
}

# The first run builds the agent and browser images, which takes most of the time.
vm_tests() {
  HALTI_E2E_BOX=1 limit 1800 cargo test --test box_engine -- --ignored --nocapture &&
    HALTI_E2E_BOX=1 limit 900 cargo test --bin halti real_vm -- --ignored --nocapture
}

# HALTI_SE_FINGER=1 tells the library's tests that a finger was promised.
se_tests() {
  (cd swift && limit 600 swift build && if [ "$finger" = 1 ]; then HALTI_SE_FINGER=1 limit 600 swift test; else limit 600 swift test; fi)
}

touch_id_test() {
  HALTI_E2E_INTERACTIVE=1 limit 600 cargo test --test e2e touch_id_approval -- --ignored --nocapture --test-threads=1
}

cred_unchanged() {
  cred_state >"$work/cred-after"
  if diff "$work/cred-before" "$work/cred-after"; then
    echo "$(wc -l <"$work/cred-after" | tr -d ' ') boxes, VMs and images of the install made by cred are as they were"
  else
    echo "the install made by cred changed while this ran (< before, > after)"
    return 1
  fi
}

write_report() {
  local i=0 r status seconds name note
  mkdir -p "$(dirname "$report")"
  {
    echo "halti macos-check: $([ "$failed" = 0 ] && echo passed || echo FAILED)"
    echo
    echo "started    $started"
    echo "commit     $commit $(git log -1 --format=%s)"
    echo "branch     ${MACOS_CHECK_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}$([ -z "$(git status --porcelain)" ] || echo ' (with uncommitted changes)')"
    if [ "$os" = Darwin ]; then
      echo "macOS      $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
    else
      echo "system     $(uname -srm): not a Mac, so the Mac-only steps are skipped"
    fi
    echo "container  $(container --version 2>/dev/null || echo 'not installed')"
    echo "rust       $(rustc --version 2>/dev/null || echo 'not installed')"
    echo "halti      $(/usr/local/bin/halti --version 2>/dev/null || echo 'not installed') (/usr/local/bin/halti)"
    echo "store      $store"
    echo "images     $(vm_ready >/dev/null && container image ls 2>/dev/null | awk -v want="$images" 'BEGIN { split(want, w, " "); for (i in w) ok[w[i]] = 1 } ok[$1] && $2 == "latest" { printf "%s@%s ", $1, $3; n++ } END { if (!n) printf "none of %s is built", want }' || echo "unknown: $(vm_ready)")"
    echo
    for r in ${results[@]+"${results[@]}"}; do
      IFS='|' read -r status seconds name note <<<"$r"
      printf '%-8s %5ss  %s%s\n' "$status" "$seconds" "$name" "${note:+: $note}"
    done
    [ "$finished" = 1 ] || echo "FAIL             stopped before the end"
    for r in ${results[@]+"${results[@]}"}; do
      i=$((i + 1))
      IFS='|' read -r status seconds name note <<<"$r"
      [ -f "$work/$i.log" ] || continue
      if [ "$status" = FAIL ]; then
        printf '\n---- %s: output\n' "$name"
        cat "$work/$i.log"
      elif grep -q '^test result: ' "$work/$i.log"; then
        printf '\n---- %s: test results\n' "$name"
        grep '^test result: ' "$work/$i.log"
      fi
    done
  } >"$report" 2>&1
  printf '\n'
  cat "$report"
  printf '\nsaved as %s\n' "$report"
  rm -rf "$work"
}
finished=0
trap 'failed=1; exit 1' INT TERM
trap 'write_report' EXIT

# The one question, before anything takes time.
finger=0
if why_no_finger="$(finger_ready)"; then
  printf 'Run the steps that need your finger now (Touch ID prompts follow the first build)? [y/N] '
  read -r answer
  case "$answer" in y | Y | yes) finger=1 ;; *) why_no_finger="declined at the start" ;; esac
fi
cred_state >"$work/cred-before"

if [ "$finger" = 1 ]; then
  step "Touch ID approval in the real Keychain" touch_id_test
else
  skip "Touch ID approval in the real Keychain" "$why_no_finger"
fi

if [ ! -f swift/Package.swift ]; then
  skip "Secure Enclave library" "this commit has none (swift/Package.swift)"
elif [ "$os" != Darwin ]; then
  skip "Secure Enclave library" "not macOS"
else
  step "Secure Enclave library$([ "$finger" = 1 ] || echo " (without the finger tests: $why_no_finger)")" se_tests
fi

step "check.sh" limit 1200 ./check.sh

if [ "$os" = Darwin ]; then
  step "box stores (hdiutil)" store_tests
else
  skip "box stores (hdiutil)" "not macOS"
fi

if [ "$vm" = 0 ]; then
  skip "engine and door in real VMs" "--no-vm"
elif why_no_vm="$(vm_ready)"; then
  step "engine and door in real VMs" vm_tests
else
  skip "engine and door in real VMs" "$why_no_vm"
fi

if [ -s "$work/cred-before" ]; then
  step "the install made by cred is untouched" cred_unchanged
fi

finished=1
exit "$failed"
