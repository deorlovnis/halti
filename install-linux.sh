#!/bin/sh
# Build halti and install it as /usr/local/bin/halti on Linux, owned by root so nothing running as
# you can replace it. It installs only a commit ./check.sh has passed at on this machine, with no
# changes to the files. `./install-linux.sh --dry-run` only says what it would do.
#
# It ends with a warning for each of two things that undo what root ownership gives: sudo that
# asks no password, and swap that isn't encrypted. Neither stops the install. See README "On a
# Linux server".
set -eu
cd "$(dirname "$0")"

# Names an install depends on, from src/names.rs.
config="$HOME/.config/halti"
store="$HOME/Library/Application Support/halti"
approved=/etc/halti/approved
dest=/usr/local/bin/halti

# Where cargo builds, as check.sh has it. check.sh writes the stamp last, naming the commit it
# passed at, and only when the files had no changes.
target="${CARGO_TARGET_DIR:-target}"
bin="$target/release/halti"
stamp="$target/check-passed"

case "${1:-}" in
  --dry-run)
    cat <<DRY
would build $bin and install it only if ./check.sh passed at this commit on this machine
  (with no changes to the files) and the build has no test hooks
would write, owned by root:
  $dest
would build no box image: boxes don't run on Linux yet
would warn if sudo runs without your password, or if swap that isn't encrypted is on
the installed halti keeps its own, and no others:
  files in $config
  files in $store, and workspaces in its ws folder unless your settings name another
  your approved settings, $approved/$(id -u).toml (written through sudo, when you approve them)
DRY
    exit 0
    ;;
  "") ;;
  *)
    echo "usage: ./install-linux.sh [--dry-run]" >&2
    exit 2
    ;;
esac

if [ "$(uname -s)" != Linux ]; then
  echo "install-linux.sh: this is for Linux; on a Mac, run install.sh" >&2
  exit 2
fi
# The checks below are about the user that runs halti, and root can do anything anyway.
if [ "$(id -u)" = 0 ]; then
  echo "install-linux.sh: run it as the user that runs halti, not as root" >&2
  exit 2
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "install-linux.sh: needs sudo, to install halti owned by root" >&2
  exit 1
fi

user=$(id -un)

# Before this script runs sudo itself, and ignoring a password typed recently: whether sudo would
# run anything as root without asking.
sudo_asks=yes
if sudo -n -k true 2>/dev/null; then sudo_asks=no; fi

# Whether a block device (its kernel name, as dm-1) is dm-crypt, or is mapped straight onto one, as
# LVM on LUKS is.
encrypted() {
  for d in "/sys/class/block/$1" "/sys/class/block/$1"/slaves/*; do
    case "$(cat "$d/dm/uuid" 2>/dev/null)" in CRYPT-*) return 0 ;; esac
  done
  return 1
}

# The swap that isn't encrypted, one entry of /proc/swaps per line. A swap file counts as the disk
# it is on. zram is memory, so it is left out.
clear_swap() {
  [ -r /proc/swaps ] || return 0
  tail -n +2 /proc/swaps | while read -r name type _; do
    case "$name" in /dev/zram*) continue ;; esac
    if [ "$type" = file ]; then
      dev=$(df -P "$name" 2>/dev/null | awk 'NR == 2 { print $1 }')
    else
      dev=$name
    fi
    dev=$(readlink -f "$dev" 2>/dev/null) || dev=
    if [ -z "$dev" ] || ! encrypted "${dev##*/}"; then echo "$name"; fi
  done
}

head=$(git rev-parse HEAD)
if [ -n "$(git status --porcelain)" ]; then
  echo "install-linux.sh: the files have changes since the last commit; commit or undo them, then run ./check.sh" >&2
  exit 1
fi
if [ "$(cat "$stamp" 2>/dev/null)" != "$head" ]; then
  echo "install-linux.sh: ./check.sh hasn't passed at this commit on this machine; run it, then install" >&2
  exit 1
fi

cargo build --release
info=$("$bin" build-info)
if ! printf '%s\n' "$info" | grep -qx 'debug_assertions=false halti_dev=false'; then
  echo "install-linux.sh: $bin has the test hooks; not installing it" >&2
  exit 1
fi
if [ "$sudo_asks" = yes ]; then
  echo "Installing $dest (sudo may ask for your password)."
else
  echo "Installing $dest."
fi
sudo install -d -o root -g root -m 755 "$(dirname "$dest")"
sudo install -o root -g root -m 755 "$bin" "$dest"
echo "installed $dest"
echo "note: boxes don't run on Linux yet; workspaces do" >&2

if [ "$sudo_asks" = no ]; then
  echo "warning: $user can use sudo without a password, so any program running as $user is root here; see README \"On a Linux server\"" >&2
fi
swap=$(clear_swap | paste -sd, - | sed 's/,/, /g')
if [ -n "$swap" ]; then
  echo "warning: swap that isn't encrypted is on ($swap): tokens and workspace keys can reach it; turn it off with sudo swapoff -a and remove it from /etc/fstab" >&2
fi
