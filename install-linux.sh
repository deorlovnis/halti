#!/bin/sh
# Build halti and install it as /usr/local/bin/halti on Linux, owned by root so nothing running as
# you can replace it. Run ./check.sh on this machine first, and install only where it passes.
# `./install-linux.sh --dry-run` only says what it would do.
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

case "${1:-}" in
  --dry-run)
    cat <<DRY
would build target/release/halti and install it only if it has no test hooks
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

cargo build --release
info=$(target/release/halti build-info)
if ! printf '%s\n' "$info" | grep -qx 'debug_assertions=false halti_dev=false'; then
  echo "install-linux.sh: target/release/halti has the test hooks; not installing it" >&2
  exit 1
fi
if ! printf '%s\n' "$info" | grep -qx "verified: linux-$(uname -m)"; then
  echo "install-linux.sh: check.sh doesn't build and test halti on $(uname -m) Linux; not installing it" >&2
  exit 1
fi
echo "Installing $dest (sudo asks for your password)."
sudo install -d -o root -g root -m 755 "$(dirname "$dest")"
sudo install -o root -g root -m 755 target/release/halti "$dest"
echo "installed $dest"
echo "note: boxes don't run on Linux yet; workspaces do" >&2

if [ "$sudo_asks" = no ]; then
  echo "warning: $user can use sudo without a password. a program running as $user, or an agent that breaks out of a box, is then root on this server. see the README: sudo" >&2
fi
swap=$(clear_swap | paste -sd, - | sed 's/,/, /g')
if [ -n "$swap" ]; then
  echo "warning: this server has swap that is not encrypted ($swap). tokens and workspace keys can be written to it. turn it off with: sudo swapoff -a, and remove it from /etc/fstab" >&2
fi
