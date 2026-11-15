#!/bin/sh
# Build halti and install it as /usr/local/bin/halti on Linux, owned by root so nothing running as
# you can replace it. It installs only a commit ./check.sh has passed at on this machine, with no
# changes to the files, and names what check.sh could not run here (where the system restricts user
# namespaces, some tests can't run). `./install-linux.sh --dry-run` only says what it would do.
#
# Where boxes can run (x86-64, /dev/kvm, Linux 6.8 or newer), it also installs, owned by root, what
# they run on: the VM program and the box kernel, each checked against the sha256 that src/vmm.rs
# pins, and the agent image, built with podman and made a disk (box/to-disk.sh), named by its
# sha256. Each is checked once root has its own copy, which root makes from what your shell reads:
# root opens no file of yours. It then says whether this server can run boxes, and if not, why.
#
# It ends with a warning for each of three things that undo what root ownership gives: sudo that
# asks no password, a group that gives root without one (docker's, say), and swap that isn't
# encrypted. None stops the install. See README "On a Linux server".
set -eu
cd "$(dirname "$0")"

# Names an install depends on, from src/names.rs.
config="$HOME/.config/halti"
store="$HOME/Library/Application Support/halti"
approved=/etc/halti/approved
dest=/usr/local/bin/halti
# Where halti finds what boxes run on; install-linux.sh's tests name another folder.
lib="${HALTI_LIB_DIR:-/usr/local/lib/halti}"
agent=halti-agent

# What boxes run on, downloaded from their makers' releases and checked against src/vmm.rs's pins:
# Cloud Hypervisor v54.1 and its reference kernel.
program_url=https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/cloud-hypervisor-static
kernel_url=https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/bzImage-x86_64
# KVM's device; install-linux.sh's tests name one that isn't there.
kvm="${HALTI_KVM_DEVICE:-/dev/kvm}"

# Where cargo builds, as check.sh has it. check.sh writes the stamp last, naming the commit it
# passed at on its first line, and only when the files had no changes; each line after it names
# something check.sh could not run here, and why.
target="${CARGO_TARGET_DIR:-target}"
bin="$target/release/halti"
stamp="$target/check-passed"

case "${1:-}" in
  --dry-run)
    cat <<DRY
would build $bin and install it only if ./check.sh passed at this commit on this machine
  (with no changes to the files) and the build has no test hooks
would name what ./check.sh could not run on this machine, if anything
would write, owned by root:
  $dest
and where boxes can run (x86-64, $kvm, Linux 6.8 or newer), also owned by root:
  $lib/cloud-hypervisor and $lib/images/bzImage, downloaded and checked against src/vmm.rs's pins
  $lib/images/$agent/<sha256>.img, the agent image built with podman and made a disk
would say whether this server can run boxes, and if not, why
would warn if sudo runs without your password, if you are in a group that gives root without one
  (docker, lxd, incus-admin, libvirt, libvirtd or disk), or if swap that isn't encrypted is on
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

# Why boxes can't run here, or nothing: the line said at the end. One whose user can't use KVM yet
# still gets what boxes run on.
cannot=""
version=$(uname -r | cut -d- -f1)
major=${version%%.*}
minor=$(echo "$version" | cut -d. -f2)
case "$major.$minor" in *[!0-9.]* | .* | *.) major=0 minor=0 ;; esac
if [ "$(uname -m)" != x86_64 ]; then
  cannot="this server can't run boxes: halti pins a VM program for x86-64 servers only"
elif [ ! -e "$kvm" ]; then
  cannot="this server can't run boxes: it has no $kvm. it needs a dedicated server, or a cloud server with nested virtualization"
elif [ "$major" -lt 6 ] || { [ "$major" = 6 ] && [ "$minor" -lt 8 ]; }; then
  cannot="this server can't run boxes: cloud-hypervisor needs Linux 6.8 or newer, and this is $major.$minor"
fi
boxes=no
if [ -z "$cannot" ]; then
  boxes=yes
  for tool in curl sha256sum podman mkfs.ext4; do
    if ! PATH="$PATH:/usr/sbin:/sbin" command -v "$tool" >/dev/null 2>&1; then
      echo "install-linux.sh: boxes here need $tool (on Debian or Ubuntu: sudo apt install curl podman e2fsprogs)" >&2
      exit 1
    fi
  done
fi

# Before this script runs sudo itself, and ignoring a password typed recently: whether sudo would
# run anything as root without asking.
sudo_asks=yes
if sudo -n -k true 2>/dev/null; then sudo_asks=no; fi

# The groups the system lists for this user (one added since the last login among them) that give
# root with no password: docker, lxd and incus-admin start a container with / mounted in it,
# libvirt (libvirtd on older Debian and Ubuntu) a VM given the system's own disk, and disk writes
# the disk under the system.
root_groups=$(id -Gn "$user" 2>/dev/null | tr ' ' '\n' | grep -xE 'docker|lxd|incus-admin|libvirt|libvirtd|disk' | paste -sd, - | sed 's/,/, /g')

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
if [ "$(head -n 1 "$stamp" 2>/dev/null)" != "$head" ]; then
  echo "install-linux.sh: ./check.sh hasn't passed at this commit on this machine; run it, then install" >&2
  exit 1
fi
not_run=$(awk 'NR > 1 { printf "%s%s", sep, $0; sep = "; " }' "$stamp")

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

# The sha256 that src/vmm.rs pins for `program` or `kernel`.
pin() {
  grep -oE "$1: \"[0-9a-f]{64}\"" src/vmm.rs | head -n 1 | cut -d'"' -f2
}

# The sha256 of a file, or nothing if it can't be read.
sum_of() {
  sha256sum "$1" 2>/dev/null | cut -c1-64
}

# Whether $1 is a file of root's with mode $2, as halti wants what boxes run on: only root may
# change it.
roots() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u %a' "$1")" = "0 $2" ]
}

# Makes $1, a new file of root's with mode $3, from what this shell reads of $2, a file of yours:
# root opens nothing you could change or swap for a link, and what it wrote is checked after, in
# its own copy. Holes stay holes.
put() {
  sudo rm -f "$1"
  sudo dd of="$1" bs=1M conv=sparse status=none <"$2"
  sudo chown root:root "$1"
  sudo chmod "$3" "$1"
}

# Installs what boxes run on, each owned by root and checked against its pin, or named by its
# sha256, in root's copy.
install_boxes() {
  work=$(mktemp -d "$target/.install-boxes.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  images="$lib/images/$agent"
  sudo install -d -o root -g root -m 755 "$lib" "$lib/images" "$images"
  for part in program kernel; do
    case $part in
      program) url=$program_url file=$lib/cloud-hypervisor mode=755 what="the VM program" ;;
      kernel) url=$kernel_url file=$lib/images/bzImage mode=644 what="the box kernel" ;;
    esac
    sum=$(pin "$part")
    if [ -z "$sum" ]; then
      echo "install-linux.sh: src/vmm.rs pins no $part" >&2
      exit 1
    fi
    # One that is there is kept only if it is root's, as halti wants it, and the pinned one.
    if ! roots "$file" "$mode" || [ "$(sum_of "$file")" != "$sum" ]; then
      curl -fsSL -o "$work/$part" "$url"
      put "$file.new" "$work/$part" "$mode"
      if [ "$(sum_of "$file.new")" != "$sum" ]; then
        sudo rm -f "$file.new"
        echo "install-linux.sh: $url isn't the $part halti pins (sha256 $sum); nothing of it was installed" >&2
        exit 1
      fi
      sudo mv -f "$file.new" "$file"
    fi
    echo "installed $what (sha256 $sum)"
  done
  # The build before this one is untagged by it; its layers go, not those of other images.
  before=$(podman image inspect -f '{{.Id}}' "$agent:install" 2>/dev/null || true)
  podman build -q -f box/agent.Containerfile -t "$agent:install" box >/dev/null
  if [ -n "$before" ] && [ "$before" != "$(podman image inspect -f '{{.Id}}' "$agent:install")" ]; then
    podman rmi "$before" >/dev/null 2>&1 || true
  fi
  box/to-disk.sh "$agent:install" "$work/agent.img" >/dev/null
  put "$images/install.new" "$work/agent.img" 644
  hex=$(sum_of "$images/install.new")
  sudo mv -f "$images/install.new" "$images/$hex.img"
  echo "built the agent image $agent@sha256:$hex"
  rm -rf "$work"
  trap - EXIT
  # Earlier builds stay, for the boxes whose policies pin them; what they take is said.
  set -- $(find "$images" -maxdepth 1 -name '*.img' ! -name "$hex.img")
  if [ $# -gt 0 ]; then
    space=$(du -cm "$@" | tail -n 1 | cut -f1)
    echo "note: $# earlier agent images are in $images, using $space MB. remove each that no box policy pins, with sudo rm" >&2
  fi
}

if [ "$boxes" = yes ]; then
  install_boxes
  if [ ! -r "$kvm" ] || [ ! -w "$kvm" ]; then
    cannot="this server can't run boxes yet: you may not use $kvm. run: sudo usermod -aG kvm $user, then log in again"
  fi
fi
if [ -z "$cannot" ]; then
  echo "this server can run boxes"
else
  echo "$cannot"
fi
if [ -n "$not_run" ]; then
  echo "note: not checked on this machine: $not_run" >&2
fi

if [ "$sudo_asks" = no ]; then
  echo "warning: $user can use sudo without a password, so any program running as $user is root here; see README \"On a Linux server\"" >&2
fi
if [ -n "$root_groups" ]; then
  echo "warning: $user is in a group that gives root without a password ($root_groups), so any program running as $user is root here; see README \"On a Linux server\"" >&2
fi
swap=$(clear_swap | paste -sd, - | sed 's/,/, /g')
if [ -n "$swap" ]; then
  echo "warning: swap that isn't encrypted is on ($swap): tokens and workspace keys can reach it; turn it off with sudo swapoff -a and remove it from /etc/fstab" >&2
fi
