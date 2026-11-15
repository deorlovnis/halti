#!/usr/bin/env bash
# Turns a box image that podman built into the disk a box's VM boots from on a Linux server: an
# ext4 file system in a sparse file, made without root. install-linux.sh names the result by its
# sha256 and installs it owned by root. Usage: box/to-disk.sh IMAGE OUT
#
# It runs in podman's user namespace, where the image's files have the owners the image gives them,
# root's being 0, and mkfs.ext4 -d writes those owners into the disk. An owner the image's own
# /etc/passwd or /etc/group doesn't name is written as root: such owners come from the archives the
# image unpacks (Docker's, gh's and uv's carry the ids of the machines that built them), and an id
# that nobody in the box has would otherwise own the programs the box runs as root.
set -euo pipefail

if [ $# != 2 ]; then
  echo "usage: box/to-disk.sh IMAGE OUT" >&2
  exit 2
fi
if [ "$(id -u)" != 0 ]; then
  exec podman unshare "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" "$@"
fi
image=$1
out=$2
# mkfs.ext4 is in the system's folders, which the PATH leaves out for some users.
export PATH="$PATH:/usr/sbin:/sbin"

if [ -e "$out" ] || [ -L "$out" ]; then
  echo "to-disk.sh: $out already exists" >&2
  exit 1
fi
# The image's files are copied beside the disk, not in /tmp, which may be memory.
work=$(mktemp -d "$(dirname "$out")/.to-disk.XXXXXX")
mounted=""
cleanup() {
  if [ -n "$mounted" ]; then podman image umount "$image" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
mnt=$(podman image mount "$image")
mounted=yes
tree="$work/root"
mkdir "$tree"
cp -a "$mnt/." "$tree/"
podman image umount "$image" >/dev/null
mounted=""

# The ids the image names in a file of its own: the third field of each line, where it is a number.
ids() {
  cut -d: -f3 "$tree/$1" | grep -xE '[0-9]+' || true
}
for names in etc/passwd etc/group; do
  if [ ! -f "$tree/$names" ] || [ -z "$(ids "$names")" ]; then
    echo "to-disk.sh: $image names no ids in /$names" >&2
    exit 1
  fi
done
users=() groups=()
for id in $(ids etc/passwd); do users+=(! -uid "$id"); done
for id in $(ids etc/group); do groups+=(! -gid "$id"); done
moved=$(find "$tree" -xdev \( \( "${users[@]}" \) -o \( "${groups[@]}" \) \) -print | wc -l)
find "$tree" -xdev "${users[@]}" -exec chown -h 0 {} +
find "$tree" -xdev "${groups[@]}" -exec chgrp -h 0 {} +

# Room for the file system's own blocks, and a margin; the file is sparse.
used=$(du -sm --apparent-size "$tree" | cut -f1)
size=$((used * 14 / 10 + 512))
truncate -s "${size}M" "$out"
if ! mkfs.ext4 -q -F -d "$tree" "$out"; then
  rm -f "$out"
  exit 1
fi
echo "made $out from $image: $used MB of files; $moved whose owner the image doesn't name are root's"
