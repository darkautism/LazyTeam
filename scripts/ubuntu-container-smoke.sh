#!/usr/bin/env bash
set -euo pipefail

UBUNTU_VERSION="${LAZYTEAM_UBUNTU_VERSION:-24.04.3}"
CACHE_ROOT="${LAZYTEAM_CONTAINER_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/lazyteam/containers}"

case "$(uname -m)" in
  aarch64|arm64) UBUNTU_ARCH=arm64 ;;
  x86_64|amd64) UBUNTU_ARCH=amd64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

for cmd in curl tar sha256sum unshare chroot; do
  command -v "$cmd" >/dev/null || { echo "missing required host tool: $cmd" >&2; exit 2; }
done

name="ubuntu-base-${UBUNTU_VERSION}-base-${UBUNTU_ARCH}.tar.gz"
base="https://cdimage.ubuntu.com/ubuntu-base/releases/${UBUNTU_VERSION%.*}/release"
archive_dir="$CACHE_ROOT/ubuntu-${UBUNTU_VERSION}-${UBUNTU_ARCH}"
archive="$archive_dir/$name"
rootfs="$archive_dir/rootfs"
mkdir -p "$archive_dir"

if [[ ! -f "$archive" ]]; then
  curl -fL "$base/$name" -o "$archive.tmp"
  mv "$archive.tmp" "$archive"
fi

curl -fsSL "$base/SHA256SUMS" -o "$archive_dir/SHA256SUMS"
(
  cd "$archive_dir"
  grep " \*$name\|  $name$" SHA256SUMS | sha256sum -c -
)

if [[ ! -x "$rootfs/bin/bash" ]]; then
  rm -rf "$rootfs"
  mkdir -p "$rootfs"
  tar --no-same-owner -xzf "$archive" -C "$rootfs"
fi

unshare --user --map-root-user --mount --pid --fork   chroot "$rootfs" /bin/bash -lc '
    . /etc/os-release
    printf "container_os=%s\n" "$PRETTY_NAME"
    printf "container_arch=%s\n" "$(uname -m)"
    printf "container_uid=%s\n" "$(id -u)"
  '
