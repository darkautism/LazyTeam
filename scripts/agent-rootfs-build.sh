#!/usr/bin/env bash
set -euo pipefail
export PATH="${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 STATE_DIR [rust|python|node|go|gcc|cpp|clang|java|cmake|ruby|php ...]" >&2
  exit 2
fi

state_dir="$(cd "$1" && pwd)"
shift
ubuntu_version="${LAZYTEAM_UBUNTU_VERSION:-24.04.3}"
preseed_archive="${LAZYTEAM_UBUNTU_BASE_ARCHIVE:-}"
base_id="${LAZYTEAM_UBUNTU_BASE_ID:-$ubuntu_version}"
root="$state_dir/agent-rootfs"
cache="$root/cache"
generations="$root/generations"

case "$(uname -m)" in
  aarch64|arm64) ubuntu_arch=arm64 ;;
  x86_64|amd64) ubuntu_arch=amd64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

declare -A requested=()
for capability in "$@"; do
  case "$capability" in
    rust|python|node|go|gcc|cpp|clang|java|cmake|ruby|php) requested["$capability"]=1 ;;
    *) echo "unknown managed capability: $capability" >&2; exit 2 ;;
  esac
done

mapfile -t capabilities < <(printf '%s\n' "${!requested[@]}" | sed '/^$/d' | sort)

rust_version_number() {
  grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$1" | head -n 1
}

rust_version_at_least() {
  local have="$1" want="$2"
  local IFS=.
  local -a h=() w=()
  read -ra h <<<"$have"
  read -ra w <<<"$want"
  local i hn wn
  for i in 0 1 2; do
    hn="${h[$i]:-0}"; wn="${w[$i]:-0}"
    if (( 10#$hn > 10#$wn )); then return 0; fi
    if (( 10#$hn < 10#$wn )); then return 1; fi
  done
  return 0
}

resolve_rust_key() {
  local requested="$1"
  if [[ "$requested" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    printf '%s\n' "$requested"
    return 0
  fi
  if [[ "$requested" != "stable" ]]; then
    echo "unsupported LAZYTEAM_RUST_TOOLCHAIN=$requested (expected stable or a pinned numeric version)" >&2
    return 2
  fi
  local manifest rustc_line concrete
  if manifest="$(curl --retry 2 --retry-delay 1 --retry-all-errors -fsSL https://static.rust-lang.org/dist/channel-rust-stable.toml)"; then
    rustc_line="$(awk '/^\[pkg\.rustc\]/{found=1} found && /^version = "/{print; exit}' <<<"$manifest")"
    concrete="$(rust_version_number "$rustc_line")"
    if [[ "$concrete" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s\n' "$concrete"
      return 0
    fi
  fi
  local recorded="$root/current/.lazyteam-rust-version"
  if [[ -r "$recorded" ]]; then
    concrete="$(tr -d '[:space:]' < "$recorded")"
    if [[ "$concrete" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
      echo "Rust stable manifest unavailable; reusing installed concrete version $concrete" >&2
      printf '%s\n' "$concrete"
      return 0
    fi
  fi
  echo "could not resolve Rust stable to a concrete version and no installed version is available" >&2
  return 1
}

rust_request="none"
rust_key="none"
if [[ -n "${requested[rust]:-}" ]]; then
  rust_request="${LAZYTEAM_RUST_TOOLCHAIN:-stable}"
  rust_key="$(resolve_rust_key "$rust_request")"
  rust_version_at_least "$rust_key" "1.85" || {
    echo "managed Rust $rust_key is below the edition-2024 floor 1.85" >&2
    exit 1
  }
fi

mkdir -p "$cache" "$generations"
name="ubuntu-base-${ubuntu_version}-base-${ubuntu_arch}.tar.gz"
release_base="https://cdimage.ubuntu.com/ubuntu-base/releases/${ubuntu_version%.*}/release"
archive="$cache/$name"

for cmd in tar sha256sum unshare mount chroot; do
  command -v "$cmd" >/dev/null || { echo "missing required host tool: $cmd" >&2; exit 2; }
done

if [[ -n "$preseed_archive" ]]; then
  [[ -r "$preseed_archive" ]] || { echo "preseeded Ubuntu rootfs archive is not readable: $preseed_archive" >&2; exit 2; }
  archive="$preseed_archive"
  if [[ -r "$archive.sha256" ]]; then
    base_hash="$(tr -d '[:space:]' < "$archive.sha256")"
  else
    base_hash="$(sha256sum "$archive" | awk '{print $1}')"
  fi
else
  command -v curl >/dev/null || { echo "missing required host tool: curl" >&2; exit 2; }
  if [[ ! -f "$archive" ]]; then
    curl --retry 3 --retry-delay 2 --retry-all-errors -fL "$release_base/$name" -o "$archive.tmp"
    mv "$archive.tmp" "$archive"
  fi
  curl --retry 3 --retry-delay 2 --retry-all-errors -fsSL "$release_base/SHA256SUMS" -o "$cache/SHA256SUMS"
  (
    cd "$cache"
    grep " \*$name\|  $name$" SHA256SUMS | sha256sum -c -
  )
  base_hash="$(grep " \*$name\|  $name$" "$cache/SHA256SUMS" | awk '{print $1}' | head -n 1)"
  [[ -n "$base_hash" ]] || { echo "could not read Ubuntu base digest for $name" >&2; exit 1; }
  printf '%s\n' "$base_hash" > "$archive.sha256"
fi

# Generation identity is content-derived, not manually versioned. Any builder
# logic change or base-rootfs content change automatically selects a new
# generation; unchanged inputs reuse the existing one.
builder_hash="$(sha256sum "$0" | awk '{print $1}')"
[[ "$base_hash" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "invalid Ubuntu base digest: $base_hash" >&2; exit 1; }
cap_key="$(printf '%s\n' "$base_id" "$ubuntu_arch" "$builder_hash" "$base_hash" "${capabilities[@]}" "rust:$rust_key" | sha256sum | cut -c1-20)"
generation="$generations/$ubuntu_version-$ubuntu_arch-$cap_key"
rootfs="$generation/rootfs"
ready="$generation/.ready"

if [[ -f "$ready" && -x "$rootfs/bin/bash" ]]; then
  ln -sfn "$rootfs" "$root/current.new"
  mv -Tf "$root/current.new" "$root/current"
  printf '%s\n' "$rootfs"
  exit 0
fi

staging="$generation.tmp-$$"
rm -rf "$staging"
mkdir -p "$staging/rootfs"
tar --no-same-owner -xzf "$archive" -C "$staging/rootfs"

packages=()
intuitive_packages=(bash ca-certificates coreutils curl diffutils file findutils gawk git grep gzip jq patch procps python3 ripgrep sed tar unzip)
if [[ -z "$preseed_archive" ]]; then
  packages+=("${intuitive_packages[@]}")
fi
for capability in "${capabilities[@]}"; do
  case "$capability" in
    rust) [[ -n "$preseed_archive" ]] || packages+=(build-essential pkg-config curl ca-certificates) ;;
    python) packages+=(python3 python3-pip python3-venv) ;;
    node) packages+=(nodejs npm) ;;
    go) packages+=(golang-go) ;;
    gcc) packages+=(gcc make pkg-config) ;;
    cpp) packages+=(g++ make cmake ninja-build pkg-config) ;;
    clang) packages+=(clang lld llvm make pkg-config) ;;
    java) packages+=(default-jdk-headless) ;;
    cmake) packages+=(cmake ninja-build) ;;
    ruby) packages+=(ruby-full) ;;
    php) packages+=(php-cli php-mbstring php-xml) ;;
  esac
done

rootfs_stage="$staging/rootfs"
if [[ -n "$preseed_archive" ]]; then
  for required in git python3 rg jq patch diff curl; do
    if [[ ! -x "$rootfs_stage/usr/bin/$required" && ! -x "$rootfs_stage/bin/$required" ]]; then
      packages+=("${intuitive_packages[@]}")
      break
    fi
  done
fi
mapfile -t packages < <(printf '%s\n' "${packages[@]}" | sed '/^$/d' | sort -u)
mkdir -p "$rootfs_stage/proc" "$rootfs_stage/dev" "$rootfs_stage/etc" "$rootfs_stage/tmp"
chmod 1777 "$rootfs_stage/tmp"
rm -f "$rootfs_stage/etc/resolv.conf" "$rootfs_stage/etc/hosts"
cp -L /etc/resolv.conf "$rootfs_stage/etc/resolv.conf"
cp -L /etc/hosts "$rootfs_stage/etc/hosts"
for device in null zero full random urandom; do
  [[ -e "$rootfs_stage/dev/$device" ]] || touch "$rootfs_stage/dev/$device"
done

namespace_args=(--user --map-root-user --mount --pid --fork)
if [[ "${LAZYTEAM_TRUSTED_CONTAINER_DAEMON:-}" == "1" ]]; then
  namespace_args=(--mount --pid --fork)
fi

if (( ${#packages[@]} > 0 )); then
  package_args="$(printf '%q ' "${packages[@]}")"
  export LAZYTEAM_BUILD_ROOTFS="$rootfs_stage"
  export LAZYTEAM_BUILD_PACKAGES="$package_args"
  unshare "${namespace_args[@]}" /bin/bash -c '
    set -euo pipefail
    rootfs="$LAZYTEAM_BUILD_ROOTFS"
    mount --make-rprivate /
    mount --bind "$rootfs" "$rootfs"
    mount -t proc proc "$rootfs/proc"
    for device in null zero full random urandom; do
      mount --bind "/dev/$device" "$rootfs/dev/$device"
    done
    chroot "$rootfs" /bin/bash -lc "set -euo pipefail; export DEBIAN_FRONTEND=noninteractive; apt-get -o APT::Sandbox::User=root update; apt-get -o APT::Sandbox::User=root install -y --no-install-recommends $LAZYTEAM_BUILD_PACKAGES; apt-get clean; rm -rf /var/lib/apt/lists/*"
  '
fi

if [[ -n "${requested[rust]:-}" ]]; then
  rustup_home="$rootfs_stage/opt/lazyteam/rustup"
  cargo_home="$rootfs_stage/opt/lazyteam/cargo"
  cargo_bin="$cargo_home/bin"
  mkdir -p "$rustup_home" "$cargo_home"

  rustup_init="$staging/rustup-init.sh"
  curl --retry 3 --retry-delay 2 --retry-all-errors --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$rustup_init"
  RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home"     sh "$rustup_init" -y --profile minimal --default-toolchain "$rust_key" --no-modify-path
  rm -f "$rustup_init"

  rustc_line="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" "$cargo_bin/rustc" --version)"
  installed_rust="$(rust_version_number "$rustc_line")"
  rust_version_at_least "$installed_rust" "1.85" || {
    echo "installed managed Rust $installed_rust is below 1.85" >&2
    exit 1
  }
  [[ "$installed_rust" == "$rust_key" ]] || {
    echo "installed managed Rust $installed_rust does not match generation key $rust_key" >&2
    exit 1
  }

  check="$staging/edition2024-check"
  target="$staging/edition2024-target"
  rm -rf "$check" "$target"
  mkdir -p "$check/src"
  printf '[package]\nname = "lazyteam-edition2024-check"\nversion = "0.1.0"\nedition = "2024"\n' > "$check/Cargo.toml"
  printf 'fn main() {}\n' > "$check/src/main.rs"
  RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target"     "$cargo_bin/cargo" metadata --no-deps --format-version 1 --manifest-path "$check/Cargo.toml" >/dev/null
  rm -rf "$check" "$target"
fi

printf '%s\n' "${capabilities[@]}" > "$rootfs_stage/.lazyteam-capabilities"
printf '%s\n' "$base_id" > "$rootfs_stage/.lazyteam-ubuntu-version"
printf '%s\n' "$builder_hash" > "$rootfs_stage/.lazyteam-builder-sha256"
printf '%s\n' "$base_hash" > "$rootfs_stage/.lazyteam-base-sha256"
printf '%s\n' "$rust_request" > "$rootfs_stage/.lazyteam-rust-request"
printf '%s\n' "$rust_key" > "$rootfs_stage/.lazyteam-rust-version"
rm -rf "$generation"
mv "$staging" "$generation"
touch "$ready"
ln -sfn "$rootfs" "$root/current.new"
mv -Tf "$root/current.new" "$root/current"
printf '%s\n' "$rootfs"
