#!/bin/sh
set -eu

DATA_DIR="${LAZYTEAM_DATA_DIR:-/app/data}"
WORKSPACE_DIR="${LAZYTEAM_WORKSPACE_DIR:-/app/workspaces}"
DEFAULT_UID="${LAZYTEAM_DEFAULT_UID:-10001}"
DEFAULT_GID="${LAZYTEAM_DEFAULT_GID:-10001}"

die() {
  echo "lazyteam-entrypoint: $*" >&2
  exit 1
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

mkdir -p "$DATA_DIR" "$WORKSPACE_DIR"

requested_uid="${LAZYTEAM_PUID:-${PUID:-}}"
requested_gid="${LAZYTEAM_PGID:-${PGID:-}}"

if [ -n "$requested_uid" ] || [ -n "$requested_gid" ]; then
  [ -n "$requested_uid" ] && [ -n "$requested_gid" ] ||
    die "set both PUID/PGID (or LAZYTEAM_PUID/LAZYTEAM_PGID), not only one"
  is_uint "$requested_uid" || die "invalid runtime UID: $requested_uid"
  is_uint "$requested_gid" || die "invalid runtime GID: $requested_gid"
  runtime_uid="$requested_uid"
  runtime_gid="$requested_gid"
  source="explicit"
else
  # Existing state is authoritative. This makes TrueNAS (commonly 568:568),
  # Unraid, Synology and ordinary bind mounts work without a PUID/PGID setting.
  if [ -e "$DATA_DIR/lazyteam.db" ]; then
    detected_uid="$(stat -c '%u' "$DATA_DIR/lazyteam.db")"
    detected_gid="$(stat -c '%g' "$DATA_DIR/lazyteam.db")"
  else
    detected_uid="$(stat -c '%u' "$DATA_DIR")"
    detected_gid="$(stat -c '%g' "$DATA_DIR")"
  fi

  if [ "$detected_uid" -ne 0 ]; then
    runtime_uid="$detected_uid"
    runtime_gid="$detected_gid"
    source="mount"
  else
    is_uint "$DEFAULT_UID" || die "invalid LAZYTEAM_DEFAULT_UID: $DEFAULT_UID"
    is_uint "$DEFAULT_GID" || die "invalid LAZYTEAM_DEFAULT_GID: $DEFAULT_GID"
    runtime_uid="$DEFAULT_UID"
    runtime_gid="$DEFAULT_GID"
    source="default"
  fi
fi

HOME_DIR="${LAZYTEAM_HOME:-$DATA_DIR/home}"
mkdir -p "$HOME_DIR"

fix_tree_if_needed() {
  path="$1"
  owner_uid="$(stat -c '%u' "$path")"
  owner_gid="$(stat -c '%g' "$path")"

  if [ "$owner_uid" -ne "$runtime_uid" ] || [ "$owner_gid" -ne "$runtime_gid" ]; then
    echo "lazyteam-entrypoint: adjusting $path ownership $owner_uid:$owner_gid -> $runtime_uid:$runtime_gid"
    chown -R "$runtime_uid:$runtime_gid" "$path" ||
      die "cannot adjust ownership of $path; check that the mount is writable and permits chown"
  fi
}

if [ "$runtime_uid" -ne 0 ]; then
  fix_tree_if_needed "$DATA_DIR"
  fix_tree_if_needed "$WORKSPACE_DIR"

  # Verify effective access instead of assuming chown/ACL semantics.
  gosu "$runtime_uid:$runtime_gid" sh -c '
    set -e
    data="$1"
    workspace="$2"
    test -w "$data"
    test -w "$workspace"
    probe="$data/.lazyteam-write-test.$$"
    : > "$probe"
    rm -f "$probe"
  ' sh "$DATA_DIR" "$WORKSPACE_DIR" ||
    die "runtime identity $runtime_uid:$runtime_gid cannot write required mounts"

  export HOME="$HOME_DIR"
  umask 027
  echo "lazyteam-entrypoint: running as $runtime_uid:$runtime_gid (auto source: $source)"
  exec gosu "$runtime_uid:$runtime_gid" "$@"
fi

export HOME="$HOME_DIR"
umask 027
echo "lazyteam-entrypoint: explicit root runtime requested"
exec "$@"
