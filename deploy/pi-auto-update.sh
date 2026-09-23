#!/bin/sh
set -eu

RUNTIME_DIR="${LAZYTEAM_PI_RUNTIME_DIR:-${LAZYTEAM_DATA_DIR:-/app/state}/pi-runtime}"
INTERVAL="${LAZYTEAM_PI_UPDATE_INTERVAL_SECS:-86400}"
PACKAGE='@earendil-works/pi-coding-agent'
BUNDLED_PI="${LAZYTEAM_BUNDLED_PI_BIN:-$(command -v pi 2>/dev/null || true)}"

log() {
  echo "lazyteam-pi-update: $*" >&2
}

valid_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

current_version() {
  target="$RUNTIME_DIR/bin/pi"
  [ -x "$target" ] || return 1
  "$target" --version 2>/dev/null | head -n 1 | tr -d '\r'
}

ensure_runtime_link() {
  mkdir -p "$RUNTIME_DIR/bin" "$RUNTIME_DIR/versions"
  [ -n "$BUNDLED_PI" ] && [ -x "$BUNDLED_PI" ] || return 1
  bundled_target="$(readlink -f "$BUNDLED_PI" 2>/dev/null || true)"
  [ -n "$bundled_target" ] && [ -x "$bundled_target" ] || bundled_target="$BUNDLED_PI"

  target="$RUNTIME_DIR/bin/pi"
  if [ ! -x "$target" ]; then
    tmp="$RUNTIME_DIR/bin/.pi-link.$$"
    rm -f "$tmp" "$target"
    ln -s "$bundled_target" "$tmp"
    mv -Tf "$tmp" "$target"
    return 0
  fi

  # Older workers linked the managed entrypoint to /usr/local/bin/pi. That
  # indirection escapes the nested Ubuntu rootfs even when the canonical Pi
  # package is admitted read-only. Normalize only the bundled-runtime case;
  # versioned managed installs under $RUNTIME_DIR remain untouched.
  current_target="$(readlink -f "$target" 2>/dev/null || true)"
  if [ -n "$current_target" ] && [ "$current_target" = "$bundled_target" ]; then
    current_link="$(readlink "$target" 2>/dev/null || true)"
    if [ "$current_link" != "$bundled_target" ]; then
      tmp="$RUNTIME_DIR/bin/.pi-link.$$"
      rm -f "$tmp"
      ln -s "$bundled_target" "$tmp"
      mv -Tf "$tmp" "$target"
    fi
  fi
}

install_latest() {
  ensure_runtime_link || {
    log "bundled Pi not found; leaving worker configuration unchanged"
    return 1
  }

  latest="$(npm view "$PACKAGE" version --silent 2>/dev/null | tr -d '\r\n')"
  case "$latest" in
    ''|*[!0-9A-Za-z.+-]*)
      log "could not resolve a safe npm version; keeping $(current_version 2>/dev/null || echo unknown)"
      return 1
      ;;
  esac

  current="$(current_version 2>/dev/null || true)"
  if [ "$current" = "$latest" ]; then
    log "Pi already current ($current)"
    return 0
  fi

  version_dir="$RUNTIME_DIR/versions/$latest"
  if [ ! -x "$version_dir/node_modules/.bin/pi" ]; then
    tmp="$RUNTIME_DIR/versions/.install-$latest-$$"
    rm -rf "$tmp"
    mkdir -p "$tmp"
    log "installing Pi $latest (current ${current:-unknown})"
    if ! npm install --prefix "$tmp" --no-audit --no-fund --omit=dev "$PACKAGE@$latest" >/dev/null 2>&1; then
      rm -rf "$tmp"
      log "npm install failed; keeping ${current:-bundled Pi}"
      return 1
    fi
    installed="$($tmp/node_modules/.bin/pi --version 2>/dev/null | head -n 1 | tr -d '\r')"
    if [ "$installed" != "$latest" ]; then
      rm -rf "$tmp"
      log "installed Pi version '$installed' did not match expected '$latest'; keeping ${current:-bundled Pi}"
      return 1
    fi
    if [ ! -e "$version_dir" ]; then
      mv "$tmp" "$version_dir"
    else
      rm -rf "$tmp"
    fi
  fi

  tmp_link="$RUNTIME_DIR/bin/.pi-link.$$"
  rm -f "$tmp_link"
  ln -s "../versions/$latest/node_modules/.bin/pi" "$tmp_link"
  mv -Tf "$tmp_link" "$RUNTIME_DIR/bin/pi"
  log "Pi switched atomically to $latest"
}

case "${1:-once}" in
  prepare)
    ensure_runtime_link
    ;;
  once)
    install_latest
    ;;
  loop)
    valid_uint "$INTERVAL" || {
      log "invalid LAZYTEAM_PI_UPDATE_INTERVAL_SECS='$INTERVAL'"
      exit 2
    }
    [ "$INTERVAL" -ge 300 ] || {
      log "LAZYTEAM_PI_UPDATE_INTERVAL_SECS must be at least 300"
      exit 2
    }
    while :; do
      sleep "$INTERVAL"
      install_latest || true
    done
    ;;
  *)
    echo "usage: $0 [prepare|once|loop]" >&2
    exit 2
    ;;
esac
