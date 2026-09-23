#!/bin/sh
set -eu

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT INT TERM
mkdir -p "$root/fake-bin" "$root/runtime"

cat > "$root/bundled-pi" <<'PI'
#!/bin/sh
echo 0.85.1
PI
chmod +x "$root/bundled-pi"

cat > "$root/fake-bin/npm" <<'NPM'
#!/bin/sh
set -eu
if [ "${1:-}" = view ]; then
  echo 0.87.1
  exit 0
fi
if [ "${1:-}" = install ]; then
  prefix=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --prefix ]; then
      shift
      prefix="$1"
      break
    fi
    shift
  done
  [ -n "$prefix" ]
  mkdir -p "$prefix/node_modules/.bin"
  cat > "$prefix/node_modules/.bin/pi" <<'PI'
#!/bin/sh
echo 0.87.1
PI
  chmod +x "$prefix/node_modules/.bin/pi"
  exit 0
fi
exit 2
NPM
chmod +x "$root/fake-bin/npm"

PATH="$root/fake-bin:$PATH" \
LAZYTEAM_PI_RUNTIME_DIR="$root/runtime" \
LAZYTEAM_BUNDLED_PI_BIN="$root/bundled-pi" \
  sh deploy/pi-auto-update.sh prepare

test "$("$root/runtime/bin/pi" --version)" = 0.85.1

PATH="$root/fake-bin:$PATH" \
LAZYTEAM_PI_RUNTIME_DIR="$root/runtime" \
LAZYTEAM_BUNDLED_PI_BIN="$root/bundled-pi" \
  sh deploy/pi-auto-update.sh once

test "$("$root/runtime/bin/pi" --version)" = 0.87.1
test -x "$root/runtime/versions/0.87.1/node_modules/.bin/pi"

cat > "$root/fake-bin/npm" <<'NPM'
#!/bin/sh
exit 1
NPM
chmod +x "$root/fake-bin/npm"
set +e
PATH="$root/fake-bin:$PATH" \
LAZYTEAM_PI_RUNTIME_DIR="$root/runtime" \
LAZYTEAM_BUNDLED_PI_BIN="$root/bundled-pi" \
  sh deploy/pi-auto-update.sh once
status=$?
set -e
test "$status" -ne 0
test "$("$root/runtime/bin/pi" --version)" = 0.87.1

echo 'pi auto-update smoke: ok'
