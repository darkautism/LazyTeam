#!/bin/sh
set -eu

image="${1:-lazyteam-worker:release-candidate}"

docker run --rm "$image" lazyteam-worker --help >/dev/null

set +e
output="$(
  docker run --rm \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    --tmpfs /app/state:size=2g,mode=0755 \
    --tmpfs /app/workspaces:size=512m,mode=0755 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add SYS_ADMIN \
    --cap-add SETGID \
    --cap-add SETUID \
    --security-opt no-new-privileges=true \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    "$image" lazyteam-worker --sandbox-diagnose 2>&1
)"
status=$?
set -e
printf '%s\n' "$output"

if [ "$status" -ne 0 ]; then
  compact="$(printf '%s' "$output" | tail -c 4000 | tr '\r\n' '  ')"
  echo "::error title=Worker container sandbox failed::$compact"
  exit "$status"
fi

case "$output" in
  *"LazyTeam agent sandbox ready"*) ;;
  *)
    compact="$(printf '%s' "$output" | tail -c 4000 | tr '\r\n' '  ')"
    echo "::error title=Worker container sandbox incomplete::$compact"
    exit 1
    ;;
esac
