#!/bin/sh
set -eu

image="${1:-lazyteam-worker:release-candidate}"
state_volume="lazyteam-worker-smoke-state-$$"
workspace_volume="lazyteam-worker-smoke-workspaces-$$"

cleanup() {
  docker volume rm -f "$state_volume" "$workspace_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker volume create "$state_volume" >/dev/null
docker volume create "$workspace_volume" >/dev/null

run_probe() {
  docker run --rm \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FSETID \
    --cap-add FOWNER \
    --cap-add KILL \
    --cap-add SYS_ADMIN \
    --cap-add SYS_CHROOT \
    --cap-add SETGID \
    --cap-add SETUID \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    -v "$state_volume:/app/state" \
    -v "$workspace_volume:/app/workspaces" \
    "$image" lazyteam-worker --sandbox-diagnose 2>&1
}

# Run twice against the same persisted worker state. The first sandbox probe
# transfers task-local paths to an isolated UID; the second proves the trusted
# daemon can safely reclaim/manage that state after a restart.
attempt=1
while [ "$attempt" -le 2 ]; do
  set +e
  output="$(run_probe)"
  status=$?
  set -e
  printf '%s\n' "$output"

  if [ "$status" -ne 0 ]; then
    compact="$(printf '%s' "$output" | tail -c 4000 | tr '\r\n' '  ')"
    echo "::error title=Worker container sandbox failed on startup $attempt::$compact"
    exit "$status"
  fi

  case "$output" in
    *"LazyTeam agent sandbox ready"*) ;;
    *)
      compact="$(printf '%s' "$output" | tail -c 4000 | tr '\r\n' '  ')"
      echo "::error title=Worker container sandbox incomplete on startup $attempt::$compact"
      exit 1
      ;;
  esac
  attempt=$((attempt + 1))
done
