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

run_worker() {
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
    -e LAZYTEAM_PI_AUTO_UPDATE=0 \
    -v "$state_volume:/app/state" \
    -v "$workspace_volume:/app/workspaces" \
    "$image" "$@" 2>&1
}

run_probe() {
  run_worker lazyteam-worker --sandbox-diagnose
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

# Exercise OpenCode through the real worker entrypoint + AgentSandbox, not by
# calling the bundled CLI directly. Run twice on persisted state; between runs
# deliberately make the backend home private to catch cross-task UID regressions.
attempt=1
while [ "$attempt" -le 2 ]; do
  set +e
  opencode_output="$(run_worker lazyteam-worker --opencode-capabilities-diagnose)"
  status=$?
  set -e
  printf '%s\n' "$opencode_output"
  if [ "$status" -ne 0 ]; then
    compact="$(printf '%s' "$opencode_output" | tail -c 4000 | tr '\r\n' '  ')"
    echo "::error title=Worker OpenCode sandbox smoke failed on attempt $attempt::$compact"
    exit "$status"
  fi
  printf '%s\n' "$opencode_output" | grep -F '"probe_error": null' >/dev/null || {
    echo "::error title=Worker OpenCode sandbox smoke failed::capability probe returned an error"
    exit 1
  }
  printf '%s\n' "$opencode_output" | grep -F '"provider": "opencode"' >/dev/null || {
    echo "::error title=Worker OpenCode sandbox smoke failed::no opencode provider models returned"
    exit 1
  }

  if [ "$attempt" -eq 1 ]; then
    docker run --rm \
      -v "$state_volume:/app/state" \
      --entrypoint sh \
      "$image" -c 'mkdir -p /app/state/opencode-home/.opencode && chmod 0700 /app/state/opencode-home /app/state/opencode-home/.opencode'
  fi
  attempt=$((attempt + 1))
done

# Headless implementation agents must be able to make an actual file edit
# through LazyTeam's OpenCodeRuntime + AgentSandbox, not by calling the CLI
# directly. This also exercises the build/auto permission policy.
set +e
write_output="$(run_worker lazyteam-worker --opencode-run-diagnose)"
write_status=$?
set -e
printf '%s\n' "$write_output"
if [ "$write_status" -ne 0 ]; then
  compact="$(printf '%s' "$write_output" | tail -c 4000 | tr '\r\n' '  ')"
  echo "::error title=Worker OpenCode write smoke failed::$compact"
  exit "$write_status"
fi
printf '%s\n' "$write_output" | grep -F 'OpenCode run diagnostic PASS model=opencode/' >/dev/null || {
  echo "::error title=Worker OpenCode write smoke failed::runtime did not report a successful sandbox write"
  exit 1
}
