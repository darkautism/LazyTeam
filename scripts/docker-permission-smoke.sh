#!/bin/sh
set -eu

IMAGE="${1:-lazyteam:ci}"

run_case() {
  name="$1"
  port="$2"
  data_mount="$3"
  workspace_mount="$4"

  docker run -d --name "$name" \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add SETGID \
    --cap-add SETUID \
    --security-opt no-new-privileges:true \
    -p "127.0.0.1:$port:8787" \
    -v "$data_mount:/app/data" \
    -v "$workspace_mount:/app/workspaces" \
    -e LAZYTEAM_LISTEN=0.0.0.0:8787 \
    -e LAZYTEAM_DATABASE_URL=sqlite:///app/data/lazyteam.db?mode=rwc \
    -e LAZYTEAM_PRODUCTION=true \
    -e LAZYTEAM_PUBLIC_URL=https://lazyteam.example.test \
    -e LAZYTEAM_OAUTH_PASSWORD=smoke-security-password-1234 \
    -e LAZYTEAM_ADMIN_TOKEN=admin-security-smoke-token-0123456789abcdef \
    -e LAZYTEAM_WORKER_TOKEN=worker-security-smoke-token-0123456789abcdef \
    -e LAZYTEAM_ALLOWED_OAUTH_CLIENT_HOSTS=chatgpt.com,*.chatgpt.com \
    -e LAZYTEAM_ALLOWED_REDIRECT_HOSTS=chatgpt.com,*.chatgpt.com \
    "$IMAGE" >/dev/null

  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$port/health" >/dev/null; then
      return 0
    fi
    sleep 1
  done

  docker logs "$name"
  return 1
}

process_uid() {
  docker exec "$1" sh -c "awk '/^Uid:/{print \$2}' /proc/1/status"
}

process_caps() {
  docker exec "$1" sh -c "awk '/^CapEff:/{print \$2}' /proc/1/status"
}

root_data="$(mktemp -d)"
root_workspaces="$(mktemp -d)"
sudo chown 0:0 "$root_data" "$root_workspaces"
run_case lazyteam-perm-root 8877 "$root_data" "$root_workspaces"
test "$(process_uid lazyteam-perm-root)" = "10001"
test "$(process_caps lazyteam-perm-root)" = "0000000000000000"
test "$(sudo stat -c '%u' "$root_data/lazyteam.db")" = "10001"
docker rm -f lazyteam-perm-root >/dev/null

nas_data="$(mktemp -d)"
nas_workspaces="$(mktemp -d)"
sudo chown 568:568 "$nas_data" "$nas_workspaces"
run_case lazyteam-perm-568 8878 "$nas_data" "$nas_workspaces"
test "$(process_uid lazyteam-perm-568)" = "568"
test "$(sudo stat -c '%u' "$nas_data/lazyteam.db")" = "568"
docker rm -f lazyteam-perm-568 >/dev/null

data_volume="lazyteam-perm-data-$$"
workspace_volume="lazyteam-perm-workspaces-$$"
docker volume create "$data_volume" >/dev/null
docker volume create "$workspace_volume" >/dev/null
run_case lazyteam-perm-volume 8879 "$data_volume" "$workspace_volume"
test "$(process_uid lazyteam-perm-volume)" = "10001"
test "$(process_caps lazyteam-perm-volume)" = "0000000000000000"
docker rm -f lazyteam-perm-volume >/dev/null
docker volume rm "$data_volume" "$workspace_volume" >/dev/null

echo "Docker permission smoke passed: root bind, TrueNAS 568 bind, named volumes"
