#!/bin/sh
set -eu

case "${1:-}" in
  models)
    printf '%s\n' 'opencode/smoke-free'
    ;;
  run)
    args=" $* "
    case "$args" in *' --format json '*) ;; *) echo 'missing --format json' >&2; exit 64;; esac
    case "$args" in *' --agent build '*) ;; *) echo 'missing --agent build' >&2; exit 65;; esac
    case "$args" in *' --auto '*) ;; *) echo 'missing --auto' >&2; exit 66;; esac
    case "$args" in *' --model opencode/smoke-free '*) ;; *) echo 'wrong model selector' >&2; exit 67;; esac
    printf 'ok\n' > opencode-write-proof.txt
    printf '%s\n' '{"type":"session.created","id":"ses_smoke"}'
    printf '%s\n' '{"type":"text","part":{"type":"text","text":"Done."}}'
    ;;
  *)
    echo "unsupported fake OpenCode command: ${1:-}" >&2
    exit 68
    ;;
esac
