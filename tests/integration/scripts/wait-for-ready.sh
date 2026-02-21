#!/usr/bin/env bash
# wait-for-ready.sh — Poll agent readyz (eBPF loaded check)
#
# Usage: wait-for-ready.sh [--port 18080] [--host 127.0.0.1] [--max-attempts 30]
set -euo pipefail

HOST="127.0.0.1"
PORT="18080"
MAX_ATTEMPTS="30"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    HOST="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

URL="http://${HOST}:${PORT}/readyz"
DELAY=0.5
MAX_DELAY=10
ATTEMPT=1

echo "Waiting for agent readiness at ${URL} (max ${MAX_ATTEMPTS} attempts)..."

while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    RESPONSE="$(curl -sf --max-time 5 "$URL" 2>/dev/null)" || true

    if [ -n "$RESPONSE" ]; then
        EBPF_LOADED="$(echo "$RESPONSE" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
        STATUS="$(echo "$RESPONSE" | jq -r '.status' 2>/dev/null)" || true

        if [ "$EBPF_LOADED" = "true" ]; then
            echo "Agent is ready — eBPF programs loaded (attempt ${ATTEMPT}/${MAX_ATTEMPTS})"
            exit 0
        fi

        echo "  attempt ${ATTEMPT}/${MAX_ATTEMPTS} — status=${STATUS} ebpf_loaded=${EBPF_LOADED}"
    else
        echo "  attempt ${ATTEMPT}/${MAX_ATTEMPTS} — no response"
    fi

    sleep "$DELAY"
    DELAY="$(awk "BEGIN { d = $DELAY * 2; print (d > $MAX_DELAY) ? $MAX_DELAY : d }")"
    ATTEMPT=$((ATTEMPT + 1))
done

echo "ERROR: Agent readyz never reached ebpf_loaded=true after ${MAX_ATTEMPTS} attempts" >&2
exit 1
