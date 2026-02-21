#!/usr/bin/env bash
# wait-for-agent.sh — Poll agent healthz with exponential backoff
#
# Usage: wait-for-agent.sh [--proto https] [--port 8080] [--host 127.0.0.1]
#                          [--endpoint /healthz] [--max-attempts 20] [--ca-cert ca.pem]
set -euo pipefail

PROTO="http"
HOST="127.0.0.1"
PORT="18080"
ENDPOINT="/healthz"
MAX_ATTEMPTS="20"
CA_CERT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proto)   PROTO="$2"; shift 2 ;;
        --host)    HOST="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        --ca-cert) CA_CERT="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

URL="${PROTO}://${HOST}:${PORT}${ENDPOINT}"
DELAY=0.2
MAX_DELAY=10
ATTEMPT=1

echo "Waiting for agent at ${URL} (max ${MAX_ATTEMPTS} attempts)..."

while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    CURL_ARGS=(-sf --max-time 5 "$URL")
    if [ -n "$CA_CERT" ]; then
        CURL_ARGS=(--cacert "$CA_CERT" "${CURL_ARGS[@]}")
    fi

    if curl "${CURL_ARGS[@]}" >/dev/null 2>&1; then
        echo "Agent is healthy (attempt ${ATTEMPT}/${MAX_ATTEMPTS})"
        exit 0
    fi

    echo "  attempt ${ATTEMPT}/${MAX_ATTEMPTS} — not ready, retrying in ${DELAY}s..."
    sleep "$DELAY"
    DELAY="$(awk "BEGIN { d = $DELAY * 2; print (d > $MAX_DELAY) ? $MAX_DELAY : d }")"
    ATTEMPT=$((ATTEMPT + 1))
done

echo "ERROR: Agent failed to become healthy after ${MAX_ATTEMPTS} attempts" >&2
exit 1
