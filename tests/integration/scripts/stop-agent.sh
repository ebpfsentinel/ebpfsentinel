#!/usr/bin/env bash
# stop-agent.sh — Gracefully stop the eBPFsentinel agent
#
# Usage: stop-agent.sh [--timeout 5]
#
# Sends SIGTERM, waits up to timeout seconds, then SIGKILL as fallback.
set -euo pipefail

TIMEOUT=5
: "${AGENT_PID_FILE:=/tmp/ebpfsentinel-test.pid}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ ! -f "$AGENT_PID_FILE" ]; then
    echo "No PID file found at ${AGENT_PID_FILE} — nothing to stop."
    exit 0
fi

PID="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true

if [ -z "$PID" ]; then
    echo "PID file is empty — cleaning up."
    rm -f "$AGENT_PID_FILE"
    exit 0
fi

if ! kill -0 "$PID" 2>/dev/null; then
    echo "Agent (PID ${PID}) is not running — cleaning up PID file."
    rm -f "$AGENT_PID_FILE"
    exit 0
fi

echo "Stopping agent (PID ${PID}) with SIGTERM..."
START_TIME="$(date +%s)"
kill -TERM "$PID" 2>/dev/null

# Wait for graceful shutdown
WAITED=0
while kill -0 "$PID" 2>/dev/null && [ "$WAITED" -lt "$TIMEOUT" ]; do
    sleep 0.5
    WAITED=$((WAITED + 1))
done

END_TIME="$(date +%s)"
ELAPSED=$((END_TIME - START_TIME))

if kill -0 "$PID" 2>/dev/null; then
    echo "WARNING: Agent did not stop in ${TIMEOUT}s — sending SIGKILL..."
    kill -KILL "$PID" 2>/dev/null || true
    sleep 0.5
    echo "Agent killed after ${ELAPSED}s."
else
    echo "Agent stopped gracefully in ${ELAPSED}s."
fi

rm -f "$AGENT_PID_FILE"
