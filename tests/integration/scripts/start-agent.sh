#!/usr/bin/env bash
# start-agent.sh — Start eBPFsentinel agent in background
#
# Usage: start-agent.sh <config_file> [extra_args...]
#
# Environment:
#   AGENT_BIN       — Path to agent binary (default: target/release/ebpfsentinel-agent)
#   AGENT_PID_FILE  — PID file location (default: /tmp/ebpfsentinel-test.pid)
#   AGENT_LOG_FILE  — Log file location (default: /tmp/ebpfsentinel-test.log)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_FILE="${1:?Usage: start-agent.sh <config_file> [extra_args...]}"
shift

# Defaults
: "${AGENT_BIN:=$(cd "$SCRIPT_DIR/../../.." && pwd)/target/release/ebpfsentinel-agent}"
: "${AGENT_PID_FILE:=/tmp/ebpfsentinel-test.pid}"
: "${AGENT_LOG_FILE:=/tmp/ebpfsentinel-test.log}"

# Kill stale process if PID file exists
if [ -f "$AGENT_PID_FILE" ]; then
    OLD_PID="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Killing stale agent (PID ${OLD_PID})..."
        kill -TERM "$OLD_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$OLD_PID" 2>/dev/null || true
    fi
    rm -f "$AGENT_PID_FILE"
fi

# Verify binary exists
if [ ! -x "$AGENT_BIN" ]; then
    echo "ERROR: Agent binary not found or not executable: ${AGENT_BIN}" >&2
    exit 1
fi

# Verify config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: ${CONFIG_FILE}" >&2
    exit 1
fi

echo "Starting agent: ${AGENT_BIN} --config ${CONFIG_FILE} $*"
echo "  PID file: ${AGENT_PID_FILE}"
echo "  Log file: ${AGENT_LOG_FILE}"

"$AGENT_BIN" --config "$CONFIG_FILE" "$@" \
    >"$AGENT_LOG_FILE" 2>&1 &
AGENT_PID=$!
echo "$AGENT_PID" > "$AGENT_PID_FILE"

echo "Agent started (PID ${AGENT_PID})"

# Quick check: is it still running after 0.5s?
sleep 0.5
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "ERROR: Agent exited immediately. Log tail:" >&2
    tail -20 "$AGENT_LOG_FILE" >&2
    rm -f "$AGENT_PID_FILE"
    exit 1
fi

echo "Agent is running."
