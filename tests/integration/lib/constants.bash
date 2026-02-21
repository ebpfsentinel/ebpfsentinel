#!/usr/bin/env bash
# constants.bash — Shared constants for integration tests

# ── Paths ──────────────────────────────────────────────────────────
# Check installed path first (Docker image extraction), then project build
if [ -z "${AGENT_BIN:-}" ]; then
    if [ -x /usr/local/bin/ebpfsentinel-agent ]; then
        AGENT_BIN="/usr/local/bin/ebpfsentinel-agent"
    else
        AGENT_BIN="${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
    fi
fi
FIXTURE_DIR="${FIXTURE_DIR:-${BATS_TEST_DIRNAME}/../fixtures}"
SCRIPT_DIR="${SCRIPT_DIR:-${BATS_TEST_DIRNAME}/../scripts}"
DATA_DIR="${DATA_DIR:-/tmp/ebpfsentinel-test-data}"
CERT_DIR="${CERT_DIR:-/tmp/ebpfsentinel-test-certs}"
JWT_DIR="${JWT_DIR:-/tmp/ebpfsentinel-test-jwt}"

# ── Network ────────────────────────────────────────────────────────
AGENT_HTTP_PORT="${AGENT_HTTP_PORT:-18080}"
AGENT_GRPC_PORT="${AGENT_GRPC_PORT:-50151}"
AGENT_METRICS_PORT="${AGENT_METRICS_PORT:-19090}"
AGENT_TLS_PORT="${AGENT_TLS_PORT:-18443}"
AGENT_HOST="${AGENT_HOST:-127.0.0.1}"

# ── URLs ───────────────────────────────────────────────────────────
BASE_URL="http://${AGENT_HOST}:${AGENT_HTTP_PORT}"
TLS_URL="https://${AGENT_HOST}:${AGENT_TLS_PORT}"
GRPC_ADDR="${AGENT_HOST}:${AGENT_GRPC_PORT}"

# ── Timeouts ───────────────────────────────────────────────────────
AGENT_START_TIMEOUT="${AGENT_START_TIMEOUT:-15}"
AGENT_STOP_TIMEOUT="${AGENT_STOP_TIMEOUT:-5}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-5}"
RETRY_MAX_ATTEMPTS="${RETRY_MAX_ATTEMPTS:-20}"
RETRY_INITIAL_DELAY="${RETRY_INITIAL_DELAY:-0.2}"
RETRY_MAX_DELAY="${RETRY_MAX_DELAY:-10}"

# ── Process ────────────────────────────────────────────────────────
AGENT_PID_FILE="${AGENT_PID_FILE:-/tmp/ebpfsentinel-test.pid}"
AGENT_LOG_FILE="${AGENT_LOG_FILE:-/tmp/ebpfsentinel-test.log}"

# ── HTTP status persistence (workaround for subshell variable scoping) ─
_HTTP_STATUS_FILE="/tmp/ebpfsentinel-test-http-status"
