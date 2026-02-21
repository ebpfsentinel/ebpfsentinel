#!/usr/bin/env bash
# helpers.bash — Common helper functions for BATS integration tests

HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Project root detection (must run before sourcing constants.bash) ──
find_project_root() {
    local dir="${BATS_TEST_DIRNAME:-$(pwd)}"
    while [ "$dir" != "/" ]; do
        if [ -f "$dir/Cargo.toml" ] && [ -d "$dir/crates" ]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    echo "/home/maxime/Github-perso/eBPFsentinel/ebpfsentinel"
}

PROJECT_ROOT="${PROJECT_ROOT:-$(find_project_root)}"
export PROJECT_ROOT

# Source dependencies (constants.bash uses PROJECT_ROOT for AGENT_BIN)
source "${HELPERS_DIR}/constants.bash"
source "${HELPERS_DIR}/retry.bash"
source "${HELPERS_DIR}/assertions.bash"

# ── Port cleanup ──────────────────────────────────────────────────

# _kill_port_holders <port1> [port2] ...
# Kill any ebpfsentinel-agent processes listening on the given ports.
_kill_port_holders() {
    for port in "$@"; do
        local pids
        pids="$(ss -tlnp 2>/dev/null | grep ":${port} " | \
            sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u)"
        for pid in $pids; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
    done
    # Brief pause for ports to release
    if ss -tlnp 2>/dev/null | grep -qE ":($(echo "$@" | tr ' ' '|')) "; then
        sleep 0.5
    fi
}

# ── Agent lifecycle ────────────────────────────────────────────────

# start_agent <config_file> [extra_args...]
# Starts the agent in the background with the given config.
# Sets AGENT_PID and writes to AGENT_PID_FILE.
start_agent() {
    local config_file="${1:?usage: start_agent <config_file> [extra_args...]}"
    shift

    # Kill stale agent if PID file exists
    stop_agent 2>/dev/null || true

    # Kill any process still listening on our ports (catches stale agents from previous runs)
    _kill_port_holders "${AGENT_HTTP_PORT}" "${AGENT_GRPC_PORT}"

    # Wait for ports to be fully freed
    local port_wait=0
    while { ss -tlnp 2>/dev/null | grep -qE ":(${AGENT_HTTP_PORT}|${AGENT_GRPC_PORT}) "; } && [ "$port_wait" -lt 10 ]; do
        sleep 0.3
        port_wait=$((port_wait + 1))
    done

    # Ensure data directory exists
    mkdir -p "$DATA_DIR"

    "$AGENT_BIN" --config "$config_file" "$@" \
        >"$AGENT_LOG_FILE" 2>&1 &
    AGENT_PID=$!
    echo "$AGENT_PID" > "$AGENT_PID_FILE"

    # Brief pause then verify the process is still alive (catches immediate exit)
    sleep 0.3
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "Agent process exited immediately. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    fi

    # Wait for agent to be healthy (suppress curl body output)
    wait_for_agent >/dev/null || {
        echo "Agent failed to start. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

# start_agent_expect_fail <config_file> [extra_args...]
# Starts the agent and expects it to exit with non-zero.
start_agent_expect_fail() {
    local config_file="${1:?usage: start_agent_expect_fail <config_file>}"
    shift

    stop_agent 2>/dev/null || true
    mkdir -p "$DATA_DIR"

    "$AGENT_BIN" --config "$config_file" "$@" \
        >"$AGENT_LOG_FILE" 2>&1
    local exit_code=$?
    return $exit_code
}

# stop_agent
# Gracefully stops the agent via SIGTERM, falls back to SIGKILL.
stop_agent() {
    local pid=""

    if [ -f "$AGENT_PID_FILE" ]; then
        pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)"
    elif [ -n "${AGENT_PID:-}" ]; then
        pid="$AGENT_PID"
    fi

    if [ -z "$pid" ]; then
        return 0
    fi

    # Check if process is still alive
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$AGENT_PID_FILE"
        return 0
    fi

    # Graceful SIGTERM
    kill -TERM "$pid" 2>/dev/null

    # Wait for shutdown
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$AGENT_STOP_TIMEOUT" ]; do
        sleep 0.5
        waited=$((waited + 1))
    done

    # Fallback SIGKILL if still alive
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null
        sleep 0.5
    fi

    rm -f "$AGENT_PID_FILE"
    unset AGENT_PID
}

# wait_for_agent [url] [max_attempts]
# Polls the healthz endpoint until 200 or timeout.
wait_for_agent() {
    local url="${1:-${BASE_URL}/healthz}"
    local max="${2:-${RETRY_MAX_ATTEMPTS}}"

    retry "$max" curl -sf --max-time "$HTTP_TIMEOUT" "$url"
}

# wait_for_agent_tls [url] [ca_cert] [max_attempts]
wait_for_agent_tls() {
    local url="${1:-${TLS_URL}/healthz}"
    local ca_cert="${2:-${CERT_DIR}/ca.pem}"
    local max="${3:-${RETRY_MAX_ATTEMPTS}}"

    retry "$max" curl -sf --max-time "$HTTP_TIMEOUT" --cacert "$ca_cert" "$url"
}

# ── HTTP helpers ───────────────────────────────────────────────────
#
# NOTE: When calling api_get/api_post/api_delete/api_patch inside command
# substitution (e.g. body="$(api_get /path)"), HTTP_STATUS is set inside a
# subshell and lost.  Each function persists the status to $_HTTP_STATUS_FILE.
# Call _load_http_status after the substitution to recover it.

# _load_http_status — recover HTTP_STATUS lost in command substitution
_load_http_status() {
    HTTP_STATUS="$(cat "$_HTTP_STATUS_FILE" 2>/dev/null)"
}

# api_get <path> [extra_curl_args...]
# Returns the response body. HTTP status is stored in $HTTP_STATUS.
api_get() {
    local path="${1:?usage: api_get <path>}"
    shift
    local url="${BASE_URL}${path}"

    local response
    response="$(curl -s --max-time "$HTTP_TIMEOUT" -w '\n%{http_code}' "$@" "$url")"
    HTTP_STATUS="$(echo "$response" | tail -1)"
    echo "$HTTP_STATUS" > "$_HTTP_STATUS_FILE"
    echo "$response" | sed '$d'
}

# api_post <path> <json_body> [extra_curl_args...]
api_post() {
    local path="${1:?usage: api_post <path> <json_body>}"
    local body="${2:?usage: api_post <path> <json_body>}"
    shift 2
    local url="${BASE_URL}${path}"

    local response
    response="$(curl -s --max-time "$HTTP_TIMEOUT" -w '\n%{http_code}' \
        -H 'Content-Type: application/json' -d "$body" "$@" "$url")"
    HTTP_STATUS="$(echo "$response" | tail -1)"
    echo "$HTTP_STATUS" > "$_HTTP_STATUS_FILE"
    echo "$response" | sed '$d'
}

# api_delete <path> [extra_curl_args...]
api_delete() {
    local path="${1:?usage: api_delete <path>}"
    shift
    local url="${BASE_URL}${path}"

    local response
    response="$(curl -s --max-time "$HTTP_TIMEOUT" -w '\n%{http_code}' -X DELETE "$@" "$url")"
    HTTP_STATUS="$(echo "$response" | tail -1)"
    echo "$HTTP_STATUS" > "$_HTTP_STATUS_FILE"
    echo "$response" | sed '$d'
}

# api_patch <path> <json_body> [extra_curl_args...]
api_patch() {
    local path="${1:?usage: api_patch <path> <json_body>}"
    local body="${2:?usage: api_patch <path> <json_body>}"
    shift 2
    local url="${BASE_URL}${path}"

    local response
    response="$(curl -s --max-time "$HTTP_TIMEOUT" -w '\n%{http_code}' \
        -H 'Content-Type: application/json' -X PATCH -d "$body" "$@" "$url")"
    HTTP_STATUS="$(echo "$response" | tail -1)"
    echo "$HTTP_STATUS" > "$_HTTP_STATUS_FILE"
    echo "$response" | sed '$d'
}

# api_status <path> [extra_curl_args...]
# Returns only the HTTP status code.
api_status() {
    local path="${1:?usage: api_status <path>}"
    shift
    local url="${BASE_URL}${path}"

    curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" -w '%{http_code}' "$@" "$url"
}

# ── Auth helpers ───────────────────────────────────────────────────

# auth_header <token_file>
# Returns: -H "Authorization: Bearer <token>"
auth_header() {
    local token_file="${1:?usage: auth_header <token_file>}"
    local token
    token="$(cat "$token_file" 2>/dev/null)"
    echo "-H" "Authorization: Bearer ${token}"
}

# ── Cleanup helper ─────────────────────────────────────────────────

cleanup_test_env() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
