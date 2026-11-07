#!/usr/bin/env bats
# 106-telemetry-heartbeat.bats - the anonymous heartbeat, received.
#
# The destination of the heartbeat is fixed when the agent is built. The
# lane's build carries a loopback endpoint (the integration workflow sets
# EBPFSENTINEL_TELEMETRY_ENDPOINT to it), so a sink on this machine stands in
# for the collector. The suite asserts:
#
#   * The first beat arrives inside the startup spread, as one JSON POST.
#   * It carries the installation identifier, the version and the load
#     state of each program, and no other field at any depth.
#   * The identifier is the one kept under `telemetry.state_path`, and an
#     agent restarted on the same state sends the same one.
#   * EBPFSENTINEL_TELEMETRY_DISABLE silences the agent entirely.
#
# Requires: root, kernel >= 6.12, jq, python3, a lane build carrying the
# loopback endpoint.

load '../lib/helpers'
load '../lib/ebpf_helpers'

SINK_PORT=18321

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 106 listens on the agent's own loopback (local lane only)"
    fi

    local bin="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    if ! grep -aq "http://127.0.0.1:${SINK_PORT}/v1/heartbeat" "$bin"; then
        echo "build it with EBPFSENTINEL_TELEMETRY_ENDPOINT=http://127.0.0.1:${SINK_PORT}/v1/heartbeat, as the integration workflow does" >&2
        soft_skip "this agent build carries no loopback telemetry endpoint: ${bin}"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-telemetry-$$"
    mkdir -p "$DATA_DIR/telemetry"
    chmod 0777 "$DATA_DIR" "$DATA_DIR/telemetry"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-telemetry-sink.yaml")"
    export PREPARED_CONFIG
}

teardown_file() {
    _stop_sink
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-telemetry-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# A collector that keeps every request it receives, one JSON line each:
# method, path, content type and body.
_start_sink() {
    _stop_sink
    : > "${DATA_DIR}/beats.jsonl"
    python3 - "$SINK_PORT" "${DATA_DIR}/beats.jsonl" <<'ENDOFSINK' >/dev/null 2>&1 &
import http.server, json, sys
port, out = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def _keep(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(out, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path,
                                "type": self.headers.get("Content-Type", ""),
                                "body": body}) + "\n")
        self.send_response(204)
        self.end_headers()
    do_POST = _keep
    do_PUT = _keep
    do_GET = _keep
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
ENDOFSINK
    echo $! > "${DATA_DIR}/sink.pid"
    local i
    for i in $(seq 1 20); do
        ss -tln 2>/dev/null | grep -q "127.0.0.1:${SINK_PORT} " && return 0
        sleep 0.2
    done
    echo "sink did not listen on ${SINK_PORT}" >&2
    return 1
}

_stop_sink() {
    if [ -f "${DATA_DIR:-/nonexistent}/sink.pid" ]; then
        kill "$(cat "${DATA_DIR}/sink.pid")" 2>/dev/null || true
        rm -f "${DATA_DIR}/sink.pid"
    fi
}

_beats() {
    grep -c . "${DATA_DIR}/beats.jsonl" 2>/dev/null || true
}

# Wait up to $1 seconds for at least one beat.
_wait_beat() {
    local i
    for i in $(seq 1 "$1"); do
        [ "$(_beats)" -ge 1 ] && return 0
        sleep 1
    done
    return 1
}

_start_agent() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        echo "eBPF programs not loaded (degraded mode)" >&2
        return 1
    }
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the first heartbeat reaches the sink as one JSON POST" {
    _start_sink
    _start_agent
    # The first beat waits at most a minute, spread by the identifier.
    _wait_beat 80 || {
        echo "no heartbeat within 80 s" >&2
        grep -i telemetry "$AGENT_LOG_FILE" | tail -5 >&2
        return 1
    }
    local req
    req="$(head -1 "${DATA_DIR}/beats.jsonl")"
    [ "$(jq -r .method <<<"$req")" = "POST" ]
    [ "$(jq -r .path <<<"$req")" = "/v1/heartbeat" ]
    jq -r .type <<<"$req" | grep -qi 'application/json'
    grep -q 'telemetry on' "$AGENT_LOG_FILE"
}

@test "the heartbeat carries the identifier, the version and program states, and nothing else" {
    local body
    body="$(head -1 "${DATA_DIR}/beats.jsonl" | jq -r .body)"
    [ -n "$body" ]
    # Exactly three fields at the top.
    [ "$(jq -c 'keys' <<<"$body")" = '["installation_id","programs","version"]' ]
    [ -n "$(jq -r .installation_id <<<"$body")" ]
    [ "$(jq -r .version <<<"$body")" != "" ]
    # Each program is its name and its state, nothing more.
    [ "$(jq '.programs | length' <<<"$body")" -ge 1 ]
    [ "$(jq -c '[.programs[] | keys] | unique' <<<"$body")" = '[["program","state"]]' ]
    jq -e '[.programs[] | select(.state == "loaded")] | length >= 1' <<<"$body" >/dev/null
    # Neither an address, an interface nor the host's name rides along.
    ! grep -q "${EBPF_VETH_HOST}" <<<"$body" || return 1
    ! grep -q "10.200.0" <<<"$body" || return 1
    ! grep -q "$(hostname)" <<<"$body" || return 1
}

@test "the identifier is the one kept on disk and survives a restart" {
    local sent kept
    sent="$(head -1 "${DATA_DIR}/beats.jsonl" | jq -r .body | jq -r .installation_id)"
    kept="$(tr -d '[:space:]' < "${DATA_DIR}/telemetry/installation")"
    [ "$sent" = "$kept" ]

    stop_ebpf_agent
    _start_sink
    _start_agent
    _wait_beat 80 || { echo "no heartbeat after restart" >&2; return 1; }
    [ "$(head -1 "${DATA_DIR}/beats.jsonl" | jq -r .body | jq -r .installation_id)" = "$sent" ]
}

@test "EBPFSENTINEL_TELEMETRY_DISABLE silences the agent" {
    stop_ebpf_agent
    _start_sink
    export EBPFSENTINEL_TELEMETRY_DISABLE=1
    _start_agent
    unset EBPFSENTINEL_TELEMETRY_DISABLE
    # Longer than the whole startup spread.
    sleep 70
    [ "$(_beats)" -eq 0 ] || { echo "a heartbeat was sent with telemetry disabled" >&2; return 1; }
    ! grep -q 'telemetry on' "$AGENT_LOG_FILE"
}
