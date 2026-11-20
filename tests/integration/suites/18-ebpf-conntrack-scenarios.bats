#!/usr/bin/env bats
# 18-ebpf-conntrack-scenarios.bats - Connection tracking eBPF scenario tests
# Requires: root, kernel >= 6.12, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/wire_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ct-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-conntrack.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ct-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── TC program attachment ────────────────────────────────────────

@test "TC conntrack program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── Conntrack status ─────────────────────────────────────────────

@test "conntrack status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Connection tracking ──────────────────────────────────────────

# _ct_flow_count <port> - how many tracked connections the agent lists toward
# <port> from the test client. The listing is bounded by `limit`, and the
# table is the host's (the SSH session and the test's own API calls are in it
# too), so the limit is set well past what a test host carries.
_ct_flow_count() {
    local port="$1" conns
    conns="$(api_get '/api/v1/conntrack/connections?limit=65536')" || return 1
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || return 1
    echo "${conns}" | jq --argjson port "${port}" '
        [ (if type == "array" then . else (.connections // []) end)[]
          | select(.dst_port == $port and .protocol == 6) ] | length
    '
}

# _ct_open_flow <port> <payload> - complete one TCP conversation toward
# <port> on the agent side, so the kernel tracks it.
_ct_open_flow() {
    local port="$1" payload="$2"
    wire_start_listener "${port}"
    send_tcp_from_ns "$EBPF_HOST_IP" "${port}" "${payload}" 2
    wire_stop_listeners
}

@test "TCP connection creates conntrack entry" {
    require_root
    require_tool ncat

    _ct_open_flow 9876 "CONNTRACK_TEST"

    # A closed connection stays in the table through TIME_WAIT, so the entry
    # is there to be listed for minutes after the conversation ended.
    local count=0 attempt=0
    while [ "${attempt}" -lt 10 ]; do
        count="$(_ct_flow_count 9876)" || count=0
        [ "${count:-0}" -ge 1 ] && break
        sleep 1
        attempt=$((attempt + 1))
    done
    [ "${count:-0}" -ge 1 ] || {
        echo "no tracked connection toward :9876 after a completed conversation" >&2
        api_get '/api/v1/conntrack/connections?limit=65536' >&2 || true
        return 1
    }
}

@test "conntrack connection count reflects active connections" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # A table nobody could read answers null rather than zero, so the count
    # is a reading only where conntrack is on and the kernel table was read.
    # Null with conntrack enabled is a failed read, not an idle host.
    local enabled count
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    count="$(echo "$body" | jq -r '.connection_count' 2>/dev/null)" || true
    if [ "$enabled" = "true" ]; then
        [ "$count" != "null" ] || {
            echo "conntrack is enabled but the table reported no count: ${body}" >&2
            return 1
        }
        [[ "$count" =~ ^[0-9]+$ ]]
    else
        [ "$count" = "null" ]
    fi
}

# ── Metrics ──────────────────────────────────────────────────────

@test "conntrack metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets"
}

@test "Conntrack max connections configurable" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Verify the status response includes capacity/limit fields
    local max_connections
    max_connections="$(echo "$body" | jq -r '.max_connections // .capacity // .limit // empty' 2>/dev/null)" || true
    [ -n "$max_connections" ]
    [ "$max_connections" != "null" ]
}

@test "Conntrack flush clears connections" {
    require_root
    require_tool ncat

    # A port of its own, so the entry an earlier test left in TIME_WAIT is
    # not what this one reads as its precondition.
    _ct_open_flow 9877 "CT_PRE_FLUSH"

    local present=0 attempt=0
    while [ "${attempt}" -lt 10 ]; do
        present="$(_ct_flow_count 9877)" || present=0
        [ "${present:-0}" -ge 1 ] && break
        sleep 1
        attempt=$((attempt + 1))
    done
    [ "${present:-0}" -ge 1 ] || {
        echo "precondition: the flow to :9877 is not tracked before the flush" >&2
        return 1
    }

    local body
    body="$(api_post /api/v1/conntrack/flush '{}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local flushed
    flushed="$(echo "$body" | jq -r '.flushed' 2>/dev/null)" || flushed=""
    [[ "$flushed" =~ ^[0-9]+$ ]] && [ "$flushed" -ge 1 ] || {
        echo "the flush reports removing nothing while a flow was tracked: ${body}" >&2
        return 1
    }

    # The table is the kernel's, shared with everything else on this host:
    # the administration SSH session and the test's own HTTP calls are
    # re-tracked the moment their next packet flows, so an empty table is not
    # something a flush can promise. The flow this test created, which sends
    # nothing more, must be gone.
    local after
    after="$(_ct_flow_count 9877)" || after=""
    [ "${after}" = "0" ] || {
        echo "the flushed flow to :9877 is still tracked (${after} entries)" >&2
        api_get '/api/v1/conntrack/connections?limit=65536' >&2 || true
        return 1
    }
}

@test "Conntrack metrics include state counters" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -q "ebpfsentinel_conntrack"
}

@test "Conntrack events endpoint opens an SSE stream" {
    require_root

    # The stream is wired at start-up when the agent reads the kernel table,
    # which the flow tests above have just shown it does: a 404 here is the
    # stream missing on a host where it must exist.
    local headers
    headers="$(curl -sI -H 'Accept: text/event-stream' --max-time 3 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/api/v1/conntrack/events" 2>&1 || true)"
    assert_contains "$headers" "text/event-stream"
}
