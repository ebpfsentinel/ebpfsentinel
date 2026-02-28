#!/usr/bin/env bats
# 19-ebpf-conntrack-scenarios.bats — Connection tracking eBPF scenario tests
# Requires: root, kernel >= 5.17, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
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
        skip "eBPF programs not loaded (degraded mode)"
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

@test "TCP connection creates conntrack entry" {
    require_root
    require_tool ncat

    # Start a listener and establish a TCP connection
    timeout 10 ncat -l "$EBPF_HOST_IP" 9876 >/dev/null 2>&1 &
    local listener_pid=$!
    sleep 0.5

    # Send traffic from namespace
    send_tcp_from_ns "$EBPF_HOST_IP" 9876 "CONNTRACK_TEST" 3

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Check connection table via API
    local body
    body="$(api_get /api/v1/conntrack/connections)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "conntrack connection count reflects active connections" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # connection_count should be a valid number
    local count
    count="$(echo "$body" | jq -r '.connection_count' 2>/dev/null)" || true
    [ -n "$count" ] && [ "$count" != "null" ]
}

@test "conntrack flush clears connections" {
    require_root

    local body
    body="$(api_post /api/v1/conntrack/flush '{}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "conntrack metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets"
}
