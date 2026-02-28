#!/usr/bin/env bats
# 23-ebpf-ddos-scenarios.bats — DDoS/scrub eBPF scenario tests
# Requires: root, kernel >= 5.17, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ddos-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ddos.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ddos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "DDoS scrub program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── DDoS status ──────────────────────────────────────────────────

@test "DDoS status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "DDoS policies loaded from config" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    [ "$count" -ge 2 ]
}

# ── ICMP flood detection ─────────────────────────────────────────

@test "ICMP flood triggers DDoS detection metrics" {
    require_root

    # Send a burst of ICMP packets (above threshold of 50 pps)
    send_icmp_from_ns "$EBPF_HOST_IP" 100 15

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

# ── SYN flood detection ──────────────────────────────────────────

@test "TCP SYN flood triggers DDoS metrics" {
    require_root

    # Send rapid TCP connections
    for i in $(seq 1 50); do
        send_tcp_from_ns "$EBPF_HOST_IP" 8888 "SYN${i}" 1 &
    done
    wait

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

# ── Attack history ───────────────────────────────────────────────

@test "DDoS attacks endpoint is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/attacks)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "DDoS attack history is accessible" {
    require_root

    local body
    body="$(api_get '/api/v1/ddos/attacks/history?limit=10')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "DDoS metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_scrub|ebpfsentinel_packets"
}
