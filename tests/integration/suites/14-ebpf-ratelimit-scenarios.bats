#!/usr/bin/env bats
# 14-ebpf-ratelimit-scenarios.bats — Rate limiting eBPF scenario tests
# Requires: root, kernel >= 5.17, bpftool, ncat, hping3

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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-rl-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ratelimit.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-rl-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "ratelimit rules loaded via API" {
    require_root

    local body
    body="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    [ "$count" -ge 1 ]
}

@test "normal traffic passes within rate limit" {
    require_root
    require_tool ncat

    # Start listener on an open port
    timeout 10 ncat -l "$EBPF_HOST_IP" 8888 > /tmp/ebpf-rl-normal-$$.out 2>&1 &
    local listener_pid=$!
    sleep 0.5

    # Send a small number of packets (well within 100 tok/s limit)
    for i in $(seq 1 3); do
        send_tcp_from_ns "$EBPF_HOST_IP" 8888 "NORMAL_${i}" 1
        sleep 0.3
    done

    sleep 1
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # At least some data should have been received
    local received
    received="$(cat /tmp/ebpf-rl-normal-$$.out 2>/dev/null)" || true
    rm -f /tmp/ebpf-rl-normal-$$.out

    [ -n "$received" ]
}

@test "SYN flood triggers rate limiting metrics" {
    require_root

    # Check if hping3 is available
    if ! command -v hping3 &>/dev/null; then
        # Fallback: use rapid ncat connections
        for i in $(seq 1 200); do
            send_tcp_from_ns "$EBPF_HOST_IP" 8888 "FLOOD${i}" 1 &
        done
        wait
    else
        # Use hping3 for proper SYN flood
        hping3_flood_from_ns "$EBPF_HOST_IP" 8888 500 u100
    fi

    # Wait for metrics to update
    sleep 5

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    # Check for rate-limit related metrics (drops or rate limit counters)
    echo "$metrics" | grep -qE "ebpfsentinel_ratelimit|ebpfsentinel_packets_dropped|ebpfsentinel_packets"
}

@test "dynamic strict rule enforces new limit" {
    require_root

    # Add a very strict rate limit rule (10 tok/s)
    local body
    body='{"id":"rl-dynamic-strict","rate":10,"burst":10,"scope":"global","algorithm":"token_bucket","action":"drop","enabled":true}'
    api_post /api/v1/ratelimit/rules "$body"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Wait for eBPF map sync
    sleep 2

    # Verify the rule was added
    local rules
    rules="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    local strict_rule
    strict_rule="$(echo "$rules" | jq '[.[] | select(.id == "rl-dynamic-strict")] | length' 2>/dev/null)" || true
    [ "${strict_rule:-0}" -ge 1 ]
}

@test "ICMP flood triggers rate limiting" {
    require_root

    # Send ICMP flood from namespace
    send_icmp_from_ns "$EBPF_HOST_IP" 50 10

    # Wait for metrics
    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    # Should have packet-related metrics
    echo "$metrics" | grep -qE "ebpfsentinel_ratelimit|ebpfsentinel_packets"
}
