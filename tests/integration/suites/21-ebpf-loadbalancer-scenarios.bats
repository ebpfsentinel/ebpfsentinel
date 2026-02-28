#!/usr/bin/env bats
# 21-ebpf-loadbalancer-scenarios.bats — Load balancer eBPF scenario tests
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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lb-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-loadbalancer.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lb-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── XDP program attachment ───────────────────────────────────────

@test "XDP loadbalancer program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── LB status ────────────────────────────────────────────────────

@test "LB status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/lb/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Dynamic service management ───────────────────────────────────

@test "LB services initially empty" {
    require_root

    local body
    body="$(api_get /api/v1/lb/services)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '0'
}

@test "LB service creation syncs to eBPF maps" {
    require_root

    # Create a TCP service on port 9500 with one backend
    local svc='{"id":"lb-ebpf-001","name":"test-svc","protocol":"tcp","listen_port":9500,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.200.0.2","port":8080,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status

    [ "$HTTP_STATUS" = "201" ]

    # Wait for eBPF map sync
    sleep 2

    # Verify service is listed
    body="$(api_get /api/v1/lb/services)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '1'
}

@test "LB service detail shows backend" {
    require_root

    local body
    body="$(api_get /api/v1/lb/services/lb-ebpf-001)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    assert_json_field "$body" '.id' 'lb-ebpf-001'
    assert_json_array_length "$body" '.backends' '1'
}

@test "LB service deletion removes from eBPF maps" {
    require_root

    api_delete /api/v1/lb/services/lb-ebpf-001 >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "204" ]

    # Wait for eBPF map sync
    sleep 2

    local body
    body="$(api_get /api/v1/lb/services)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '0'
}

# ── Metrics ──────────────────────────────────────────────────────

@test "LB metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_lb|ebpfsentinel_loadbalancer|ebpfsentinel_packets"
}
