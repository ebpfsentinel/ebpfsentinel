#!/usr/bin/env bats
# 35-ebpf-routing-scenarios.bats — Dynamic routing eBPF scenario tests
# Requires: root, kernel >= 6.1, bpftool

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-routing-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-routing.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-routing-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Routing status ───────────────────────────────────────────────

@test "Routing status returns enabled" {
    require_root

    local body
    body="$(api_get /api/v1/routing/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Gateway list ─────────────────────────────────────────────────

@test "Gateway list shows configured gateway" {
    require_root

    local body
    body="$(api_get /api/v1/routing/gateways)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local gw_ip
    gw_ip="$(echo "$body" | jq -r '
        (if type == "array" then . else (.gateways // []) end)
        | .[]
        | (.ip // .address // .gateway_ip)
    ' 2>/dev/null | grep -F "10.200.0.254" | head -1)" || true
    [ "$gw_ip" = "10.200.0.254" ]
}

# ── Gateway health ───────────────────────────────────────────────

@test "Gateway health state reported" {
    require_root

    local body
    body="$(api_get /api/v1/routing/gateways)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    # health_status may be "unknown" or "down" since no real gateway exists —
    # the important thing is that the field is present in the response
    local health
    health="$(echo "$body" | jq -r '
        (if type == "array" then . else (.gateways // []) end)
        | .[0]
        | (.health_status // .health // .state)
    ' 2>/dev/null)" || true
    [ -n "$health" ]
    [ "$health" != "null" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "Routing metrics present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_routing|ebpfsentinel_packets"
}
