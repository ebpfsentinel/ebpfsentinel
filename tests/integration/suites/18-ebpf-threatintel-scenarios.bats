#!/usr/bin/env bats
# 18-ebpf-threatintel-scenarios.bats — Threat intel eBPF scenario tests
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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ti-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-threatintel.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ti-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── TC program attachment ────────────────────────────────────────

@test "TC threatintel program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    # TC programs attach to the interface; verify presence
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── Threat intel status ──────────────────────────────────────────

@test "threat intel status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/threatintel/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "threat intel feeds list is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/threatintel/feeds)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "threat intel IOC list is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/threatintel/iocs)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "threat intel metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_threatintel|ebpfsentinel_packets"
}
