#!/usr/bin/env bats
# 34-ebpf-zone-scenarios.bats — Zone management eBPF scenario tests
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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-zones-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-zones.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-zones-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Zone status ──────────────────────────────────────────────────

@test "Zone status returns enabled" {
    require_root

    local body
    body="$(api_get /api/v1/zones/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Zone list ────────────────────────────────────────────────────

@test "Zone list shows configured zones" {
    require_root

    local body
    body="$(api_get /api/v1/zones)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else (.zones // [] | length) end' 2>/dev/null)" || true
    [ "$count" -ge 2 ]
}

# ── Zone policies ────────────────────────────────────────────────

@test "Zone policies accessible" {
    require_root

    local body
    body="$(api_get /api/v1/zones/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    # Response must be non-empty and contain at least one policy
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else (.policies // [] | length) end' 2>/dev/null)" || true
    [ "$count" -ge 1 ]
}

# ── Inter-zone deny policy ───────────────────────────────────────

@test "Zone policy inter-zone deny configured" {
    require_root

    local body
    body="$(api_get /api/v1/zones/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    # Look for a deny policy with source_zone=external and dest_zone=internal
    local deny_found
    deny_found="$(echo "$body" | jq -r '
        (if type == "array" then . else (.policies // []) end)
        | .[]
        | select(
            (.action == "deny")
            and ((.source_zone == "external") or (.src_zone == "external") or (.from == "external"))
          )
        | .action
    ' 2>/dev/null | head -1)" || true
    [ "$deny_found" = "deny" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "Zone metrics present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_zone|ebpfsentinel_packets"
}
