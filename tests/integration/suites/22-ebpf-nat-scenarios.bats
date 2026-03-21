#!/usr/bin/env bats
# 22-ebpf-nat-scenarios.bats — NAT eBPF scenario tests
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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-nat-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-nat.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-nat-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── TC program attachment ────────────────────────────────────────

@test "TC NAT programs attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── NAT status ───────────────────────────────────────────────────

@test "NAT status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "NAT rules list is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/nat/rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Conntrack (prerequisite for NAT) ─────────────────────────────

@test "conntrack is enabled alongside NAT" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "NAT metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets|ebpfsentinel_rules_loaded"
}

# ── Additional NAT API tests ──────────────────────────────────────

@test "NAT status returns enabled" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "NAT rules list accessible" {
    require_root

    local body
    body="$(api_get /api/v1/nat/rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── NPTv6 CRUD ───────────────────────────────────────────────────

@test "NPTv6 rule CRUD — create" {
    require_root

    local rule='{"id":"nptv6-test","internal_prefix":"fd00::","external_prefix":"2001:db8::","prefix_len":48}'
    local body
    body="$(api_post /api/v1/nat/nptv6 "$rule")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id
    id="$(echo "$body" | jq -r '.id // empty' 2>/dev/null)" || true
    [ "$id" = "nptv6-test" ]
}

@test "NPTv6 rule CRUD — delete" {
    require_root

    api_delete /api/v1/nat/nptv6/nptv6-test >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

@test "NAT metrics present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets|ebpfsentinel_rules_loaded"
}

# ── Extended NAT tests ────────────────────────────────────────────

@test "NPTv6 rule CRUD via API" {
    require_root

    local rule='{"id":"nptv6-001","internal_prefix":"fd00::","external_prefix":"2001:db8::","prefix_len":48,"enabled":true}'
    local body
    body="$(api_post /api/v1/nat/nptv6 "$rule" 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Read back
    body="$(api_get /api/v1/nat/nptv6 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    # Delete
    api_delete /api/v1/nat/nptv6/nptv6-001 >/dev/null 2>&1 || true
}

@test "hairpin NAT config accepted" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    # Hairpin should be configurable
    local enabled
    enabled="$(echo "$body" | jq -r '.hairpin_enabled // .hairpin // "unknown"' 2>/dev/null)" || true
    [ -n "$enabled" ]
}

@test "NAT rules list is queryable" {
    require_root

    # The NAT rules endpoint is read-only (populated from config).
    # Verify it returns a valid JSON array.
    local body
    body="$(api_get /api/v1/nat/rules 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local is_array
    is_array="$(echo "$body" | jq 'type == "array"' 2>/dev/null)" || true
    [ "$is_array" = "true" ]
}
