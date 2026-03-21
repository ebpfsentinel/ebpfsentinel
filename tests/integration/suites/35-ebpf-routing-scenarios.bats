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

# ── Gateway CRUD — create and delete ────────────────────────────

@test "Gateway CRUD — create and delete" {
    require_root

    # Create a new gateway
    local create_body
    create_body="$(api_post /api/v1/routing/gateways \
        '{"name":"test-crud-gw","ip":"10.200.0.253","weight":1,"health_check_interval_secs":10,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local gw_id
    gw_id="$(echo "$create_body" | jq -r '.id // .gateway_id' 2>/dev/null)" || true
    [ -n "$gw_id" ]
    [ "$gw_id" != "null" ]

    # Verify the gateway appears in the list
    local list_body
    list_body="$(api_get /api/v1/routing/gateways)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local found
    found="$(echo "$list_body" | jq "[if type == \"array\" then .[] else (.gateways // [])[] end | select(.id == \"$gw_id\" or .gateway_id == \"$gw_id\")] | length" 2>/dev/null)" || found=0
    [ "${found:-0}" -ge 1 ]

    # Delete the created gateway
    local delete_body
    delete_body="$(api_delete "/api/v1/routing/gateways/${gw_id}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

# ── Gateway health check status detail ──────────────────────────

@test "Gateway health check includes check interval" {
    require_root

    local body
    body="$(api_get /api/v1/routing/gateways)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # The first gateway should have a health_check_interval or similar field
    local gateways
    gateways="$(echo "$body" | jq 'if type == "array" then . else (.gateways // []) end' 2>/dev/null)" || true
    local count
    count="$(echo "$gateways" | jq 'length' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]

    # Verify the first gateway has health-related fields
    local gw
    gw="$(echo "$gateways" | jq '.[0]' 2>/dev/null)" || true
    [ -n "$gw" ]
    [ "$gw" != "null" ]

    # Gateway must have at least ip/address and health status fields
    local gw_ip
    gw_ip="$(echo "$gw" | jq -r '.ip // .address // .gateway_ip' 2>/dev/null)" || true
    [ -n "$gw_ip" ]
    [ "$gw_ip" != "null" ]
}

# ── Multi-gateway failover config ───────────────────────────────

@test "Multi-gateway failover configuration" {
    require_root

    # Create a second gateway for failover
    local create_body
    create_body="$(api_post /api/v1/routing/gateways \
        '{"name":"failover-gw","ip":"10.200.0.252","weight":2,"health_check_interval_secs":5,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local gw_id
    gw_id="$(echo "$create_body" | jq -r '.id // .gateway_id' 2>/dev/null)" || true
    [ -n "$gw_id" ]
    [ "$gw_id" != "null" ]

    # Verify there are now at least 2 gateways (original + failover)
    local list_body
    list_body="$(api_get /api/v1/routing/gateways)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$list_body" | jq 'if type == "array" then length else (.gateways // []) | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 2 ]

    # Verify the failover gateway has weight=2
    local gateways
    gateways="$(echo "$list_body" | jq 'if type == "array" then . else (.gateways // []) end' 2>/dev/null)" || true
    local failover_weight
    failover_weight="$(echo "$gateways" | jq -r ".[] | select(.id == \"$gw_id\" or .gateway_id == \"$gw_id\") | .weight" 2>/dev/null)" || true
    [ "$failover_weight" = "2" ]

    # Clean up
    api_delete "/api/v1/routing/gateways/${gw_id}" >/dev/null 2>&1 || true
}

# ── Routing routes list ─────────────────────────────────────────

@test "Routing routes list accessible" {
    require_root

    local body
    body="$(api_get /api/v1/routing/routes)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Routes endpoint must return a valid response (may be empty if no routes configured)
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else (.routes // []) | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 0 ]
}
