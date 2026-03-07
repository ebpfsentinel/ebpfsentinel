#!/usr/bin/env bats
# 26-alert-end-to-end.bats — Alert lifecycle end-to-end tests
# Requires: root, kernel >= 5.17, bpftool, ncat, jq
#
# Tests the full alert lifecycle:
#   1. Trigger an IDS alert via TCP traffic to port 4444
#   2. Verify the alert is persisted and queryable via REST API
#   3. Validate alert fields (source, destination, protocol)
#   4. Mark the alert as false positive
#   5. Verify FP flag is persisted and filterable

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-alert-e2e-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-alert-e2e.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-alert-e2e-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "traffic on port 4444 generates IDS alert" {
    require_root
    require_tool ncat

    # Start a dummy listener on port 4444 (so TCP handshake completes)
    timeout 10 ncat -l "$EBPF_HOST_IP" 4444 >/dev/null 2>&1 &
    local listener_pid=$!
    sleep 0.5

    # Send traffic that should trigger the IDS rule
    send_tcp_from_ns "$EBPF_HOST_IP" 4444 "ALERT_E2E_TEST" 3

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Wait for the alert to appear
    local alert
    alert="$(wait_for_alert '.[] | select(.rule_id == "ids-alert-test")' 15 1)" || true

    [ -n "$alert" ] && [ "$alert" != "null" ]
}

@test "alert queryable via REST API" {
    require_root

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local rule_id severity
    rule_id="$(echo "$body" | jq -r '[.alerts[] | select(.rule_id == "ids-alert-test")][0].rule_id' 2>/dev/null)" || true
    severity="$(echo "$body" | jq -r '[.alerts[] | select(.rule_id == "ids-alert-test")][0].severity' 2>/dev/null)" || true

    [ "$rule_id" = "ids-alert-test" ]
    [ "$severity" = "high" ]
}

@test "alert has correct source and destination" {
    require_root

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local alert
    alert="$(echo "$body" | jq '[.alerts[] | select(.rule_id == "ids-alert-test")][0]' 2>/dev/null)" || true

    [ -n "$alert" ] && [ "$alert" != "null" ]

    local src_port dst_port protocol
    src_port="$(echo "$alert" | jq -r '.src_port' 2>/dev/null)" || true
    dst_port="$(echo "$alert" | jq -r '.dst_port' 2>/dev/null)" || true
    protocol="$(echo "$alert" | jq -r '.protocol' 2>/dev/null)" || true

    # Source port should be an ephemeral port (> 0)
    [ "${src_port:-0}" -gt 0 ]
    # Destination port must be 4444
    [ "$dst_port" = "4444" ]
    # Protocol 6 = TCP
    [ "$protocol" = "6" ]
}

@test "alert count increments" {
    require_root

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq '[.alerts[] | select(.rule_id == "ids-alert-test")] | length' 2>/dev/null)" || true

    [ "${count:-0}" -ge 1 ]
}

@test "mark alert as false positive" {
    require_root

    # Get the alert id from the first matching alert
    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local alert_id
    alert_id="$(echo "$body" | jq -r '[.alerts[] | select(.rule_id == "ids-alert-test")][0].id' 2>/dev/null)" || true

    [ -n "$alert_id" ] && [ "$alert_id" != "null" ]

    # Persist alert_id for subsequent tests
    echo "$alert_id" > "$DATA_DIR/alert_id.txt"

    # Mark as false positive
    local patch_body
    patch_body="$(api_patch "/api/v1/alerts/${alert_id}/false-positive" '{"false_positive": true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "false positive flag persisted" {
    require_root

    local alert_id
    alert_id="$(cat "$DATA_DIR/alert_id.txt" 2>/dev/null)"
    [ -n "$alert_id" ] || skip "no alert_id from previous test"

    local body
    body="$(api_get "/api/v1/alerts/${alert_id}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local fp
    fp="$(echo "$body" | jq -r '.false_positive' 2>/dev/null)" || true

    [ "$fp" = "true" ]
}

@test "query with false_positive filter excludes FP" {
    require_root

    local alert_id
    alert_id="$(cat "$DATA_DIR/alert_id.txt" 2>/dev/null)"
    [ -n "$alert_id" ] || skip "no alert_id from previous test"

    local body
    body="$(api_get '/api/v1/alerts?false_positive=false')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # The FP-marked alert should NOT appear in the filtered results
    local match
    match="$(echo "$body" | jq -r "[.alerts[] | select(.id == \"${alert_id}\")] | length" 2>/dev/null)" || true

    [ "${match:-0}" -eq 0 ]
}
