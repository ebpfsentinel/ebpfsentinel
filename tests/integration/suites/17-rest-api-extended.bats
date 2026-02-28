#!/usr/bin/env bats
# 17-rest-api-extended.bats — Extended domain REST API endpoints
# Covers: IDS, DLP, Conntrack, NAT, Routing, Aliases, Load Balancer, Operations

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-full.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── IDS ───────────────────────────────────────────────────────────

@test "IDS: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/ids/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "IDS: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/ids/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── DLP ───────────────────────────────────────────────────────────

@test "DLP: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/dlp/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "DLP: GET patterns returns 200" {
    local body
    body="$(api_get /api/v1/dlp/patterns)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Conntrack ─────────────────────────────────────────────────────

@test "Conntrack: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/conntrack/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "Conntrack: GET connections returns 200" {
    local body
    body="$(api_get /api/v1/conntrack/connections)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Conntrack: POST flush returns 200" {
    local body
    body="$(api_post /api/v1/conntrack/flush '{}')"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── NAT ───────────────────────────────────────────────────────────

@test "NAT: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/nat/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "NAT: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/nat/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Routing ───────────────────────────────────────────────────────

@test "Routing: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/routing/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "Routing: GET gateways returns 200" {
    local body
    body="$(api_get /api/v1/routing/gateways)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Aliases ───────────────────────────────────────────────────────

@test "Aliases: GET status returns 200" {
    local body
    body="$(api_get /api/v1/aliases/status)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Load Balancer ─────────────────────────────────────────────────

@test "LB: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/lb/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "LB: GET services returns 200 (empty)" {
    local body
    body="$(api_get /api/v1/lb/services)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" '.' '0'
}

@test "LB: POST creates service and returns 201" {
    local svc='{"id":"it-lb-001","name":"web-svc","protocol":"tcp","listen_port":8080,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.0.0.1","port":8081,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-lb-001'
    assert_json_field "$body" '.protocol' 'tcp'
    assert_json_field "$body" '.algorithm' 'round_robin'
}

@test "LB: GET service by id returns 200 with backends" {
    local body
    body="$(api_get /api/v1/lb/services/it-lb-001)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-lb-001'
    assert_json_array_length "$body" '.backends' '1'
}

@test "LB: DELETE service returns 204" {
    api_delete /api/v1/lb/services/it-lb-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

@test "LB: DELETE nonexistent service returns 404" {
    api_delete /api/v1/lb/services/no-such-svc >/dev/null 2>&1 || true
    assert_http_status "404" "$HTTP_STATUS"
}

@test "LB: POST with invalid protocol returns 400" {
    local svc='{"id":"it-lb-bad","name":"bad","protocol":"invalid","listen_port":80,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: POST with zero listen_port returns 400" {
    local svc='{"id":"it-lb-bad2","name":"bad","protocol":"tcp","listen_port":0,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: POST with empty backends returns 400" {
    local svc='{"id":"it-lb-bad3","name":"bad","protocol":"tcp","listen_port":80,"backends":[]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: list is empty after deletion" {
    local body
    body="$(api_get /api/v1/lb/services)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" '.' '0'
}

# ── Operations ────────────────────────────────────────────────────

@test "Ops: GET config returns 200" {
    local body
    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Ops: GET ebpf status returns 200" {
    local body
    body="$(api_get /api/v1/ebpf/status)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Ops: POST config reload returns 200" {
    local body
    body="$(api_post /api/v1/config/reload '{}')"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── IPS extended ──────────────────────────────────────────────────

@test "IPS: GET domain-blocks returns 200" {
    local body
    body="$(api_get /api/v1/ips/domain-blocks)"
    assert_http_status "200" "$HTTP_STATUS"
}
