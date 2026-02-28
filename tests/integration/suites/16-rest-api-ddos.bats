#!/usr/bin/env bats
# 16-rest-api-ddos.bats — DDoS protection API endpoints

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

# ── DDoS Status ───────────────────────────────────────────────────

@test "DDoS: GET status returns 200" {
    local body
    body="$(api_get /api/v1/ddos/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

# ── DDoS Attacks ──────────────────────────────────────────────────

@test "DDoS: GET attacks returns 200 (empty)" {
    local body
    body="$(api_get /api/v1/ddos/attacks)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DDoS: GET attacks history returns 200" {
    local body
    body="$(api_get '/api/v1/ddos/attacks/history?limit=10')"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── DDoS Policies ────────────────────────────────────────────────

@test "DDoS: GET policies returns 200 with seed policy" {
    local body
    body="$(api_get /api/v1/ddos/policies)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DDoS: POST creates policy and returns 201" {
    local policy='{"id":"it-ddos-001","attack_type":"icmp_flood","detection_threshold_pps":5000,"mitigation_action":"block","auto_block_duration_secs":120,"enabled":true}'
    local body
    body="$(api_post /api/v1/ddos/policies "$policy")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-ddos-001'
}

@test "DDoS: DELETE policy returns 204" {
    api_delete /api/v1/ddos/policies/it-ddos-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

# ── Validation ────────────────────────────────────────────────────

@test "DDoS: POST with invalid attack_type returns 400" {
    local policy='{"id":"it-ddos-bad","attack_type":"invalid","detection_threshold_pps":1000,"mitigation_action":"alert"}'
    api_post /api/v1/ddos/policies "$policy" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "DDoS: POST with zero threshold returns 400" {
    local policy='{"id":"it-ddos-bad2","attack_type":"syn_flood","detection_threshold_pps":0,"mitigation_action":"alert"}'
    api_post /api/v1/ddos/policies "$policy" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "DDoS: DELETE non-existent policy returns 404" {
    api_delete /api/v1/ddos/policies/no-such-policy >/dev/null 2>&1 || true
    assert_http_status "404" "$HTTP_STATUS"
}
