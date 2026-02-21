#!/usr/bin/env bats
# 02-rest-api-health.bats — REST API health and observability endpoints

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "GET /healthz returns {\"status\":\"ok\"}" {
    local body
    body="$(api_get /healthz)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.status' 'ok'
}

@test "GET /readyz has ebpf_loaded field" {
    local body
    body="$(api_get /readyz)"
    _load_http_status
    # Accept 200 or 503 (depends on eBPF availability)
    [[ "$HTTP_STATUS" == "200" ]] || [[ "$HTTP_STATUS" == "503" ]]
    assert_json_field_exists "$body" '.ebpf_loaded'
}

@test "GET /api/v1/agent/status has version and uptime_seconds fields" {
    local body
    body="$(api_get /api/v1/agent/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field_exists "$body" '.version'

    local uptime
    uptime="$(echo "$body" | jq -r '.uptime_seconds')"
    [ "$uptime" -ge 0 ]
}

@test "GET /metrics returns Prometheus text format" {
    local body
    body="$(api_get /metrics)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_contains "$body" "# HELP"
    assert_contains "$body" "# TYPE"
}

@test "GET /swagger-ui/ returns 200 or redirect" {
    local status_code
    status_code="$(curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" -w '%{http_code}' -L "${BASE_URL}/swagger-ui/")"
    [[ "$status_code" == "200" ]] || [[ "$status_code" == "301" ]] || [[ "$status_code" == "302" ]]
}

@test "GET /api-docs/openapi.json returns valid OpenAPI spec" {
    local body
    body="$(api_get /api-docs/openapi.json)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field_exists "$body" '.openapi'
    assert_json_field_exists "$body" '.paths'
}
