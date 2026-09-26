#!/usr/bin/env bats
# 03-rest-api-firewall.bats - Firewall CRUD via REST API

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

@test "list rules holds no user rule initially" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" 'map(select(.system != true))' '0'
}

@test "anti-lockout keeps SSH and the agent's API ports as system rules" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    assert_http_status "200" "$HTTP_STATUS"
    local port
    for port in 22 8080 50051; do
        echo "$body" | jq -e --arg p "$port" \
            'any(.[]; .system == true and .action == "allow" and .dst_port == $p)' >/dev/null || {
            echo "no anti-lockout system rule for port $port" >&2
            return 1
        }
    done
}

@test "POST creates a firewall rule and returns 201" {
    local rule='{"id":"it-fw-001","priority":100,"action":"deny","protocol":"tcp","dst_port":22,"scope":"global"}'
    local body
    body="$(api_post /api/v1/firewall/rules "$rule")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-fw-001'
}

@test "list returns created rule with correct id" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    assert_http_status "200" "$HTTP_STATUS"

    local rule_id
    rule_id="$(echo "$body" | jq -r 'map(select(.system != true)) | .[0].id')"
    [ "$rule_id" = "it-fw-001" ]
}

@test "POST duplicate id returns 409" {
    local rule='{"id":"it-fw-001","priority":200,"action":"allow","protocol":"udp","scope":"global"}'
    api_post /api/v1/firewall/rules "$rule" >/dev/null
    assert_http_status "409" "$HTTP_STATUS"
}

@test "POST invalid action returns 400" {
    local rule='{"id":"it-fw-bad","priority":100,"action":"nope","protocol":"tcp","scope":"global"}'
    api_post /api/v1/firewall/rules "$rule" >/dev/null
    assert_http_status "400" "$HTTP_STATUS"
}

@test "DELETE rule returns 204" {
    api_delete /api/v1/firewall/rules/it-fw-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

@test "DELETE nonexistent rule returns 404" {
    api_delete /api/v1/firewall/rules/nonexistent-rule >/dev/null
    assert_http_status "404" "$HTTP_STATUS"
}

@test "list holds no user rule after deletion" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" 'map(select(.system != true))' '0'
}
