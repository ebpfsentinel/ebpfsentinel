#!/usr/bin/env bats
# 07-authentication.bats — JWT authentication and RBAC tests

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    export JWT_DIR="${JWT_DIR:-/tmp/ebpfsentinel-test-jwt}"
    mkdir -p "$DATA_DIR"

    # Generate JWT keys if not present
    if [ ! -f "${JWT_DIR}/jwt-public.pem" ]; then
        bash "${SCRIPT_DIR}/generate-jwt-keys.sh" --out-dir "$JWT_DIR"
    fi

    # Prepare auth config from template
    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-auth-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__JWT_PUBKEY__|${JWT_DIR}/jwt-public.pem|g" \
        "${FIXTURE_DIR}/config-auth-jwt.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Helper ─────────────────────────────────────────────────────────

# get_token <name> — returns the raw JWT string for the given token name
get_token() {
    cat "${JWT_DIR}/token-${1}.jwt" 2>/dev/null
}

# ── Tests ──────────────────────────────────────────────────────────

@test "healthz is accessible without token (public route)" {
    local status_code
    status_code="$(api_status /healthz)"
    assert_http_status "200" "$status_code"
}

@test "readyz is accessible without token (public route)" {
    local status_code
    status_code="$(api_status /readyz)"
    # 200 or 503 are both acceptable — just not 401
    [[ "$status_code" == "200" ]] || [[ "$status_code" == "503" ]]
}

@test "API endpoint without token returns 401" {
    local status_code
    status_code="$(api_status /api/v1/firewall/rules)"
    assert_http_status "401" "$status_code"
}

@test "valid admin token returns 200" {
    local body
    body="$(api_get /api/v1/firewall/rules -H "Authorization: Bearer $(get_token admin)")"
    _load_http_status
    assert_http_status "200" "$HTTP_STATUS"
}

@test "expired token returns 401" {
    local status_code
    status_code="$(curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" -w '%{http_code}' \
        -H "Authorization: Bearer $(get_token expired)" \
        "${BASE_URL}/api/v1/firewall/rules")"
    assert_http_status "401" "$status_code"
}

@test "garbage token returns 401" {
    local status_code
    status_code="$(curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" -w '%{http_code}' \
        -H "Authorization: Bearer this.is.garbage" \
        "${BASE_URL}/api/v1/firewall/rules")"
    assert_http_status "401" "$status_code"
}

@test "viewer can read (GET rules returns 200)" {
    local body
    body="$(api_get /api/v1/firewall/rules -H "Authorization: Bearer $(get_token viewer)")"
    _load_http_status
    assert_http_status "200" "$HTTP_STATUS"
}

@test "viewer cannot write (POST rule returns 403)" {
    local rule='{"id":"it-rbac-001","priority":100,"action":"deny","protocol":"tcp","scope":"global"}'
    api_post /api/v1/firewall/rules "$rule" -H "Authorization: Bearer $(get_token viewer)" >/dev/null
    assert_http_status "403" "$HTTP_STATUS"
}

@test "admin can create firewall rule" {
    local rule='{"id":"it-rbac-admin-001","priority":100,"action":"deny","protocol":"tcp","scope":"global"}'
    local body
    body="$(api_post /api/v1/firewall/rules "$rule" -H "Authorization: Bearer $(get_token admin)")"
    _load_http_status
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-rbac-admin-001'

    # Cleanup
    api_delete /api/v1/firewall/rules/it-rbac-admin-001 -H "Authorization: Bearer $(get_token admin)" >/dev/null
}

@test "operator can create rule in own namespace (namespace:prod)" {
    local rule='{"id":"it-rbac-op-001","priority":100,"action":"deny","protocol":"tcp","scope":"namespace:prod"}'
    local body
    body="$(api_post /api/v1/firewall/rules "$rule" -H "Authorization: Bearer $(get_token operator)")"
    _load_http_status
    assert_http_status "201" "$HTTP_STATUS"

    # Cleanup
    api_delete /api/v1/firewall/rules/it-rbac-op-001 -H "Authorization: Bearer $(get_token admin)" >/dev/null
}

@test "operator cannot create rule in other namespace (namespace:finance returns 403)" {
    local rule='{"id":"it-rbac-op-002","priority":100,"action":"deny","protocol":"tcp","scope":"namespace:finance"}'
    api_post /api/v1/firewall/rules "$rule" -H "Authorization: Bearer $(get_token operator)" >/dev/null
    assert_http_status "403" "$HTTP_STATUS"
}
