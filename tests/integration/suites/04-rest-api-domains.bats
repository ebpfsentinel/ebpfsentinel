#!/usr/bin/env bats
# 04-rest-api-domains.bats — Domain-specific API endpoints (L7, IPS, Rate Limit, etc.)

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

# ── L7 Rules ───────────────────────────────────────────────────────

@test "L7: GET list returns 200" {
    local body
    body="$(api_get /api/v1/firewall/l7-rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "L7: POST creates rule and returns 201" {
    local rule='{"id":"it-l7-001","priority":100,"action":"deny","protocol":"http","path":"/admin","enabled":true}'
    local body
    body="$(api_post /api/v1/firewall/l7-rules "$rule")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-l7-001'
}

@test "L7: DELETE rule returns 204" {
    api_delete /api/v1/firewall/l7-rules/it-l7-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

# ── IPS ────────────────────────────────────────────────────────────

@test "IPS: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/ips/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "IPS: GET blacklist returns 200" {
    local body
    body="$(api_get /api/v1/ips/blacklist)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Rate Limit ─────────────────────────────────────────────────────

@test "Rate Limit: GET list returns 200" {
    local body
    body="$(api_get /api/v1/ratelimit/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Rate Limit: POST creates rule and returns 201" {
    local rule='{"id":"it-rl-001","scope":"global","rate":100,"burst":200,"action":"drop","algorithm":"token_bucket"}'
    local body
    body="$(api_post /api/v1/ratelimit/rules "$rule")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-rl-001'
}

@test "Rate Limit: DELETE rule returns 204" {
    api_delete /api/v1/ratelimit/rules/it-rl-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

# ── Threat Intel ───────────────────────────────────────────────────

@test "Threat Intel: GET status returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/status)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Threat Intel: GET iocs returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/iocs)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Threat Intel: GET feeds returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/feeds)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Alerts ─────────────────────────────────────────────────────────

@test "Alerts: GET list returns 200 (empty)" {
    local body
    body="$(api_get /api/v1/alerts)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Audit ──────────────────────────────────────────────────────────

@test "Audit: GET logs returns 200" {
    local body
    body="$(api_get /api/v1/audit/logs)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Audit: GET rule history returns 200" {
    local body
    body="$(api_get /api/v1/audit/rules/any-rule/history)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── DNS Intelligence ──────────────────────────────────────────────

@test "DNS: GET cache returns 200" {
    local body
    body="$(api_get /api/v1/dns/cache)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DNS: GET cache with domain filter returns 200" {
    local body
    body="$(api_get '/api/v1/dns/cache?domain=example.com')"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DNS: GET stats returns 200" {
    local body
    body="$(api_get /api/v1/dns/stats)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DNS: GET blocklist returns 200" {
    local body
    body="$(api_get /api/v1/dns/blocklist)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "DNS: DELETE cache (flush) returns 200" {
    local body
    body="$(api_delete /api/v1/dns/cache)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Domain Reputation ─────────────────────────────────────────────

@test "Domains: GET reputation returns 200" {
    local body
    body="$(api_get /api/v1/domains/reputation)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Domains: GET reputation with filters returns 200" {
    local body
    body="$(api_get '/api/v1/domains/reputation?domain=example.com&min_score=0.5')"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Domains: POST blocklist adds domain and returns 200" {
    local payload='{"domain":"test-block.example.com"}'
    local body
    body="$(api_post /api/v1/domains/blocklist "$payload")"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.domain' 'test-block.example.com'
}

@test "Domains: DELETE blocklist removes domain and returns 200" {
    local body
    body="$(api_delete /api/v1/domains/blocklist/test-block.example.com)"
    assert_http_status "200" "$HTTP_STATUS"
}
