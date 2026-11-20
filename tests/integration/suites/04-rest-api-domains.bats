#!/usr/bin/env bats
# 04-rest-api-domains.bats - Domain-specific API endpoints (L7, IPS, Rate Limit, etc.)

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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("action"))' >/dev/null
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
    local listing
    listing="$(api_get /api/v1/firewall/l7-rules)"
    echo "$listing" | jq -e --arg id "it-l7-001" 'type == "array" and (map(.id) | index($id) | not)' >/dev/null || {
        echo "it-l7-001 still listed after delete: $listing" >&2; return 1; }
}

# ── IPS ────────────────────────────────────────────────────────────

@test "IPS: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/ips/rules)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id"))' >/dev/null
}

@test "IPS: GET blacklist returns 200" {
    local body
    body="$(api_get /api/v1/ips/blacklist)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("ip"))' >/dev/null
}

# ── Rate Limit ─────────────────────────────────────────────────────

@test "Rate Limit: GET list returns 200" {
    local body
    body="$(api_get /api/v1/ratelimit/rules)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("algorithm"))' >/dev/null
}

@test "Rate Limit: POST creates rule and returns 201" {
    # A rule names one source host: the data plane keys the token bucket by
    # source address, so `src_ip` is required and there is no global scope.
    local rule='{"id":"it-rl-001","src_ip":"203.0.113.10/32","rate":100,"burst":200,"action":"drop","algorithm":"token_bucket"}'
    local body
    body="$(api_post /api/v1/ratelimit/rules "$rule")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-rl-001'
    # The host the rule limits has to survive the round trip: a 201 carrying a
    # different source would enforce against traffic the caller never named.
    assert_json_field "$body" '.src_ip' '203.0.113.10/32'
}

@test "Rate Limit: DELETE rule returns 204" {
    api_delete /api/v1/ratelimit/rules/it-rl-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
    local listing
    listing="$(api_get /api/v1/ratelimit/rules)"
    echo "$listing" | jq -e --arg id "it-rl-001" 'type == "array" and (map(.id) | index($id) | not)' >/dev/null || {
        echo "it-rl-001 still listed after delete: $listing" >&2; return 1; }
}

# ── Threat Intel ───────────────────────────────────────────────────

@test "Threat Intel: GET status returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/status)"
    assert_http_status "200"
    echo "$body" | jq -e '(.enabled | type == "boolean") and (.ioc_count | type == "number") and (.feed_count | type == "number")' >/dev/null
}

@test "Threat Intel: GET iocs returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/iocs)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array"' >/dev/null
}

@test "Threat Intel: GET feeds returns 200" {
    local body
    body="$(api_get /api/v1/threatintel/feeds)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("format"))' >/dev/null
}

# ── Alerts ─────────────────────────────────────────────────────────

@test "Alerts: GET list returns 200 (empty)" {
    local body
    body="$(api_get /api/v1/alerts)"
    assert_http_status "200"
    echo "$body" | jq -e '(.alerts | type == "array") and (.total | type == "number") and .total >= (.alerts | length)' >/dev/null
}

# ── Audit ──────────────────────────────────────────────────────────

@test "Audit: GET logs returns 200" {
    local body
    body="$(api_get /api/v1/audit/logs)"
    assert_http_status "200"
    echo "$body" | jq -e '(.entries | type == "array") and (.total | type == "number")' >/dev/null
}

@test "Audit: GET rule history returns 200" {
    local body
    body="$(api_get /api/v1/audit/rules/any-rule/history)"
    assert_http_status "200"
    echo "$body" | jq -e '.rule_id == "any-rule" and (.entries | type == "array")' >/dev/null
}

# ── DNS Intelligence ──────────────────────────────────────────────

@test "DNS: GET cache returns 200" {
    local body
    body="$(api_get /api/v1/dns/cache)"
    assert_http_status "200"
    echo "$body" | jq -e '(.entries | type == "array") and (.page | type == "number")' >/dev/null
}

@test "DNS: GET cache with domain filter returns 200" {
    local body
    body="$(api_get '/api/v1/dns/cache?domain=example.com')"
    assert_http_status "200"
    echo "$body" | jq -e '(.entries | type == "array") and all(.entries[]; (.domain // "") | test("example\\.com$"))' >/dev/null
}

@test "DNS: GET stats returns 200" {
    local body
    body="$(api_get /api/v1/dns/stats)"
    assert_http_status "200"
    echo "$body" | jq -e '(.hit_count | type == "number") and (.miss_count | type == "number") and (.top_queried | type == "array")' >/dev/null
}

@test "DNS: GET blocklist returns 200" {
    local body
    body="$(api_get /api/v1/dns/blocklist)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("pattern"))' >/dev/null
}

@test "DNS: DELETE cache (flush) returns 200" {
    local body
    body="$(api_delete /api/v1/dns/cache)"
    assert_http_status "200"
    echo "$body" | jq -e '.flushed_entries | type == "number"' >/dev/null
}

# ── Domain Reputation ─────────────────────────────────────────────

@test "Domains: GET reputation returns 200" {
    local body
    body="$(api_get /api/v1/domains/reputation)"
    assert_http_status "200"
    echo "$body" | jq -e '(.entries | type == "array") and (.page_size | type == "number")' >/dev/null
}

@test "Domains: GET reputation with filters returns 200" {
    local body
    body="$(api_get '/api/v1/domains/reputation?domain=example.com&min_score=0.5')"
    assert_http_status "200"
    echo "$body" | jq -e '.entries | type == "array"' >/dev/null
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
    # The pattern is listed before the delete, so its absence afterwards is
    # the delete's doing and not an add that never landed.
    body="$(api_get /api/v1/dns/blocklist)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e 'any(.[]; .pattern == "test-block.example.com")' >/dev/null || {
        echo "test-block.example.com is not listed before the delete: ${body}" >&2
        return 1
    }

    body="$(api_delete /api/v1/domains/blocklist/test-block.example.com)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.removed' 'true'

    body="$(api_get /api/v1/dns/blocklist)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e 'any(.[]; .pattern == "test-block.example.com") | not' >/dev/null || {
        echo "test-block.example.com is still listed after the delete: ${body}" >&2
        return 1
    }
}
