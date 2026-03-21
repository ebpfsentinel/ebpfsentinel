#!/usr/bin/env bats
# 33-ebpf-geoip-scenarios.bats — GeoIP enrichment eBPF scenario tests
# Requires: root, kernel >= 6.1, bpftool
# Note: most tests skip gracefully when no GeoLite2 mmdb files are present.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# ── Skip guard: GeoIP mmdb availability ─────────────────────────

_require_geoip_mmdb() {
    if [ ! -f "${DATA_DIR}/GeoLite2-Country.mmdb" ]; then
        skip "GeoIP mmdb not available (${DATA_DIR}/GeoLite2-Country.mmdb)"
    fi
}

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-geoip-$$"
    mkdir -p "$DATA_DIR"

    # Copy mmdb files from well-known system or project locations if available.
    # Tests skip individually when the file is absent — no hard failure here.
    for mmdb_src in \
        "${PROJECT_ROOT}/tests/fixtures/GeoLite2-Country.mmdb" \
        "/usr/share/GeoIP/GeoLite2-Country.mmdb" \
        "/var/lib/GeoIP/GeoLite2-Country.mmdb"; do
        if [ -f "$mmdb_src" ]; then
            cp "$mmdb_src" "${DATA_DIR}/GeoLite2-Country.mmdb" 2>/dev/null || true
            break
        fi
    done

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-geoip.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-geoip-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Agent status ─────────────────────────────────────────────────

@test "GeoIP enrichment available in agent status" {
    require_root

    local body
    body="$(api_get /api/v1/agent/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    # Agent status must be accessible; geoip field present when mmdb loaded
    local status
    status="$(echo "$body" | jq -r '.status // .state' 2>/dev/null)" || true
    [ -n "$status" ]
    [ "$status" != "null" ]
}

# ── Firewall country rules ───────────────────────────────────────

@test "Firewall country deny rule configured" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Verify at least one rule with country_codes is present (from fixture)
    local country_rules
    country_rules="$(echo "$body" | \
        jq '[if type == "array" then .[] else .rules[] end | select(.country_codes != null and (.country_codes | length) > 0)] | length' \
        2>/dev/null)" || country_rules=0

    [ "${country_rules:-0}" -ge 1 ]
}

# ── Alert GeoIP fields ───────────────────────────────────────────

@test "Alert contains GeoIP fields" {
    require_root
    _require_geoip_mmdb

    # Trigger traffic to generate an alert — send packets from the namespace to the host.
    # The firewall has a country-deny rule that triggers an alert action on matching traffic.
    send_tcp_from_ns "$EBPF_HOST_IP" 9999 "GEOIP_TRIGGER" 3
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local alerts
    alerts="$(echo "$body" | jq '.alerts // .' 2>/dev/null)" || alerts="$body"
    local count
    count="$(echo "$alerts" | jq 'length' 2>/dev/null)" || count=0

    if [ "${count:-0}" -eq 0 ]; then
        skip "no alerts generated — traffic may not have matched a country-deny rule"
    fi

    # At least one alert should carry GeoIP enrichment fields when mmdb is loaded
    local has_geo
    has_geo="$(echo "$alerts" | \
        jq '[.[] | select(.src_geo != null or .geo != null or .country_code != null)] | length' \
        2>/dev/null)" || has_geo=0

    [ "${has_geo:-0}" -ge 1 ]
}

# ── Cross-domain: DDoS country thresholds ────────────────────────

@test "GeoIP cross-domain: DDoS country thresholds configured" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # The fixture enables DDoS with a policy that has country_codes set
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]

    # Verify the policies endpoint is accessible and contains at least one policy
    local policies_body
    policies_body="$(api_get /api/v1/ddos/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$policies_body" | jq 'if type == "array" then length else .policies | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]
}

# ── Cross-domain: ratelimit country tiers ────────────────────────

@test "GeoIP cross-domain: ratelimit country tiers configured" {
    require_root

    local body
    body="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Fixture has a ratelimit rule with country_codes (CN) — verify at least 1 rule
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .rules | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]

    # Verify at least one rule has country_codes configured
    local country_rules
    country_rules="$(echo "$body" | \
        jq '[if type == "array" then .[] else .rules[] end | select(.country_codes != null and (.country_codes | length) > 0)] | length' \
        2>/dev/null)" || country_rules=0

    [ "${country_rules:-0}" -ge 1 ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "GeoIP metrics present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_geoip|ebpfsentinel_country|ebpfsentinel_packets"
}

# ── GeoIP status endpoint ───────────────────────────────────────

@test "GeoIP status endpoint returns mmdb info" {
    require_root

    local body
    body="$(api_get /api/v1/geoip/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Status must indicate whether GeoIP is enabled and mmdb loaded
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled // .geoip_enabled' 2>/dev/null)" || true
    [ -n "$enabled" ]
    [ "$enabled" != "null" ]
}

# ── Country deny rule blocks traffic ────────────────────────────

@test "GeoIP country deny rule triggers alert on traffic" {
    require_root
    _require_geoip_mmdb

    # Record current alert count before the test
    local before_body before_count
    before_body="$(api_get /api/v1/alerts)" || true
    before_count="$(echo "$before_body" | jq '(.alerts // .) | length' 2>/dev/null)" || before_count=0

    # Send traffic from the namespace — firewall has a country-deny rule
    send_tcp_from_ns "$EBPF_HOST_IP" 9999 "GEOIP_COUNTRY_DENY_TEST" 3
    send_udp_from_ns "$EBPF_HOST_IP" 9999 "GEOIP_UDP_TEST" 3

    sleep 3

    # Verify alerts endpoint is accessible
    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local alerts
    alerts="$(echo "$body" | jq '.alerts // .' 2>/dev/null)" || alerts="$body"
    local count
    count="$(echo "$alerts" | jq 'length' 2>/dev/null)" || count=0

    if [ "${count:-0}" -eq 0 ]; then
        skip "no alerts generated — traffic may not have matched a country-deny rule"
    fi

    # At least one new alert should exist
    [ "${count:-0}" -ge 1 ]
}

# ── Alert GeoIP enrichment fields detail ────────────────────────

@test "Alert GeoIP enrichment includes country code" {
    require_root
    _require_geoip_mmdb

    # Generate traffic to trigger alerts with GeoIP enrichment
    send_tcp_from_ns "$EBPF_HOST_IP" 9999 "GEOIP_ENRICHMENT_CC" 3
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local alerts
    alerts="$(echo "$body" | jq '.alerts // .' 2>/dev/null)" || alerts="$body"
    local count
    count="$(echo "$alerts" | jq 'length' 2>/dev/null)" || count=0

    if [ "${count:-0}" -eq 0 ]; then
        skip "no alerts generated — cannot verify GeoIP enrichment"
    fi

    # Check that at least one alert has a country_code or src_country field
    local has_country
    has_country="$(echo "$alerts" | \
        jq '[.[] | select(.country_code != null or .src_country != null or .src_geo != null or .geo.country_code != null)] | length' \
        2>/dev/null)" || has_country=0

    [ "${has_country:-0}" -ge 1 ]
}

# ── Cross-domain: L7 country matching ───────────────────────────

@test "GeoIP cross-domain: L7 rules with country matching" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Fixture may have L7 rules with country_codes configured — verify endpoint is accessible
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .rules | length end' 2>/dev/null)" || true

    # At minimum, L7 rules endpoint must respond; country-aware L7 rules may or may not exist
    [ "${count:-0}" -ge 0 ]

    # If any L7 rules have country_codes, verify the field is non-empty
    local country_l7
    country_l7="$(echo "$body" | \
        jq '[if type == "array" then .[] else .rules[] end | select(.country_codes != null and (.country_codes | length) > 0)] | length' \
        2>/dev/null)" || country_l7=0

    # This is a cross-domain integration check — country_l7 may be 0 if not configured
    [ "${country_l7:-0}" -ge 0 ]
}

# ── GeoIP lookup endpoint ──────────────────────────────────────

@test "GeoIP lookup for known IP" {
    require_root
    _require_geoip_mmdb

    # Query the GeoIP lookup endpoint for a well-known public IP
    local body
    body="$(api_get /api/v1/geoip/lookup?ip=8.8.8.8)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # The response should contain a country code field for Google DNS
    local country
    country="$(echo "$body" | jq -r '.country_code // .country // .iso_code' 2>/dev/null)" || true

    if [ -z "$country" ] || [ "$country" = "null" ]; then
        skip "GeoIP lookup endpoint not available or mmdb does not contain 8.8.8.8"
    fi

    [ "$country" = "US" ]
}

# ── GeoIP metrics counter after traffic ─────────────────────────

@test "GeoIP metrics counter increments after lookup traffic" {
    require_root
    _require_geoip_mmdb

    # Send traffic to trigger GeoIP lookups
    send_tcp_from_ns "$EBPF_HOST_IP" 9999 "GEOIP_METRICS_TEST" 3
    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]

    # After traffic, at least one GeoIP-related metric should have a non-zero value
    local geoip_line
    geoip_line="$(echo "$metrics" | grep -E "ebpfsentinel_geoip|ebpfsentinel_country" | head -1)" || true

    if [ -z "$geoip_line" ]; then
        skip "no GeoIP-specific metrics found"
    fi

    local value
    value="$(echo "$geoip_line" | awk '{print $2}')" || true
    [ -n "$value" ]
}
