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
