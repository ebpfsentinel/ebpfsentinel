#!/usr/bin/env bats
# 20-ebpf-dns-scenarios.bats — DNS intelligence eBPF scenario tests
# Requires: root, kernel >= 5.17, bpftool

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dns-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dns.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dns-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── TC program attachment ────────────────────────────────────────

@test "TC DNS program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── DNS API status ───────────────────────────────────────────────

@test "DNS cache is accessible via API" {
    require_root

    local body
    body="$(api_get /api/v1/dns/cache)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS stats returns valid response" {
    require_root

    local body
    body="$(api_get /api/v1/dns/stats)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS blocklist is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/dns/blocklist)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS cache flush succeeds" {
    require_root

    api_delete /api/v1/dns/cache >/dev/null
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

# ── DNS packet capture ──────────────────────────────────────────

@test "UDP:53 traffic is observed by DNS program" {
    require_root

    # Send a DNS-like UDP packet to port 53 from namespace
    send_udp_from_ns "$EBPF_HOST_IP" 53 "DNS_TEST_QUERY" 2

    sleep 2

    # DNS metrics should reflect packet observation
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_dns|ebpfsentinel_packets"
}
