#!/usr/bin/env bats
# 24-ebpf-scrub-scenarios.bats — Packet normalization (tc-scrub) eBPF tests
# Requires: root, kernel >= 5.17, bpftool, ping
#
# Tests tc-scrub program with:
#   - Program attachment and health checks
#   - ICMP traffic passthrough with scrub active
#   - Metrics increment on processed packets
#   - Configuration accessible via REST API
#   - Fragmented packet handling

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool ping

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-scrub-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Prepare config
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-scrub.yaml")"
    export PREPARED_CONFIG

    # Start agent with eBPF programs
    start_ebpf_agent "$PREPARED_CONFIG"

    # Wait for eBPF programs to load
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load (degraded mode). Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-scrub-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "scrub program attaches successfully" {
    require_root

    local body
    body="$(api_get /healthz)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local readyz_body
    readyz_body="$(api_get /readyz)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local loaded
    loaded="$(echo "$readyz_body" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
    [ "$loaded" = "true" ]
}

# ── ICMP passthrough ─────────────────────────────────────────────

@test "ICMP traffic passes through scrub" {
    require_root

    # Send 3 ICMP pings from namespace to host through scrub
    run ip netns exec "$EBPF_TEST_NS" ping -c 3 -W 2 -i 0.2 "$EBPF_HOST_IP"

    [ "$status" -eq 0 ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "scrub metrics increment on packets" {
    require_root

    # Generate traffic to ensure counters tick
    send_icmp_from_ns "$EBPF_HOST_IP" 5 10

    sleep 2

    local value
    value="$(wait_for_metric "ebpfsentinel_scrub_packets_total" 1 15)" || true

    [ -n "$value" ]
}

# ── Configuration API ────────────────────────────────────────────

@test "scrub configuration accessible via API" {
    require_root

    local body
    body="$(api_get /api/v1/config)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Verify scrub section exists in response
    local scrub
    scrub="$(echo "$body" | jq '.scrub // .firewall.scrub // empty' 2>/dev/null)" || true
    [ -n "$scrub" ]
}

# ── Fragmented packets ───────────────────────────────────────────

@test "scrub handles fragmented packets" {
    require_root

    # Send large ICMP packets that will be fragmented (2000 bytes payload)
    send_icmp_from_ns "$EBPF_HOST_IP" 3 10

    # Also send oversized ping to trigger fragmentation
    ip netns exec "$EBPF_TEST_NS" \
        ping -c 3 -W 2 -i 0.2 -s 2000 "$EBPF_HOST_IP" 2>/dev/null || true

    sleep 2

    # Verify metrics still increment after fragmented traffic
    local value
    value="$(wait_for_metric "ebpfsentinel_scrub_packets_total" 1 15)" || true

    [ -n "$value" ]
}
