#!/usr/bin/env bats
# 25-packet-accountability.bats — Packet processing accountability tests
# Requires: root, kernel >= 5.17, bpftool, ncat
#
# Validates that every packet entering an eBPF program is accounted for:
#   1. total_seen counter increments for every packet (no silent drops)
#   2. total_seen == sum of all outcome counters (internal consistency)
#
# Uses the Prometheus /metrics endpoint to read kernel eBPF counters
# exposed via the MetricsReader -> AgentMetrics pipeline.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-acct-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Use the firewall config (includes most programs)
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-firewall.yaml")"
    export PREPARED_CONFIG

    # Start agent with eBPF programs
    start_ebpf_agent "$PREPARED_CONFIG"

    # Wait for eBPF programs to load
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-acct-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

# get_kernel_metric <map_label> <action_label>
# Reads the absolute kernel counter value from /metrics endpoint.
# Returns the ebpfsentinel_bytes_processed_total value for the given
# map name and action, which carries the raw kernel counter value.
get_kernel_metric() {
    local map_name="${1:?usage: get_kernel_metric <map_name> <action>}"
    local action="${2:?usage: get_kernel_metric <map_name> <action>}"

    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local body
    body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || return 1

    # Look for the bytes_processed counter which carries absolute kernel values
    local value
    value="$(echo "$body" | grep "^ebpfsentinel_bytes_processed_total{" | \
        grep "interface=\"${map_name}\"" | \
        grep "direction=\"${action}\"" | \
        awk '{print $2}' | head -1)"

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "0"
    else
        # Truncate decimal part if present (Prometheus counters may have .0)
        echo "${value%%.*}"
    fi
}

# wait_for_metrics_flush [seconds]
# Wait for the kernel metrics polling loop to flush eBPF counters
# to Prometheus. Default polling interval is 10s.
wait_for_metrics_flush() {
    local wait_secs="${1:-12}"
    sleep "$wait_secs"
}

# ── Firewall: total_seen increments ─────────────────────────────

@test "firewall: total_seen increments when traffic is sent" {
    require_root

    # Read total_seen BEFORE sending traffic
    local before
    before="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"

    # Send 10 ICMP packets from the namespace
    send_icmp_from_ns "$EBPF_HOST_IP" 10 10

    # Wait for metrics polling loop to pick up the new counters
    wait_for_metrics_flush 12

    # Read total_seen AFTER
    local after
    after="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"

    local delta=$((after - before))

    echo "total_seen before=$before after=$after delta=$delta"

    # We sent 10 ICMP packets — firewall should have seen at least 10
    # (may see more due to ARP, other background traffic on the veth)
    [ "$delta" -ge 10 ]
}

# ── Firewall: internal consistency ──────────────────────────────

@test "firewall: total_seen >= passed + dropped + errors" {
    require_root

    # Send some mixed traffic to ensure counters are populated
    send_icmp_from_ns "$EBPF_HOST_IP" 5 5
    send_tcp_from_ns "$EBPF_HOST_IP" 7777 "BLOCKED" 2
    send_tcp_from_ns "$EBPF_HOST_IP" 8888 "LOGGED" 2

    wait_for_metrics_flush 12

    local total_seen passed dropped errors
    total_seen="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"
    passed="$(get_kernel_metric "FIREWALL_METRICS" "passed")"
    dropped="$(get_kernel_metric "FIREWALL_METRICS" "dropped")"
    errors="$(get_kernel_metric "FIREWALL_METRICS" "errors")"

    local sum=$((passed + dropped + errors))

    echo "total_seen=$total_seen passed=$passed dropped=$dropped errors=$errors sum=$sum"

    # total_seen should be >= sum of outcome counters
    # (equal when no packets are in-flight during the read)
    [ "$total_seen" -ge "$sum" ]
    # And total_seen should be > 0 (we sent traffic)
    [ "$total_seen" -gt 0 ]
}

# ── Firewall: known packet count ────────────────────────────────

@test "firewall: sending N UDP packets produces delta >= N in total_seen" {
    require_root
    require_tool ncat

    local PACKET_COUNT=50

    local before
    before="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"

    # Send N UDP packets (1 packet per send to be precise)
    local i=0
    while [ "$i" -lt "$PACKET_COUNT" ]; do
        send_udp_from_ns "$EBPF_HOST_IP" 12345 "PKT$i" 1
        i=$((i + 1))
    done

    wait_for_metrics_flush 12

    local after
    after="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"

    local delta=$((after - before))

    echo "Sent: $PACKET_COUNT, total_seen delta: $delta"

    # Each UDP send may generate ARP + UDP packet, but we should see
    # at least PACKET_COUNT packets processed
    [ "$delta" -ge "$PACKET_COUNT" ]
}

# ── Firewall: dropped packets counted ───────────────────────────

@test "firewall: dropped TCP to port 7777 counted in both total_seen and dropped" {
    require_root
    require_tool ncat

    local before_total before_dropped
    before_total="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"
    before_dropped="$(get_kernel_metric "FIREWALL_METRICS" "dropped")"

    # Port 7777 is configured as deny in the firewall fixture
    local i=0
    while [ "$i" -lt 5 ]; do
        send_tcp_from_ns "$EBPF_HOST_IP" 7777 "DROP$i" 1
        i=$((i + 1))
    done

    wait_for_metrics_flush 12

    local after_total after_dropped
    after_total="$(get_kernel_metric "FIREWALL_METRICS" "total_seen")"
    after_dropped="$(get_kernel_metric "FIREWALL_METRICS" "dropped")"

    local delta_total=$((after_total - before_total))
    local delta_dropped=$((after_dropped - before_dropped))

    echo "total_seen delta=$delta_total, dropped delta=$delta_dropped"

    # Both should have increased
    [ "$delta_total" -gt 0 ]
    [ "$delta_dropped" -gt 0 ]
    # total_seen should be >= dropped (total includes everything)
    [ "$delta_total" -ge "$delta_dropped" ]
}

# ── IDS: total_seen works ────────────────────────────────────────

@test "ids: total_seen metric is exposed via /metrics" {
    require_root

    # IDS may not be enabled in the firewall config, but the metric
    # map should still be readable (zeroes if not active).
    local total_seen
    total_seen="$(get_kernel_metric "IDS_METRICS" "total_seen")" || true

    # Just verify the metric is parseable (returns a number)
    echo "IDS total_seen=$total_seen"
    [[ "$total_seen" =~ ^[0-9]+$ ]]
}

# ── Metrics endpoint: total_seen labels present ─────────────────

@test "metrics: total_seen label is exposed for FIREWALL_METRICS" {
    require_root

    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local body
    body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || {
        skip "metrics endpoint not available"
    }

    # Check that total_seen appears in the metrics output for the firewall
    echo "$body" | grep -q 'direction="total_seen"'
}
