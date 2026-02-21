#!/usr/bin/env bats
# 15-performance-benchmark.bats — Performance benchmarks (throughput + resource usage)
# Requires: root, kernel >= 5.17, bpftool, iperf3
#
# Outputs JSON report to /tmp/ebpfsentinel-benchmark-latest.json

load '../lib/helpers'
load '../lib/ebpf_helpers'

BENCHMARK_REPORT="/tmp/ebpfsentinel-benchmark-latest.json"

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool iperf3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-bench-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Initialize benchmark report
    echo '{}' > "$BENCHMARK_REPORT"

    # Start iperf3 server on the host side
    iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile /tmp/iperf3-bench-$$.pid 2>/dev/null
    sleep 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true

    # Stop iperf3 server
    if [ -f /tmp/iperf3-bench-$$.pid ]; then
        kill "$(cat /tmp/iperf3-bench-$$.pid)" 2>/dev/null || true
        rm -f /tmp/iperf3-bench-$$.pid
    fi
    # Kill any leftover iperf3 on our bind address
    pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true

    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-bench-$$}"
}

# ── Helper: update JSON report ──────────────────────────────────────

_report_set() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --argjson v "$value" '. + {($k): $v}' "$BENCHMARK_REPORT")"
    echo "$tmp" > "$BENCHMARK_REPORT"
}

_report_set_str() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' "$BENCHMARK_REPORT")"
    echo "$tmp" > "$BENCHMARK_REPORT"
}

# ── Baseline tests (no agent) ──────────────────────────────────────

@test "baseline: TCP throughput (no agent)" {
    require_root
    require_tool iperf3

    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 5)" || skip "iperf3 failed"

    local bps
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || true

    [ -n "$bps" ] && [ "$bps" != "null" ]
    _report_set "baseline_tcp_bps" "$bps"
}

@test "baseline: UDP throughput (no agent)" {
    require_root
    require_tool iperf3

    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 5 "-u -b 0")" || skip "iperf3 failed"

    local bps
    bps="$(echo "$result" | jq '.end.sum.bits_per_second' 2>/dev/null)" || true

    [ -n "$bps" ] && [ "$bps" != "null" ]
    _report_set "baseline_udp_bps" "$bps"
}

@test "baseline: resource usage snapshot" {
    require_root

    local mem_total mem_available
    mem_total="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
    mem_available="$(grep MemAvailable /proc/meminfo | awk '{print $2}')"

    _report_set "baseline_mem_total_kb" "$mem_total"
    _report_set "baseline_mem_available_kb" "$mem_available"

    [ -n "$mem_total" ]
}

# ── Agent-loaded tests ──────────────────────────────────────────────

@test "start agent with full eBPF stack" {
    require_root

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-benchmark.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded (degraded mode)"

    # Record agent PID for later checks
    _report_set "agent_pid" "$AGENT_PID"
}

@test "with-agent: TCP throughput" {
    require_root
    require_tool iperf3

    # Ensure agent is running
    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 5)" || skip "iperf3 failed"

    local bps
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || true

    [ -n "$bps" ] && [ "$bps" != "null" ]
    _report_set "agent_tcp_bps" "$bps"
}

@test "with-agent: UDP throughput" {
    require_root
    require_tool iperf3

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 5 "-u -b 0")" || skip "iperf3 failed"

    local bps
    bps="$(echo "$result" | jq '.end.sum.bits_per_second' 2>/dev/null)" || true

    [ -n "$bps" ] && [ "$bps" != "null" ]
    _report_set "agent_udp_bps" "$bps"
}

@test "with-agent: resource usage snapshot" {
    require_root

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local mem_available
    mem_available="$(grep MemAvailable /proc/meminfo | awk '{print $2}')"

    _report_set "agent_mem_available_kb" "$mem_available"

    [ -n "$mem_available" ]
}

@test "agent memory footprint under 256MB RSS" {
    require_root

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local pid
    pid="$(cat "$AGENT_PID_FILE")"

    # Read VmRSS from /proc (in kB)
    local rss_kb
    rss_kb="$(grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || skip "cannot read agent /proc"

    _report_set "agent_rss_kb" "$rss_kb"

    local max_rss_kb=262144  # 256 MB in kB
    [ "$rss_kb" -lt "$max_rss_kb" ]
}

@test "throughput overhead summary (<20%)" {
    require_root

    # Read baseline and agent values from report
    local baseline_tcp agent_tcp
    baseline_tcp="$(jq -r '.baseline_tcp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true
    agent_tcp="$(jq -r '.agent_tcp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true

    if [ -z "$baseline_tcp" ] || [ -z "$agent_tcp" ]; then
        skip "baseline or agent TCP throughput not recorded"
    fi

    # Calculate overhead percentage
    local overhead
    overhead="$(echo "scale=2; (1 - ($agent_tcp / $baseline_tcp)) * 100" | bc -l 2>/dev/null)" || true

    if [ -n "$overhead" ]; then
        _report_set_str "tcp_overhead_pct" "$overhead"

        # Assert overhead < 20%
        local is_ok
        is_ok="$(echo "$overhead < 20" | bc -l 2>/dev/null)" || true
        [ "${is_ok:-0}" = "1" ]
    else
        skip "could not compute overhead"
    fi

    # Also compute UDP overhead
    local baseline_udp agent_udp
    baseline_udp="$(jq -r '.baseline_udp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true
    agent_udp="$(jq -r '.agent_udp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true

    if [ -n "$baseline_udp" ] && [ -n "$agent_udp" ]; then
        local udp_overhead
        udp_overhead="$(echo "scale=2; (1 - ($agent_udp / $baseline_udp)) * 100" | bc -l 2>/dev/null)" || true
        if [ -n "$udp_overhead" ]; then
            _report_set_str "udp_overhead_pct" "$udp_overhead"
        fi
    fi

    # Finalize report with timestamp
    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _report_set_str "kernel" "$(uname -r)"

    # Print summary to stdout
    echo "# Benchmark Report: ${BENCHMARK_REPORT}"
    jq '.' "$BENCHMARK_REPORT"
}
