#!/usr/bin/env bats
# 01-performance-benchmark.bats — Performance benchmarks (throughput + resource usage)
# Requires: root, kernel >= 6.9, bpftool, iperf3
#
# Each throughput point is sampled IPERF_SAMPLES times and reduced to a median;
# the spread of the no-agent samples becomes the run's noise floor, and the
# overhead gate is the larger of the budget and that floor. See the measurement
# parameters below for why.
#
# Outputs JSON report to /tmp/ebpfsentinel-benchmark-latest.json

# perf suites live in tests/perf/ but reuse the shared integration lib; fixtures are local.
FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

BENCHMARK_REPORT="/tmp/ebpfsentinel-benchmark-latest.json"

# Every number below travels through printf, sort -g, awk, bc and jq. Under a
# comma-decimal locale those disagree about what "941772835.6" means — sort -g
# stops ordering and printf rejects the value outright — so the whole suite
# runs in the C locale.
export LC_ALL=C

# ── Measurement parameters ─────────────────────────────────────────
#
# One 5-second iperf3 run over a veth pair is dominated by scheduler noise:
# back-to-back runs of the *same* configuration routinely differ by tens of
# percent on a virtual NIC. Comparing two such single runs measures the host's
# mood, not the agent. So every measurement point is sampled several times and
# reduced to a median, and the spread of the no-agent samples is kept as the
# run's own noise floor: an overhead smaller than that floor is not something
# this environment can resolve, and gating on it would only produce flakes.

# Samples per measurement point, and the duration of each one.
IPERF_SAMPLES="${IPERF_SAMPLES:-5}"
IPERF_DURATION="${IPERF_DURATION:-5}"

# Throughput the agent is allowed to cost, as a percentage of the no-agent
# median. The gate is the larger of this and the measured noise floor.
TCP_OVERHEAD_BUDGET_PCT="${TCP_OVERHEAD_BUDGET_PCT:-20}"

# A run whose own baseline samples spread wider than this cannot resolve the
# budget at all — the box is too unstable to benchmark on, and any verdict it
# produced would be a coin flip.
MAX_BASELINE_NOISE_PCT="${MAX_BASELINE_NOISE_PCT:-25}"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
        require_kernel 5 17
        require_tool bpftool
    fi
    require_tool iperf3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-bench-$$"
    mkdir -p "$DATA_DIR"

    # Ensure no agent from a previous suite is still attached (it would throttle
    # the "no agent" baseline and silently invalidate the overhead figures).
    stop_ebpf_agent 2>/dev/null || true

    # Create netns + veth pair
    create_test_netns

    # Initialize benchmark report (remove stale file from previous root run)
    rm -f "$BENCHMARK_REPORT"
    echo '{}' > "$BENCHMARK_REPORT"

    # Start the iperf3 server. In 2-VM mode the agent is the iperf target
    # (EBPF_HOST_IP = the agent VM), so the server must run ON THE AGENT — not on
    # the attacker VM that runs bats. Starting it locally there fails to bind the
    # agent's IP, leaving the baseline client with no server (it hangs/skips).
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill iperf3 2>/dev/null || true
        sleep 0.5
        _agent_ssh_sudo bash -c "'iperf3 -s -B ${EBPF_HOST_IP} -D --pidfile /tmp/iperf3-bench.pid'" 2>/dev/null || true
    else
        iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile /tmp/iperf3-bench-$$.pid 2>/dev/null
    fi
    sleep 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true

    # Stop iperf3 server (on the agent VM in 2-VM mode, locally otherwise).
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill iperf3 2>/dev/null || true
    else
        if [ -f /tmp/iperf3-bench-$$.pid ]; then
            kill "$(cat /tmp/iperf3-bench-$$.pid)" 2>/dev/null || true
            rm -f /tmp/iperf3-bench-$$.pid
        fi
        pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true
    fi

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

# ── Helper: sampled throughput ─────────────────────────────────────

# _iperf_samples [extra iperf3 args] — echo IPERF_SAMPLES bits/s readings,
# space separated. Failed runs are dropped rather than counted as zero, which
# would drag the median toward a number no measurement produced.
_iperf_samples() {
    local extra="${1:-}"
    local i result bps out=""

    for ((i = 0; i < IPERF_SAMPLES; i++)); do
        if [ -n "$extra" ]; then
            result="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION" "$extra")" || continue
            bps="$(echo "$result" | jq '.end.sum.bits_per_second' 2>/dev/null)" || continue
        else
            result="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION")" || continue
            bps="$(echo "$result" | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || continue
        fi
        if [ -n "$bps" ] && [ "$bps" != "null" ]; then
            # Round to whole bits/s: sub-bit precision is meaningless here, and
            # jq's exponent notation for large values would defeat `sort -g`.
            out+="$(awk -v b="$bps" 'BEGIN { printf "%.0f", b }') "
        fi
        # Let the NIC queues drain so consecutive samples stay independent.
        sleep 1
    done

    echo "${out% }"
}

_median() {
    printf '%s\n' "$@" | sort -g | awk '
        {v[NR] = $1}
        END {
            if (NR == 0) exit 1
            if (NR % 2) printf "%.0f", v[(NR + 1) / 2]
            else printf "%.0f", (v[NR / 2] + v[NR / 2 + 1]) / 2
        }'
}

# Spread of the samples as a percentage of their median — the smallest
# overhead this run can tell apart from noise.
_spread_pct() {
    printf '%s\n' "$@" | sort -g | awk '
        {v[NR] = $1}
        END {
            if (NR < 2) { print "0.00"; exit }
            med = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
            if (med <= 0) { print "0.00"; exit }
            printf "%.2f", (v[NR] - v[1]) / med * 100
        }'
}

_report_samples() {
    local key="$1"
    shift
    local json
    json="$(printf '%s\n' "$@" | jq -cs '.')" || return 0
    _report_set "$key" "$json"
}

# ── Baseline tests (no agent) ──────────────────────────────────────

@test "baseline: TCP throughput (no agent)" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    require_tool iperf3

    local samples
    samples="$(_iperf_samples)"
    [ -n "$samples" ] || skip "iperf3 produced no usable sample"

    # shellcheck disable=SC2086  # the sample list must expand to separate args
    _report_samples "baseline_tcp_samples" $samples
    # shellcheck disable=SC2086
    _report_set "baseline_tcp_bps" "$(_median $samples)"
    # shellcheck disable=SC2086
    _report_set_str "baseline_tcp_noise_pct" "$(_spread_pct $samples)"
}

@test "baseline: UDP throughput (no agent)" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    require_tool iperf3

    local samples
    samples="$(_iperf_samples "-u -b 0")"
    [ -n "$samples" ] || skip "iperf3 produced no usable sample"

    # shellcheck disable=SC2086
    _report_samples "baseline_udp_samples" $samples
    # shellcheck disable=SC2086
    _report_set "baseline_udp_bps" "$(_median $samples)"
    # shellcheck disable=SC2086
    _report_set_str "baseline_udp_noise_pct" "$(_spread_pct $samples)"
}

@test "baseline: resource usage snapshot" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    local mem_total mem_available
    mem_total="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
    mem_available="$(grep MemAvailable /proc/meminfo | awk '{print $2}')"

    _report_set "baseline_mem_total_kb" "$mem_total"
    _report_set "baseline_mem_available_kb" "$mem_available"

    [ -n "$mem_total" ]
}

# ── Agent-loaded tests ──────────────────────────────────────────────

@test "start agent with full eBPF stack" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-benchmark.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }

    # Record agent PID for later checks
    _report_set "agent_pid" "$AGENT_PID"
}

@test "with-agent: TCP throughput" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    require_tool iperf3

    # Ensure agent is running
    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local samples
    samples="$(_iperf_samples)"
    [ -n "$samples" ] || skip "iperf3 produced no usable sample"

    # shellcheck disable=SC2086
    _report_samples "agent_tcp_samples" $samples
    # shellcheck disable=SC2086
    _report_set "agent_tcp_bps" "$(_median $samples)"
    # shellcheck disable=SC2086
    _report_set_str "agent_tcp_noise_pct" "$(_spread_pct $samples)"
}

@test "with-agent: UDP throughput" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    require_tool iperf3

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local samples
    samples="$(_iperf_samples "-u -b 0")"
    [ -n "$samples" ] || skip "iperf3 produced no usable sample"

    # shellcheck disable=SC2086
    _report_samples "agent_udp_samples" $samples
    # shellcheck disable=SC2086
    _report_set "agent_udp_bps" "$(_median $samples)"
    # shellcheck disable=SC2086
    _report_set_str "agent_udp_noise_pct" "$(_spread_pct $samples)"
}

@test "with-agent: resource usage snapshot" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local mem_available
    mem_available="$(grep MemAvailable /proc/meminfo | awk '{print $2}')"

    _report_set "agent_mem_available_kb" "$mem_available"

    [ -n "$mem_available" ]
}

@test "agent memory footprint under 256MB RSS" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"

    local pid
    pid="$(cat "$AGENT_PID_FILE")"

    # Read VmRSS from /proc (in kB)
    local rss_kb
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        rss_kb="$(_agent_ssh_sudo grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || skip "cannot read agent /proc on remote"
    else
        rss_kb="$(grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || skip "cannot read agent /proc"
    fi

    _report_set "agent_rss_kb" "$rss_kb"

    local max_rss_kb=262144  # 256 MB in kB
    [ "$rss_kb" -lt "$max_rss_kb" ]
}

@test "TCP throughput overhead within budget" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    local baseline_tcp agent_tcp noise
    baseline_tcp="$(jq -r '.baseline_tcp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true
    agent_tcp="$(jq -r '.agent_tcp_bps // empty' "$BENCHMARK_REPORT" 2>/dev/null)" || true
    noise="$(jq -r '.baseline_tcp_noise_pct // "0"' "$BENCHMARK_REPORT" 2>/dev/null)" || noise=0

    if [ -z "$baseline_tcp" ] || [ -z "$agent_tcp" ]; then
        skip "baseline or agent TCP throughput not recorded"
    fi

    local overhead
    overhead="$(echo "scale=2; (1 - ($agent_tcp / $baseline_tcp)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] || skip "could not compute overhead"
    _report_set_str "tcp_overhead_pct" "$overhead"

    # The gate is the budget or the run's own noise floor, whichever is
    # larger: below the floor, an "overhead" is indistinguishable from two
    # consecutive baseline runs disagreeing with each other.
    local threshold
    threshold="$(echo "if ($noise > $TCP_OVERHEAD_BUDGET_PCT) $noise else $TCP_OVERHEAD_BUDGET_PCT" | bc -l 2>/dev/null)"
    _report_set_str "tcp_overhead_threshold_pct" "$threshold"

    if [ "$(echo "$noise > $MAX_BASELINE_NOISE_PCT" | bc -l 2>/dev/null)" = "1" ]; then
        skip "baseline spread ${noise}% exceeds ${MAX_BASELINE_NOISE_PCT}% — too noisy to resolve a ${TCP_OVERHEAD_BUDGET_PCT}% budget"
    fi

    if [ "$(echo "$overhead <= $threshold" | bc -l 2>/dev/null)" != "1" ]; then
        echo "TCP overhead ${overhead}% exceeds ${threshold}% (budget ${TCP_OVERHEAD_BUDGET_PCT}%, baseline spread ${noise}%)" >&2
        echo "  baseline median ${baseline_tcp} bps, with-agent median ${agent_tcp} bps" >&2
        return 1
    fi

    # UDP is reported, not gated: `-u -b 0` saturates the sender's CPU rather
    # than the link, so it measures the load generator as much as the agent.
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
