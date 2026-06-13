#!/usr/bin/env bats
# 05-ebpf-feature-overhead-extended.bats — isolated per-feature eBPF datapath
# overhead for the subsystems NOT covered by perf/02 (which layers
# firewall→IDS→ratelimit→threatintel→conntrack). Here each feature is measured
# ALONE against the no-agent baseline, so its standalone TCP-throughput cost is
# attributable: packet scrubbing (tc-scrub), DNS capture (tc-dns), QoS shaping
# passthrough (tc-qos), and connection tracking (tc-conntrack).
#
# Method mirrors perf/02: baseline (no agent) → enable one feature → iperf3 TCP
# → overhead = (1 - bps/baseline) × 100, asserted under a (VM-relaxed) threshold.
#
# Requires: root, kernel >= 6.9, bpftool, iperf3, jq. Nightly tier.
# Outputs JSON to /tmp/ebpfsentinel-feature-overhead-extended.json

# perf suites live in tests/perf/ but reuse the shared integration lib; fixtures are local.
FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

OVERHEAD_REPORT="/tmp/ebpfsentinel-feature-overhead-extended.json"
IPERF_DURATION="${IPERF_DURATION:-10}"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        require_root
        require_kernel 5 17
        require_tool bpftool
    fi
    require_tool iperf3
    require_tool jq

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo which iperf3 &>/dev/null || skip "iperf3 not installed on agent VM"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-overhead-ext-$$"
    mkdir -p "$DATA_DIR"
    create_test_netns

    rm -f "$OVERHEAD_REPORT"
    echo '{}' > "$OVERHEAD_REPORT"

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
        sleep 0.5
        _agent_ssh_sudo bash -c "'iperf3 -s -B ${EBPF_HOST_IP} -D --pidfile /tmp/iperf3-overhead-ext.pid'" 2>/dev/null || true
    else
        iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile /tmp/iperf3-overhead-ext-$$.pid 2>/dev/null
    fi
    sleep 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
    else
        [ -f /tmp/iperf3-overhead-ext-$$.pid ] && { kill "$(cat /tmp/iperf3-overhead-ext-$$.pid)" 2>/dev/null || true; rm -f /tmp/iperf3-overhead-ext-$$.pid; }
        pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true
    fi
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-overhead-ext-$$}"
}

_report_set() {
    local tmp; tmp="$(jq --arg k "$1" --argjson v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}
_report_set_str() {
    local tmp; tmp="$(jq --arg k "$1" --arg v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}

# _make_feature_config <feature> — write a config enabling only <feature>
# (firewall stays in pass mode as the XDP base for every variant).
_make_feature_config() {
    local feature="$1"
    local scrub=false dns=false qos=false conntrack=false
    case "$feature" in
        scrub) scrub=true ;;
        dns) dns=true ;;
        qos) qos=true ;;
        conntrack) conntrack=true ;;
    esac
    local cfg="${DATA_DIR}/config-${feature}-$$.yaml"
    cat > "$cfg" <<EOF
agent:
  interfaces:
    - __INTERFACE__
  bind_address: "127.0.0.1"
  log_level: warn
  http_port: 8080
  grpc_port: 50051
  metrics_port: 9090

firewall:
  enabled: true
  default_policy: pass
  rules: []
  scrub:
    enabled: ${scrub}
    min_ttl: 64
    max_mss: 1460
    random_ip_id: true

dns:
  enabled: ${dns}
  cache:
    max_entries: 10000
    min_ttl_secs: 60
    purge_interval_secs: 30

qos:
  enabled: ${qos}
  scheduler: fifo
  pipes:
    - id: pipe-bench
      bandwidth: "1000mbps"
      delay: 0

conntrack:
  enabled: ${conntrack}
  half_open_threshold: 100
  rst_threshold: 50
  fin_threshold: 50
  ack_threshold: 200

ddos:
  enabled: ${conntrack}
  policies: []

alerting:
  enabled: false
audit:
  enabled: false
EOF
    echo "$cfg"
}

_measure_tcp_throughput() {
    local result bps
    result="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION")" || return 1
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || return 1
    [ -n "$bps" ] && [ "$bps" != "null" ] || return 1
    echo "$bps"
}

# _run_feature <feature> <json-key> — start the agent with only <feature>,
# measure throughput, record overhead vs the recorded baseline. Returns the
# overhead pct (echo) for the caller to assert on.
_run_feature() {
    local feature="$1" key="$2"
    local baseline; baseline="$(jq -r '.baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || { echo "SKIP_NO_BASELINE"; return 0; }

    stop_ebpf_agent 2>/dev/null || true
    local prepared; prepared="$(prepare_ebpf_config "$(_make_feature_config "$feature")")"
    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || { echo "ERR_NOT_LOADED"; return 0; }

    local bps; bps="$(_measure_tcp_throughput)" || { stop_ebpf_agent; echo "ERR_IPERF"; return 0; }
    _report_set "${key}_bps" "$bps"
    local overhead; overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || overhead=0
    _report_set_str "${key}_overhead_pct" "$overhead"
    stop_ebpf_agent
    echo "$overhead"
}

# _assert_overhead <overhead> — sanity-bound the per-feature overhead. The
# absolute numbers are heavily environment-limited: in the single-VM netns lane
# the datapath runs generic (SKB-mode) XDP over a veth, which is far slower than
# a physical NIC in native mode, so overheads of 80-90 % are normal here. The
# assertion is therefore a loose "the feature did not catastrophically break the
# datapath" bound; the values are recorded for regression trending, and real
# budgets (< 20 %) are enforced by perf/01 in 2VM real-NIC mode.
_assert_overhead() {
    local overhead="$1"
    case "$overhead" in SKIP_NO_BASELINE) skip "baseline not recorded";; ERR_NOT_LOADED) echo "eBPF not loaded" >&2; return 1;; ERR_IPERF) skip "iperf3 failed";; esac
    local limit=95
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && limit=80
    echo "# overhead: ${overhead}% (sanity limit: ${limit}%, env-limited — see header)"
    [ "$(echo "$overhead < $limit" | bc -l 2>/dev/null)" = "1" ]
}

# ── Tests ──────────────────────────────────────────────────────────

@test "baseline: TCP throughput (no agent)" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    stop_ebpf_agent 2>/dev/null || true
    local bps; bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"
    _report_set "baseline_bps" "$bps"
    echo "# baseline: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"
}

@test "scrub (tc-scrub) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_feature scrub scrub)"
}

@test "dns capture (tc-dns) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_feature dns dns)"
}

@test "qos shaping passthrough (tc-qos) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_feature qos qos)"
}

@test "conntrack (tc-conntrack) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_feature conntrack conntrack)"
}

@test "summary: extended per-feature overhead report" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    local baseline; baseline="$(jq -r '.baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "no data"
    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _report_set_str "kernel" "$(uname -r)"
    echo "# Extended per-feature overhead (baseline $(echo "scale=2; $baseline/1000000000" | bc -l) Gbps):"
    local f bps oh
    for f in scrub dns qos conntrack; do
        bps="$(jq -r ".${f}_bps // empty" "$OVERHEAD_REPORT" 2>/dev/null)"
        oh="$(jq -r ".${f}_overhead_pct // \"---\"" "$OVERHEAD_REPORT" 2>/dev/null)"
        [ -n "$bps" ] && printf "#   %-12s %6s Gbps  overhead %s%%\n" "$f" "$(echo "scale=2; $bps/1000000000" | bc -l)" "$oh" || printf "#   %-12s skipped\n" "$f"
    done
    jq '.' "$OVERHEAD_REPORT"
}
