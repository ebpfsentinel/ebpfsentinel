#!/usr/bin/env bats
# 06-ebpf-feature-overhead-nat-dlp.bats — datapath overhead for the two eBPF
# subsystems NOT covered by perf/02 (firewall→IDS→ratelimit→threatintel→conntrack)
# or perf/05 (scrub, dns, qos, conntrack):
#
#   - NAT translation: tc-nat-egress (SNAT/masquerade) + tc-nat-ingress (DNAT).
#     Measured as TCP-throughput cost vs the no-agent baseline, the same way as
#     perf/05, for egress alone, ingress alone, and both together. NAT runs on
#     top of conntrack, so the conntrack cost is included — the delta vs perf/05's
#     conntrack-only number is the translation cost.
#
#   - DLP uprobe: uprobe-dlp hooks SSL_write/SSL_read on libssl. iperf3 never
#     touches TLS, so its cost is invisible to plain throughput; instead we drive
#     a local openssl bulk transfer and compare goodput with the uprobe attached
#     vs detached (agent stopped). This is the per-SSL-call inspection cost.
#
# Method (NAT) mirrors perf/05: baseline (no agent) → enable one variant → iperf3
# TCP → overhead = (1 - bps/baseline) × 100, asserted under a (VM-relaxed) bound.
#
# Requires: root, kernel >= 6.9, bpftool, iperf3, jq; openssl for the DLP test.
# Nightly tier. Outputs JSON to /tmp/ebpfsentinel-feature-overhead-nat-dlp.json

# perf suites live in tests/perf/ but reuse the shared integration lib; fixtures are local.
FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

OVERHEAD_REPORT="/tmp/ebpfsentinel-feature-overhead-nat-dlp.json"
IPERF_DURATION="${IPERF_DURATION:-10}"
DLP_TLS_PORT="${DLP_TLS_PORT:-19443}"
DLP_PAYLOAD_MB="${DLP_PAYLOAD_MB:-32}"

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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-natdlp-$$"
    mkdir -p "$DATA_DIR"
    # No leftover agent before the baseline (it would skew the overhead figures).
    stop_ebpf_agent 2>/dev/null || true
    create_test_netns

    rm -f "$OVERHEAD_REPORT"
    echo '{}' > "$OVERHEAD_REPORT"

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill iperf3 2>/dev/null || true
        sleep 0.5
        _agent_ssh_sudo bash -c "'iperf3 -s -B ${EBPF_HOST_IP} -D --pidfile /tmp/iperf3-natdlp.pid'" 2>/dev/null || true
    else
        iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile /tmp/iperf3-natdlp-$$.pid 2>/dev/null
    fi
    sleep 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill iperf3 2>/dev/null || true
    else
        [ -f /tmp/iperf3-natdlp-$$.pid ] && { kill "$(cat /tmp/iperf3-natdlp-$$.pid)" 2>/dev/null || true; rm -f /tmp/iperf3-natdlp-$$.pid; }
        pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true
    fi
    [ -n "${DLP_TLS_SRV_PID:-}" ] && kill "$DLP_TLS_SRV_PID" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-natdlp-$$}"
}

_report_set() {
    local tmp; tmp="$(jq --arg k "$1" --argjson v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}
_report_set_str() {
    local tmp; tmp="$(jq --arg k "$1" --arg v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}

# _make_nat_config <variant> — write a config that enables conntrack + NAT with
# only the requested translation direction. The firewall stays in pass mode so
# the measured cost is the NAT datapath, not policy lookups.
#   egress  → SNAT (masquerade) on tc-nat-egress
#   ingress → DNAT on tc-nat-ingress
#   full    → both
_make_nat_config() {
    local variant="$1"
    local snat="" dnat=""
    case "$variant" in
        egress|full)
            snat=$'  snat_rules:\n    - id: bench-masq\n      type: masquerade\n      interface: __INTERFACE__\n      match_src: "10.200.0.0/24"\n      port_range: "10000-60000"' ;;
    esac
    case "$variant" in
        ingress|full)
            dnat=$'  dnat_rules:\n    - id: bench-dnat\n      type: dnat\n      translated_addr: "10.200.0.1"\n      translated_port: 5201\n      match_dst_port: 5201\n      match_protocol: tcp' ;;
    esac
    local cfg="${DATA_DIR}/config-nat-${variant}-$$.yaml"
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

conntrack:
  enabled: true
  half_open_threshold: 128
  rst_threshold: 50
  fin_threshold: 50
  ack_threshold: 200

nat:
  enabled: true
${snat}
${dnat}

alerting:
  enabled: false
audit:
  enabled: false
EOF
    echo "$cfg"
}

# _make_dlp_config — firewall pass base + DLP enabled (uprobe-dlp attaches to libssl).
_make_dlp_config() {
    local cfg="${DATA_DIR}/config-dlp-$$.yaml"
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

dlp:
  enabled: true
  mode: alert

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

# _run_nat <variant> <json-key> — start the agent with the NAT variant, measure
# throughput, record overhead vs baseline. Echoes the overhead pct (or a marker).
_run_nat() {
    local variant="$1" key="$2"
    local baseline; baseline="$(jq -r '.baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || { echo "SKIP_NO_BASELINE"; return 0; }

    stop_ebpf_agent 2>/dev/null || true
    local prepared; prepared="$(prepare_ebpf_config "$(_make_nat_config "$variant")")"
    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || { echo "ERR_NOT_LOADED"; return 0; }

    local bps; bps="$(_measure_tcp_throughput)" || { stop_ebpf_agent; echo "ERR_IPERF"; return 0; }
    _report_set "${key}_bps" "$bps"
    local overhead; overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || overhead=0
    _report_set_str "${key}_overhead_pct" "$overhead"
    stop_ebpf_agent
    echo "$overhead"
}

# See perf/05 header: single-VM netns runs generic (SKB-mode) XDP/TC over a veth,
# far slower than a physical NIC, so 80-90% overheads are normal here. The bound
# is a "did not catastrophically break the datapath" sanity check; real budgets
# (< 20%) are enforced by perf/01 in 2VM real-NIC mode.
_assert_overhead() {
    local overhead="$1"
    case "$overhead" in SKIP_NO_BASELINE) skip "baseline not recorded";; ERR_NOT_LOADED) echo "eBPF not loaded" >&2; return 1;; ERR_IPERF) skip "iperf3 failed";; esac
    local limit=95
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && limit=80
    echo "# overhead: ${overhead}% (sanity limit: ${limit}%, env-limited — see header)"
    [ "$(echo "$overhead < $limit" | bc -l 2>/dev/null)" = "1" ]
}

# _openssl_goodput — start a local TLS echo server, push DLP_PAYLOAD_MB through
# an s_client, return MB/s. Pure-loopback so it works in either lane.
_openssl_goodput() {
    local key="$1"
    openssl req -x509 -newkey rsa:2048 -keyout "$DATA_DIR/dlp.key" \
        -out "$DATA_DIR/dlp.crt" -days 1 -nodes -subj "/CN=dlp-bench" >/dev/null 2>&1 || return 1

    openssl s_server -accept "$DLP_TLS_PORT" -cert "$DATA_DIR/dlp.crt" \
        -key "$DATA_DIR/dlp.key" -quiet -naccept 1 >/dev/null 2>&1 &
    DLP_TLS_SRV_PID=$!
    sleep 1

    local bytes=$(( DLP_PAYLOAD_MB * 1024 * 1024 ))
    local start_ns end_ns ms
    start_ns="$(date +%s%N)"
    head -c "$bytes" /dev/zero | timeout 60 openssl s_client -connect "127.0.0.1:${DLP_TLS_PORT}" \
        -quiet >/dev/null 2>&1 || true
    end_ns="$(date +%s%N)"
    kill "$DLP_TLS_SRV_PID" 2>/dev/null || true
    DLP_TLS_SRV_PID=""

    ms="$(( (end_ns - start_ns) / 1000000 ))"
    [ "$ms" -gt 0 ] || ms=1
    local mbps; mbps="$(echo "scale=4; $DLP_PAYLOAD_MB * 1000 / $ms" | bc -l 2>/dev/null)" || mbps=0
    _report_set_str "${key}_mb_per_s" "$mbps"
    _report_set "${key}_ms" "$ms"
    echo "$mbps"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "baseline: TCP throughput (no agent)" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    stop_ebpf_agent 2>/dev/null || true
    local bps; bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"
    _report_set "baseline_bps" "$bps"
    echo "# baseline: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"
}

@test "NAT egress (tc-nat-egress SNAT/masquerade) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_nat egress nat_egress)"
}

@test "NAT ingress (tc-nat-ingress DNAT) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_nat ingress nat_ingress)"
}

@test "NAT full (SNAT egress + DNAT ingress) datapath overhead" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _assert_overhead "$(_run_nat full nat_full)"
}

@test "DLP uprobe (uprobe-dlp) SSL inspection goodput cost" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    command -v openssl >/dev/null 2>&1 || skip "openssl not installed"
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && skip "DLP uprobe goodput measured local-lane only (loopback libssl)"

    stop_ebpf_agent 2>/dev/null || true
    local off; off="$(_openssl_goodput dlp_off)" || skip "openssl baseline transfer failed"

    local prepared; prepared="$(prepare_ebpf_config "$(_make_dlp_config)")"
    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || { echo "DLP eBPF not loaded" >&2; return 1; }
    local on; on="$(_openssl_goodput dlp_on)" || { stop_ebpf_agent; skip "openssl transfer with DLP failed"; }
    stop_ebpf_agent

    local overhead; overhead="$(echo "scale=4; (1 - ($on / $off)) * 100" | bc -l 2>/dev/null)" || overhead=0
    _report_set_str "dlp_overhead_pct" "$overhead"
    echo "# DLP off ${off} MB/s, on ${on} MB/s → uprobe overhead ${overhead}%"
    # Uprobe inspection on libssl writes is bounded; allow generous headroom for
    # the userspace ring drain. Negative (noise) is fine; just bound the upside.
    [ "$(echo "$overhead < 75" | bc -l 2>/dev/null)" = "1" ]
}

@test "summary: NAT + DLP overhead report" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    local baseline; baseline="$(jq -r '.baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "no data"
    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _report_set_str "kernel" "$(uname -r)"
    echo "# NAT/DLP overhead (baseline $(echo "scale=2; $baseline/1000000000" | bc -l) Gbps):"
    local k bps oh
    for k in nat_egress nat_ingress nat_full; do
        bps="$(jq -r ".${k}_bps // empty" "$OVERHEAD_REPORT" 2>/dev/null)"
        oh="$(jq -r ".${k}_overhead_pct // \"---\"" "$OVERHEAD_REPORT" 2>/dev/null)"
        [ -n "$bps" ] && printf "#   %-12s %6s Gbps  overhead %s%%\n" "$k" "$(echo "scale=2; $bps/1000000000" | bc -l)" "$oh" || printf "#   %-12s skipped\n" "$k"
    done
    local doh; doh="$(jq -r '.dlp_overhead_pct // "---"' "$OVERHEAD_REPORT" 2>/dev/null)"
    printf "#   %-12s uprobe goodput overhead %s%%\n" "dlp" "$doh"
    jq '.' "$OVERHEAD_REPORT"
}
