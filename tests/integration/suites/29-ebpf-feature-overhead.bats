#!/usr/bin/env bats
# 29-ebpf-feature-overhead.bats — Per-feature eBPF overhead measurement
# Measures TCP throughput with incremental feature enablement to isolate
# the cost of each eBPF subsystem.
#
# Requires: root, kernel >= 5.17, bpftool, iperf3
# Outputs JSON report to /tmp/ebpfsentinel-feature-overhead-latest.json

load '../lib/helpers'
load '../lib/ebpf_helpers'

OVERHEAD_REPORT="/tmp/ebpfsentinel-feature-overhead-latest.json"
IPERF_DURATION=10

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool iperf3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-overhead-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Initialize report
    echo '{}' > "$OVERHEAD_REPORT"

    # Start iperf3 server on host side
    iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile /tmp/iperf3-overhead-$$.pid 2>/dev/null
    sleep 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true

    # Stop iperf3 server
    if [ -f /tmp/iperf3-overhead-$$.pid ]; then
        kill "$(cat /tmp/iperf3-overhead-$$.pid)" 2>/dev/null || true
        rm -f /tmp/iperf3-overhead-$$.pid
    fi
    pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true

    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-overhead-$$}"
}

# ── Helper: update JSON report ──────────────────────────────────────

_report_set() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --argjson v "$value" '. + {($k): $v}' "$OVERHEAD_REPORT")"
    echo "$tmp" > "$OVERHEAD_REPORT"
}

_report_set_str() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' "$OVERHEAD_REPORT")"
    echo "$tmp" > "$OVERHEAD_REPORT"
}

# ── Helper: generate feature config inline ──────────────────────────
# Usage: _make_feature_config [firewall] [ids] [ratelimit] [threatintel] [conntrack]
# Each argument is the feature name to enable. Omitted features are disabled.

_make_feature_config() {
    local enable_firewall=false
    local enable_ids=false
    local enable_ratelimit=false
    local enable_threatintel=false
    local enable_conntrack=false

    for feat in "$@"; do
        case "$feat" in
            firewall)    enable_firewall=true ;;
            ids)         enable_ids=true ;;
            ratelimit)   enable_ratelimit=true ;;
            threatintel) enable_threatintel=true ;;
            conntrack)   enable_conntrack=true ;;
        esac
    done

    local config_file="${DATA_DIR}/config-overhead-$$.yaml"

    cat > "$config_file" <<EOF
agent:
  interfaces:
    - __INTERFACE__
  bind_address: "0.0.0.0"
  log_level: warn
  http_port: 18080
  grpc_port: 50151
  metrics_port: 19090

firewall:
  enabled: ${enable_firewall}
  default_policy: pass
  rules:
    - id: fw-bench-1
      priority: 10
      action: deny
      protocol: tcp
      dst_port: 9999
      scope: global
      enabled: true

ids:
  enabled: ${enable_ids}
  mode: alert
  rules:
    - id: ids-bench-1
      description: "Benchmark IDS rule"
      severity: medium
      protocol: tcp
      dst_port: 4444
      enabled: true

ratelimit:
  enabled: ${enable_ratelimit}
  default_rate: 100000
  default_burst: 200000
  default_algorithm: token_bucket
  rules:
    - id: rl-bench-1
      rate: 100000
      burst: 200000
      scope: global
      algorithm: token_bucket
      action: drop
      enabled: true

threatintel:
  enabled: ${enable_threatintel}
  mode: alert
  feeds: []

conntrack:
  enabled: ${enable_conntrack}
  half_open_threshold: 100
  rst_threshold: 50
  fin_threshold: 50
  ack_threshold: 200

ddos:
  enabled: ${enable_conntrack}
  policies: []

alerting:
  enabled: false

audit:
  enabled: false
EOF

    echo "$config_file"
}

# ── Helper: measure throughput ──────────────────────────────────────

_measure_tcp_throughput() {
    local result bps
    result="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION")" || return 1
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || return 1

    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        return 1
    fi

    echo "$bps"
}

# ── Step 0: Baseline (no agent) ────────────────────────────────────

@test "step-0: baseline TCP throughput (no agent)" {
    require_root
    require_tool iperf3

    # Ensure no agent is running
    stop_ebpf_agent 2>/dev/null || true

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step0_baseline_bps" "$bps"
    _report_set_str "step0_label" "no-agent"

    echo "# Baseline throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"
}

# ── Step 1: Firewall only ──────────────────────────────────────────

@test "step-1: firewall only" {
    require_root
    require_tool iperf3

    local baseline
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "baseline not recorded"

    stop_ebpf_agent 2>/dev/null || true

    local config_file
    config_file="$(_make_feature_config firewall)"
    local prepared
    prepared="$(prepare_ebpf_config "$config_file")"

    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded"

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step1_bps" "$bps"
    _report_set_str "step1_label" "firewall"

    local overhead
    overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] && _report_set_str "step1_overhead_pct" "$overhead"

    # Marginal cost is same as overhead for step 1
    [ -n "$overhead" ] && _report_set_str "step1_marginal_pct" "$overhead"

    echo "# Firewall-only throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%)"

    stop_ebpf_agent
}

# ── Step 2: Firewall + IDS ─────────────────────────────────────────

@test "step-2: firewall + IDS" {
    require_root
    require_tool iperf3

    local baseline prev_bps
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    prev_bps="$(jq -r '.step1_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "baseline not recorded"
    [ -n "$prev_bps" ] || skip "step-1 not recorded"

    stop_ebpf_agent 2>/dev/null || true

    local config_file
    config_file="$(_make_feature_config firewall ids)"
    local prepared
    prepared="$(prepare_ebpf_config "$config_file")"

    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded"

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step2_bps" "$bps"
    _report_set_str "step2_label" "firewall+ids"

    local overhead
    overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] && _report_set_str "step2_overhead_pct" "$overhead"

    local marginal
    marginal="$(echo "scale=4; (1 - ($bps / $prev_bps)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$marginal" ] && _report_set_str "step2_marginal_pct" "$marginal"

    echo "# Firewall+IDS throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%, marginal: ${marginal}%)"

    stop_ebpf_agent
}

# ── Step 3: Firewall + IDS + Ratelimit ─────────────────────────────

@test "step-3: firewall + IDS + ratelimit" {
    require_root
    require_tool iperf3

    local baseline prev_bps
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    prev_bps="$(jq -r '.step2_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "baseline not recorded"
    [ -n "$prev_bps" ] || skip "step-2 not recorded"

    stop_ebpf_agent 2>/dev/null || true

    local config_file
    config_file="$(_make_feature_config firewall ids ratelimit)"
    local prepared
    prepared="$(prepare_ebpf_config "$config_file")"

    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded"

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step3_bps" "$bps"
    _report_set_str "step3_label" "firewall+ids+ratelimit"

    local overhead
    overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] && _report_set_str "step3_overhead_pct" "$overhead"

    local marginal
    marginal="$(echo "scale=4; (1 - ($bps / $prev_bps)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$marginal" ] && _report_set_str "step3_marginal_pct" "$marginal"

    echo "# +Ratelimit throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%, marginal: ${marginal}%)"

    stop_ebpf_agent
}

# ── Step 4: Firewall + IDS + Ratelimit + ThreatIntel ───────────────

@test "step-4: firewall + IDS + ratelimit + threatintel" {
    require_root
    require_tool iperf3

    local baseline prev_bps
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    prev_bps="$(jq -r '.step3_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "baseline not recorded"
    [ -n "$prev_bps" ] || skip "step-3 not recorded"

    stop_ebpf_agent 2>/dev/null || true

    local config_file
    config_file="$(_make_feature_config firewall ids ratelimit threatintel)"
    local prepared
    prepared="$(prepare_ebpf_config "$config_file")"

    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded"

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step4_bps" "$bps"
    _report_set_str "step4_label" "firewall+ids+ratelimit+threatintel"

    local overhead
    overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] && _report_set_str "step4_overhead_pct" "$overhead"

    local marginal
    marginal="$(echo "scale=4; (1 - ($bps / $prev_bps)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$marginal" ] && _report_set_str "step4_marginal_pct" "$marginal"

    echo "# +ThreatIntel throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%, marginal: ${marginal}%)"

    stop_ebpf_agent
}

# ── Step 5: All features (conntrack/DDoS added) ───────────────────

@test "step-5: all features (firewall + IDS + ratelimit + threatintel + conntrack/DDoS)" {
    require_root
    require_tool iperf3

    local baseline prev_bps
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    prev_bps="$(jq -r '.step4_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "baseline not recorded"
    [ -n "$prev_bps" ] || skip "step-4 not recorded"

    stop_ebpf_agent 2>/dev/null || true

    local config_file
    config_file="$(_make_feature_config firewall ids ratelimit threatintel conntrack)"
    local prepared
    prepared="$(prepare_ebpf_config "$config_file")"

    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || skip "eBPF programs not loaded"

    local bps
    bps="$(_measure_tcp_throughput)" || skip "iperf3 failed"

    [ -n "$bps" ]
    _report_set "step5_bps" "$bps"
    _report_set_str "step5_label" "all-features"

    local overhead
    overhead="$(echo "scale=4; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$overhead" ] && _report_set_str "step5_overhead_pct" "$overhead"

    local marginal
    marginal="$(echo "scale=4; (1 - ($bps / $prev_bps)) * 100" | bc -l 2>/dev/null)" || true
    [ -n "$marginal" ] && _report_set_str "step5_marginal_pct" "$marginal"

    echo "# All-features throughput: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%, marginal: ${marginal}%)"

    stop_ebpf_agent
}

# ── NFR2 assertion: total overhead < 5% ────────────────────────────

@test "NFR2: total overhead with all features < 5%" {
    require_root

    local overhead
    overhead="$(jq -r '.step5_overhead_pct // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true

    if [ -z "$overhead" ]; then
        skip "all-features overhead not recorded"
    fi

    # Assert: overhead must be less than 5%
    local is_ok
    is_ok="$(echo "$overhead < 5" | bc -l 2>/dev/null)" || true
    echo "# Total overhead with all features: ${overhead}% (limit: 5%)"
    [ "${is_ok:-0}" = "1" ]
}

# ── Summary table ──────────────────────────────────────────────────

@test "summary: per-feature overhead report" {
    require_root

    local baseline
    baseline="$(jq -r '.step0_baseline_bps // empty' "$OVERHEAD_REPORT" 2>/dev/null)" || true
    [ -n "$baseline" ] || skip "no data to summarize"

    # Add metadata
    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _report_set_str "kernel" "$(uname -r)"
    _report_set "iperf_duration_s" "$IPERF_DURATION"

    # Print summary table
    echo "#"
    echo "# ============================================================"
    echo "# eBPFsentinel Per-Feature Overhead Report"
    echo "# ============================================================"
    echo "#"
    printf "# %-45s %12s %10s %10s\n" "Configuration" "Throughput" "Overhead" "Marginal"
    printf "# %-45s %12s %10s %10s\n" "---------------------------------------------" "------------" "----------" "----------"

    local baseline_gbps
    baseline_gbps="$(echo "scale=2; $baseline / 1000000000" | bc -l 2>/dev/null)"
    printf "# %-45s %10s %s %10s %10s\n" "Step 0: no-agent (baseline)" "${baseline_gbps}" "Gbps" "---" "---"

    local step label bps overhead_pct marginal_pct gbps
    for step in 1 2 3 4 5; do
        label="$(jq -r ".step${step}_label // \"---\"" "$OVERHEAD_REPORT" 2>/dev/null)"
        bps="$(jq -r ".step${step}_bps // empty" "$OVERHEAD_REPORT" 2>/dev/null)"
        overhead_pct="$(jq -r ".step${step}_overhead_pct // \"---\"" "$OVERHEAD_REPORT" 2>/dev/null)"
        marginal_pct="$(jq -r ".step${step}_marginal_pct // \"---\"" "$OVERHEAD_REPORT" 2>/dev/null)"

        if [ -n "$bps" ]; then
            gbps="$(echo "scale=2; $bps / 1000000000" | bc -l 2>/dev/null)"
            printf "# %-45s %10s %s %9s%% %9s%%\n" \
                "Step ${step}: ${label}" "${gbps}" "Gbps" "${overhead_pct}" "${marginal_pct}"
        else
            printf "# %-45s %12s %10s %10s\n" "Step ${step}: ${label}" "skipped" "---" "---"
        fi
    done

    echo "#"
    echo "# Report saved to: ${OVERHEAD_REPORT}"
    echo "#"

    # Dump full JSON
    jq '.' "$OVERHEAD_REPORT"
}
