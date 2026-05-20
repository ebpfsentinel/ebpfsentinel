#!/usr/bin/env bats
# 41-mhddos-l7-attacks.bats — Exercise MHDDoS L7 multi-method floods
# against a single agent instance with L7 firewall, IPS auto-blacklist,
# and global rate limiter all enabled.
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM provisioned per Story 34.3 (MHDDoS at /opt/MHDDoS)
#   - Agent VM reachable via 2VM SSH helpers (Story 34.2)
#   - Kernel >= 6.9, bpftool on agent side
#
# Each per-method test:
#   1. snapshots the relevant agent metric
#   2. drives 30 s of MHDDoS traffic of one method (10 threads)
#   3. asserts (a) the metric grew, (b) the attacker IP is blacklisted,
#      (c) at least one alert carries a MITRE T1498/T1499 tag,
#      (d) API p99 stays under 500 ms during the attack window.
#
# MHDDoS exits non-zero whenever the agent successfully drops or rate-
# limits its connection attempts; we never assert on its exit code.

load '../lib/ebpf_helpers'
load '../lib/mhddos_helpers'

setup_file() {
    require_root
    require_kernel 6 9
    require_tool bpftool
    require_tool jq
    require_tool bc
    require_tool curl
    require_mhddos

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "suite 41 requires EBPF_2VM_MODE=true (attacker VM driving real flood)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-mhddos-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mhddos.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }

    export ATTACKER_IP
    ATTACKER_IP="$(attacker_ip)"
    export ATTACK_DURATION="${ATTACK_DURATION:-30}"
    export ATTACK_THREADS="${ATTACK_THREADS:-10}"
    export P99_BUDGET_MS="${P99_BUDGET_MS:-500}"
}

teardown_file() {
    stop_mhddos 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-mhddos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    stop_mhddos 2>/dev/null || true
}

# ── Shared per-method assertions ──────────────────────────────────────

# _run_attack_and_assert <method> <metric_name> [path]
# Single helper that captures the shared assertion shape across all
# eight methods. Per-method tests stay one-liners that document intent.
_run_attack_and_assert() {
    local method="$1"
    local metric="$2"
    local path="${3:-/}"

    local before
    before="$(get_metrics_value "$metric" || echo "0")"
    [ -z "$before" ] && before="0"

    # Background MHDDoS, foreground latency probes.
    run_mhddos_background "$method" "$ATTACK_DURATION" "$ATTACK_THREADS" "$path"

    # Mid-attack: assert API control plane stays responsive.
    sleep 5
    assert_api_p99_below "$P99_BUDGET_MS" 50

    # Wait for the flood to wind down.
    wait "${MHDDOS_PID:-0}" 2>/dev/null || true
    stop_mhddos

    assert_metric_increased "$metric" "$before" 1
    assert_ip_blacklisted "$ATTACKER_IP"
    # Either MITRE technique counts as success — agent tags volumetric
    # vs endpoint differently across the eight methods.
    assert_alert_has_mitre_technique T1498 || \
        assert_alert_has_mitre_technique T1499
}

# ── Per-method tests ──────────────────────────────────────────────────

@test "MHDDoS GET flood trips L7 HTTP path metrics" {
    _run_attack_and_assert GET ebpfsentinel_l7_blocked_total "/"
}

@test "MHDDoS POST flood trips L7 payload metrics" {
    _run_attack_and_assert POST ebpfsentinel_l7_blocked_total "/login"
}

@test "MHDDoS STRESS (persistent conn) exhausts rate limit tokens" {
    _run_attack_and_assert STRESS ebpfsentinel_ratelimit_dropped_total "/"
}

@test "MHDDoS BYPASS triggers behavioural/JA4 anomaly path" {
    _run_attack_and_assert BYPASS ebpfsentinel_ids_alerts_total "/"
}

@test "MHDDoS OVH volumetric flood detected" {
    _run_attack_and_assert OVH ebpfsentinel_ddos_drops_total "/"
}

@test "MHDDoS TLS handshake flood captured" {
    _run_attack_and_assert TLS ebpfsentinel_l7_blocked_total "/"
}

@test "MHDDoS CFB (WAF bypass) attempt logged" {
    _run_attack_and_assert CFB ebpfsentinel_l7_blocked_total "/admin"
}

@test "MHDDoS SLOW (slowloris) hits L7 timeout policy" {
    _run_attack_and_assert SLOW ebpfsentinel_l7_blocked_total "/"
}
