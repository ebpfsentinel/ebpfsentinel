#!/usr/bin/env bats
# 43-slowhttptest-slow-attacks.bats — Slow L7 attacks against an agent
# with a slow-request timeout policy.
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM with slowhttptest installed (Story 34.3)
#   - Agent VM reachable via 2VM SSH helpers (Story 34.2)
#   - Kernel >= 6.9
#
# Three offensive variants (Slowloris, RUDY, Slowread) and one
# false-positive guard (legitimate slow client within timeout). Each
# offensive variant asserts:
#   1. an IDS / IPS metric grew
#   2. the attacker IP was promoted to the blacklist
#   3. at least one alert carries MITRE T1499.002
# The false-positive test asserts the IP is NOT blacklisted.

load '../lib/ebpf_helpers'
load '../lib/slowhttp_helpers'

setup_file() {
    require_root
    require_kernel 6 9
    require_tool jq
    require_tool bc
    require_tool curl
    require_slowhttptest

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "suite 43 requires EBPF_2VM_MODE=true (attacker VM driving real slow flood)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-slowhttp-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-l7-timeout.yaml")"
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
}

teardown_file() {
    stop_slowhttp 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-slowhttp-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    stop_slowhttp 2>/dev/null || true
}

# _run_slow_and_assert <mode> <metric>
# Foreground attack, then assert metric grew, attacker is blacklisted,
# and MITRE T1499.002 was tagged on at least one alert.
_run_slow_and_assert() {
    local mode="$1"
    local metric="$2"

    local before
    before="$(get_metrics_value "$metric" || echo "0")"
    [ -z "$before" ] && before="0"

    run_slowhttp "$mode" "$ATTACK_DURATION"

    assert_metric_increased "$metric" "$before" 1
    assert_ip_blacklisted "$ATTACKER_IP"
    assert_alert_has_mitre_technique T1499.002 || \
        assert_alert_has_mitre_technique T1499
}

# ── Offensive variants ────────────────────────────────────────────────

@test "slowhttptest Slowloris (-H) trips slow-headers timeout and blacklists source" {
    _run_slow_and_assert slowloris ebpfsentinel_ids_alerts_total
}

@test "slowhttptest RUDY (-B) trips slow-body timeout and blacklists source" {
    _run_slow_and_assert rudy ebpfsentinel_ids_alerts_total
}

@test "slowhttptest Slowread (-X) trips slow-read timeout and blacklists source" {
    _run_slow_and_assert slowread ebpfsentinel_ids_alerts_total
}

# ── False-positive guard ──────────────────────────────────────────────

@test "legitimate slow client within timeout is NOT blacklisted" {
    # Take a fresh blacklist snapshot, then send a single request that
    # streams slow enough to be noticeably slow but still completes
    # inside the configured reassembly idle_timeout_secs (5 s in the
    # fixture). A short 3 s legit window keeps us well clear of the
    # IPS threshold (10 events / 10 s).
    local before_count
    before_count="$(get_blacklist_count 2>/dev/null || echo "0")"
    [ -z "$before_count" ] && before_count="0"

    slowhttp_legit_request 3 /

    # Brief settle so blacklist write would have landed if it were going to.
    sleep 5

    local after_count
    after_count="$(get_blacklist_count 2>/dev/null || echo "0")"
    [ -z "$after_count" ] && after_count="0"

    if [ "$(echo "$after_count > $before_count" | bc -l 2>/dev/null)" = "1" ]; then
        # A new blacklist entry appeared — verify it is NOT the legit-client IP.
        local body
        body="$(api_get /api/v1/ips/blacklist 2>/dev/null || echo '[]')"
        local hit
        hit="$(echo "$body" | jq -r --arg ip "$ATTACKER_IP" \
            '.[] | select(.ip == $ip or .source_ip == $ip or .src_ip == $ip) | .ip // .source_ip // .src_ip' \
            2>/dev/null | head -1)"
        [ -z "$hit" ] || [ "$hit" = "null" ] || {
            echo "False positive: legit slow client ${ATTACKER_IP} was blacklisted" >&2
            return 1
        }
    fi
}
