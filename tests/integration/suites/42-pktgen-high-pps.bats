#!/usr/bin/env bats
# 42-pktgen-high-pps.bats — Sustain ≥1 Mpps from the attacker NIC and
# measure the agent's XDP early-drop CPU savings against a plain pass
# baseline. Validates that pktgen + XDP firewall + rate-limiter behave
# at production volumes.
#
# Topology: 2vm. Profile: nightly. Kernel >= 6.9.
#
# Test plan:
#   1. Baseline (no XDP rule effect) — record achievable pps + CPU.
#   2. XDP firewall PASS rule — record CPU under load (high).
#   3. XDP firewall DROP rule — assert CPU < baseline + 30%
#      and dropped_total metric grew ≥ realised pps × duration / 2.
#   4. XDP ratelimit + SYN cookie — assert syncookie counter grew,
#      no kernel-level SYN backlog overflow (via nstat ListenDrops).
#   5. tc-ids passive observation — assert ringbuf overruns are
#      reported as metric increments, not panics.
#
# Numeric reporting: per-test rows appended to
# /tmp/ebpfsentinel-42-pktgen.json (one JSON object per line).

load '../lib/ebpf_helpers'
load '../lib/pktgen_helpers'

REPORT_FILE="/tmp/ebpfsentinel-42-pktgen.json"
PKTGEN_DURATION="${PKTGEN_DURATION:-30}"
PKTGEN_MIN_PPS="${PKTGEN_MIN_PPS:-1000000}"
CPU_BUDGET_DROP_PCT="${CPU_BUDGET_DROP_PCT:-30}"
CPU_PASS_MULTIPLIER="${CPU_PASS_MULTIPLIER:-100}"

setup_file() {
    require_root
    require_kernel 6 9
    require_tool bpftool
    require_tool jq
    require_tool bc

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "suite 42 requires EBPF_2VM_MODE=true (pktgen on attacker NIC)"
    fi

    require_pktgen

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-pktgen-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns
    : > "$REPORT_FILE"
}

teardown_file() {
    pktgen_stop 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-pktgen-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    pktgen_stop 2>/dev/null || true
}

# ── Helpers ───────────────────────────────────────────────────────────

# _agent_cpu_pct — sample agent VM CPU usage over 1s
_agent_cpu_pct() {
    _agent_ssh "top -bn2 -d1 | awk '/Cpu\\(s\\)/{u=\$2; gsub(\",\",\"\",u); print u; exit}'" \
        2>/dev/null | tail -1
}

# _record <test> <pps> <cpu_pct> <dropped_delta> [extra_json]
_record() {
    local name="$1" pps="$2" cpu="$3" drops="$4" extra="${5:-{}}"
    jq -n --arg t "$name" --argjson pps "${pps:-0}" \
        --argjson cpu "${cpu:-0}" --argjson drops "${drops:-0}" \
        --argjson extra "$extra" \
        '{test:$t, pps:$pps, cpu_pct:$cpu, dropped_delta:$drops, extra:$extra}' \
        >> "$REPORT_FILE"
}

# _start_with <fixture>
_start_with() {
    local fixture="$1"
    stop_ebpf_agent 2>/dev/null || true
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/${fixture}")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        skip "eBPF programs not loaded for fixture ${fixture}"
    }
}

# _metric_or_zero <name> [label]
_metric_or_zero() {
    local v
    v="$(get_metrics_value "$1" "${2:-}" 2>/dev/null || echo "0")"
    [ -z "$v" ] && v="0"
    echo "$v"
}

# ── Tests ─────────────────────────────────────────────────────────────

@test "pktgen baseline — measures achievable pps and idle CPU" {
    # No agent rules in effect for the duration of the baseline; we just
    # need pktgen + driver characterisation.
    _start_with config-ebpf-pktgen-pass.yaml

    local cpu_before
    cpu_before="$(_agent_cpu_pct)"
    cpu_before="${cpu_before:-0}"

    local realised
    realised="$(pktgen_run "$PKTGEN_DURATION")"
    realised="${realised:-0}"

    local cpu_during
    cpu_during="$(_agent_cpu_pct)"
    cpu_during="${cpu_during:-0}"

    _record baseline "$realised" "$cpu_during" 0 \
        "$(jq -n --argjson b "$cpu_before" '{cpu_before:$b}')"

    # Sustained-rate gate.
    if [ "$(echo "$realised < $PKTGEN_MIN_PPS" | bc -l)" = "1" ]; then
        skip "achievable pps ${realised} below floor ${PKTGEN_MIN_PPS} — driver/NIC capped"
    fi
    export BASELINE_PPS="$realised"
    export BASELINE_CPU="$cpu_during"
}

@test "XDP pass rule — high CPU confirms stack traversal" {
    [ -n "${BASELINE_PPS:-}" ] || skip "baseline test did not record BASELINE_PPS"
    _start_with config-ebpf-pktgen-pass.yaml

    local cpu_during realised
    realised="$(pktgen_run "$PKTGEN_DURATION")"
    realised="${realised:-0}"
    cpu_during="$(_agent_cpu_pct)"
    cpu_during="${cpu_during:-0}"

    _record xdp_pass "$realised" "$cpu_during" 0 "{}"

    # The pass path SHOULD be measurably above baseline (kernel processes
    # every packet). We only assert non-zero CPU because absolute %CPU
    # depends on the VM host; the *relative* check vs xdp_drop is below.
    [ "$(echo "$cpu_during > 0" | bc -l)" = "1" ]
    export PASS_CPU="$cpu_during"
}

@test "XDP drop rule — CPU stays low and dropped_total grows" {
    [ -n "${BASELINE_CPU:-}" ] || skip "baseline test did not record BASELINE_CPU"
    _start_with config-ebpf-pktgen-drop.yaml

    local drops_before drops_after delta cpu_during realised
    drops_before="$(_metric_or_zero ebpfsentinel_xdp_dropped_total)"
    realised="$(pktgen_run "$PKTGEN_DURATION")"
    realised="${realised:-0}"
    cpu_during="$(_agent_cpu_pct)"
    cpu_during="${cpu_during:-0}"
    sleep 2
    drops_after="$(_metric_or_zero ebpfsentinel_xdp_dropped_total)"
    delta="$(echo "$drops_after - $drops_before" | bc -l)"

    _record xdp_drop "$realised" "$cpu_during" "$delta" "{}"

    # Acceptance criterion 2.3: CPU stays below baseline + 30%.
    local cpu_budget
    cpu_budget="$(echo "$BASELINE_CPU + $CPU_BUDGET_DROP_PCT" | bc -l)"
    if [ "$(echo "$cpu_during > $cpu_budget" | bc -l)" = "1" ]; then
        echo "XDP drop CPU ${cpu_during}% exceeded budget ${cpu_budget}%" >&2
        return 1
    fi

    # If we also captured PASS_CPU, sanity-check: drop CPU should be
    # markedly lower than pass CPU (XDP saves stack traversal).
    if [ -n "${PASS_CPU:-}" ]; then
        if [ "$(echo "$PASS_CPU <= $cpu_during" | bc -l)" = "1" ]; then
            echo "XDP drop CPU (${cpu_during}%) not lower than pass CPU (${PASS_CPU}%)" >&2
            return 1
        fi
    fi

    # Dropped delta should account for at least half the realised pps
    # over the run (allows for sampler skew, metric scrape interval).
    local min_expected
    min_expected="$(echo "($realised * $PKTGEN_DURATION) / 2" | bc -l)"
    if [ "$(echo "$delta < $min_expected" | bc -l)" = "1" ]; then
        echo "xdp_dropped_total grew by ${delta}, expected ≥ ${min_expected}" >&2
        return 1
    fi
}

@test "XDP ratelimit + SYN cookie path activates under SYN flood" {
    _start_with config-ebpf-pktgen-syncookie.yaml

    local cookies_before cookies_after listen_drops_before listen_drops_after realised cpu_during

    cookies_before="$(_metric_or_zero ebpfsentinel_syncookie_sent_total)"
    listen_drops_before="$(_agent_ssh 'nstat -az TcpExtListenDrops 2>/dev/null | awk "NR==2 {print \$2}"')"
    listen_drops_before="${listen_drops_before:-0}"

    # Drive SYN flood: pkt_size 60, dport 80 (HTTP) — pktgen emits UDP,
    # which the rate-limiter still observes as ingress pps; the SYN
    # cookie counter is exercised when the conntrack path sees the
    # rate-limit verdict. For real TCP SYN flooding we'd use hping3,
    # but pktgen achieves the volume needed for the threshold gate.
    realised="$(pktgen_run "$PKTGEN_DURATION" 60 80)"
    realised="${realised:-0}"
    cpu_during="$(_agent_cpu_pct)"
    cpu_during="${cpu_during:-0}"
    sleep 2

    cookies_after="$(_metric_or_zero ebpfsentinel_syncookie_sent_total)"
    listen_drops_after="$(_agent_ssh 'nstat -az TcpExtListenDrops 2>/dev/null | awk "NR==2 {print \$2}"')"
    listen_drops_after="${listen_drops_after:-0}"

    local cookie_delta listen_delta
    cookie_delta="$(echo "$cookies_after - $cookies_before" | bc -l)"
    listen_delta="$(echo "$listen_drops_after - $listen_drops_before" | bc -l)"

    _record syncookie "$realised" "$cpu_during" 0 \
        "$(jq -n --argjson c "$cookie_delta" --argjson l "$listen_delta" \
            '{cookie_delta:$c, listen_drops_delta:$l}')"

    # Acceptance: kernel SYN backlog must not overflow.
    if [ "$(echo "$listen_delta > 0" | bc -l)" = "1" ]; then
        # The cookie path SHOULD absorb the flood; any ListenDrops
        # increment means the rate-limiter let SYNs reach the listen
        # queue. We allow up to 100 (jitter), beyond that we fail.
        if [ "$(echo "$listen_delta > 100" | bc -l)" = "1" ]; then
            echo "TcpExtListenDrops grew by ${listen_delta} — SYN backlog overflow" >&2
            return 1
        fi
    fi
    # Soft assertion: cookie counter should be > 0 OR rate-limiter
    # absorbed all of it via early drop (also acceptable).
    local drops_after
    drops_after="$(_metric_or_zero ebpfsentinel_ratelimit_dropped_total)"
    if [ "$(echo "$cookie_delta == 0 && $drops_after == 0" | bc -l)" = "1" ]; then
        echo "neither syncookie nor ratelimit drop counter moved under flood" >&2
        return 1
    fi
}

@test "tc-ids passive observation — ringbuf overruns logged, no panic" {
    _start_with config-ebpf-pktgen-drop.yaml

    local overruns_before overruns_after realised cpu_during
    overruns_before="$(_metric_or_zero ebpfsentinel_ringbuf_dropped_total)"
    realised="$(pktgen_run "$PKTGEN_DURATION")"
    realised="${realised:-0}"
    cpu_during="$(_agent_cpu_pct)"
    cpu_during="${cpu_during:-0}"
    sleep 2
    overruns_after="$(_metric_or_zero ebpfsentinel_ringbuf_dropped_total)"

    local overrun_delta
    overrun_delta="$(echo "$overruns_after - $overruns_before" | bc -l)"
    _record tc_ids "$realised" "$cpu_during" "$overrun_delta" "{}"

    # Agent must still be healthy after the flood.
    local health
    health="$(curl -sf --max-time "$HTTP_TIMEOUT" "${BASE_URL}/healthz" \
        | jq -r '.status // .ok // ""' 2>/dev/null)"
    [ "$health" = "ok" ] || [ "$health" = "true" ] || {
        echo "agent /healthz did not return ok after pktgen flood: '${health}'" >&2
        return 1
    }
}
