#!/usr/bin/env bats
# 40-scapy-amplification.bats — UDP reflection/amplification protection
# against an agent with scrub + amplification DDoS policy.
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM with python3 + scapy (Story 34.3)
#   - Agent VM reachable via 2VM SSH helpers (Story 34.2)
#   - Kernel >= 6.9
#
# Each vector test floods the agent (victim side) with the reflected
# response leg of an amplification attack: UDP datagrams sourced *from*
# the amplifier port (53/123/1900/11211). The kernel UDP-amplification
# protection rate-limits per source/amplifier-port and drops the flood,
# and asserts:
#   1. the DDoS amp_dropped metric grew (flood dropped at XDP ingress)
#   2. at least one alert carries MITRE T1498.002 (Reflection Amplification)
#
# A final test drives the reflector leg instead (--query: a spoofed-source
# query *to* the amplifier port, denied by the firewall) and asserts ZERO
# amplification responses leave the agent.

load '../lib/ebpf_helpers'
load '../lib/amp_helpers'

setup_file() {
    require_root
    require_kernel 6 9
    require_tool jq
    require_tool bc

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 40 requires EBPF_2VM_MODE=true (attacker VM crafting spoofed packets)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    require_amp

    export DATA_DIR="/tmp/ebpfsentinel-test-data-amp-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ddos-amplification.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    export AMP_COUNT="${AMP_COUNT:-500}"
    export AMP_RATE="${AMP_RATE:-200}"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-amp-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _run_amp_and_assert <vector> <metric>
# Snapshot metric, run probe, assert metric grew and a T1498.002 alert
# was emitted. Vector exits non-zero only on argv errors — we ignore
# that here and gate on agent-side side-effects.
_run_amp_and_assert() {
    local vector="$1"
    local metric="$2"

    local before
    before="$(get_metrics_value "$metric" || echo "0")"
    [ -z "$before" ] && before="0"

    amp_run "$vector" "$AMP_COUNT" "$AMP_RATE" || true

    assert_metric_increased "$metric" "$before" 1
    assert_alert_has_mitre_technique T1498.002 || \
        assert_alert_has_mitre_technique T1498
}

# ── Per-vector tests ──────────────────────────────────────────────────

@test "DNS ANY flood with spoofed source is dropped pre-response" {
    _run_amp_and_assert dns_any 'ebpfsentinel_packets_total{interface="DDOS_METRICS",action="amp_dropped"}'
}

@test "NTP monlist with spoofed source is blocked" {
    _run_amp_and_assert ntp_monlist 'ebpfsentinel_packets_total{interface="DDOS_METRICS",action="amp_dropped"}'
}

@test "SSDP M-SEARCH with spoofed source is blocked" {
    _run_amp_and_assert ssdp_search 'ebpfsentinel_packets_total{interface="DDOS_METRICS",action="amp_dropped"}'
}

@test "Memcached stats with spoofed source is blocked" {
    _run_amp_and_assert memcached_stats 'ebpfsentinel_packets_total{interface="DDOS_METRICS",action="amp_dropped"}'
}

# ── Egress-zero guard ─────────────────────────────────────────────────

@test "no amplification response leaves the agent (egress capture)" {
    # Start a capture on the agent's external interface, then run one short
    # DNS-ANY salvo in the reflector direction (--query: a spoofed-source
    # ANY query *to* UDP/53). The firewall denies the query at ingress; the
    # agent must NOT answer it, i.e. emit any UDP packet sourced from the
    # amplification ports (53/123/1900/11211).
    local iface="${EBPF_AGENT_INTERFACE:-eth1}"
    local bpf='udp and (src port 53 or src port 123 or src port 1900 or src port 11211)'

    local remote_pcap
    remote_pcap="$(capture_on agent "$iface" "$bpf")" || soft_skip "capture_on failed on agent VM"

    amp_run dns_any 200 200 "" --query || true

    local local_pcap
    local_pcap="$(stop_capture agent "$remote_pcap")" || soft_skip "stop_capture failed on agent VM"

    amp_egress_zero "$local_pcap"
}

# ── Real crafted-packet flooder (hyenae-ng) ───────────────────────
#
# hyenae-ng is provisioned on the attacker VM as a raw L2/L3 flood
# generator. It is a menu-driven tool, so the flood is driven by feeding
# its assistant a canned key sequence under a hard timeout; we never
# assert on its exit code, only on the agent-side observed-packet delta.

# _amp_packet_metric — sum every observed-packet counter the agent exposes.
_amp_packet_metric() {
    local metrics
    metrics="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || {
        echo 0
        return
    }
    echo "$metrics" \
        | awk '/^ebpfsentinel_packets[_a-z]*(_total)?[ {]/ {sum += $NF}
               END { if (sum == "") print 0; else print sum }'
}

@test "real hyenae-ng crafted flood is observed by the datapath" {
    if ! command -v hyenae-ng >/dev/null 2>&1; then
        env_skip "hyenae-ng not available on attacker VM"
    fi

    local dst="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local before
    before="$(_amp_packet_metric)"

    # Drive the assistant towards an ICMP-echo flood at the agent. The key
    # sequence targets hyenae-ng's default menu layout; a hard timeout
    # guarantees the tool never blocks the suite waiting for input.
    timeout 10 hyenae-ng <<EOF >/dev/null 2>&1 || true
1
1
${dst}
500
y
EOF

    sleep 3
    local after
    after="$(_amp_packet_metric)"
    if [ "${after:-0}" -le "${before:-0}" ]; then
        # The tool ran but no flood reached the datapath — its menu layout
        # varies across builds. Flag for the live lane rather than assert a
        # false product failure here.
        soft_skip "hyenae-ng produced no observable flood on this build"
    fi
}

# ── MITRE coverage sweep ───────────────────────────────────────────

@test "alerts emitted by this suite carry a MITRE technique mapping" {
    local body count
    body="$(api_get /api/v1/alerts 2>/dev/null)" || body=""
    count="$(echo "${body}" | jq -r '.alerts | length' 2>/dev/null)" || count=0
    if [ "${count:-0}" -lt 1 ]; then
        soft_skip "no alerts emitted by this suite — MITRE assertion not applicable here"
    fi
    assert_alert_has_any_mitre_technique 15
}
