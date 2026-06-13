#!/usr/bin/env bats
# 42-xdp-firewall-reject.bats — wire-validates the xdp-firewall-reject
# tail-call program: TCP RST forging for `action: reject` on TCP rules,
# ICMP Destination-Port-Unreachable forging for UDP rules, and
# whitelist bypass (no RST/ICMP for trusted sources).
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM with tcpdump, tshark, ncat, scapy (Story 34.3)
#   - Agent VM reachable via 2VM SSH helpers (Story 34.2)
#   - Kernel >= 6.9
#
# Asserts (per AC):
#   1. TCP connect to a `reject` port yields ECONNREFUSED, captured RST
#      has valid checksum, source/dest swapped vs the original SYN, and
#      the rejected_total metric grew.
#   2. UDP packet to a `reject` port yields ICMP type 3 code 3 captured
#      on the attacker side with valid checksums.
#   3. A SYN sourced from the whitelisted subnet (scapy-spoofed) does
#      NOT produce a RST.

load '../lib/ebpf_helpers'
load '../lib/reject_helpers'

REJECT_TCP_PORT="${REJECT_TCP_PORT:-8081}"
REJECT_UDP_PORT="${REJECT_UDP_PORT:-9999}"
WHITELIST_SUBNET_DEFAULT="10.200.0.0/24"
WHITELIST_PROBE_SRC="${WHITELIST_PROBE_SRC:-10.200.0.50}"

setup_file() {
    require_root
    require_kernel 6 9
    require_tool jq
    require_tool bc

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "suite 42 requires EBPF_2VM_MODE=true (forged-reply capture on attacker VM)"
    fi

    require_reject_tools

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-reject-$$"
    mkdir -p "$DATA_DIR"

    # The fixture's whitelist allow rule is keyed on __WHITELIST_SUBNET__.
    # prepare_ebpf_config defaults this to 10.200.0.0/24, which is what
    # the scapy spoof test below uses.
    export WHITELIST_SUBNET="${WHITELIST_SUBNET:-${WHITELIST_SUBNET_DEFAULT}}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-reject.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-reject-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers local to this suite ───────────────────────────────────────

_metric_or_zero() {
    local v
    v="$(get_metrics_value "$1" "${2:-}" 2>/dev/null || echo 0)"
    [ -z "$v" ] && v=0
    echo "$v"
}

_attacker_iface() {
    # The attacker's NIC on the 56.0/24 private network. ip route covers
    # the case where eth0 is the management bridge and eth1 carries the
    # test traffic (the standard Vagrant 2VM layout).
    local route
    route="$(ip -4 route get "${AGENT_VM_IP}" 2>/dev/null | head -1)"
    if [[ "$route" =~ dev[[:space:]]+([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "eth1"
    fi
}

# ── Tests ─────────────────────────────────────────────────────────────

@test "TCP reject rule: forged RST yields ECONNREFUSED on attacker" {
    local iface
    iface="$(_attacker_iface)"
    export REJECT_CAPTURE_IFACE="$iface"

    local rejected_before
    rejected_before="$(_metric_or_zero ebpfsentinel_packets_total \
        '{interface="FIREWALL_METRICS",action="rejected"}')"

    local bpf="tcp and src host ${AGENT_VM_IP} and src port ${REJECT_TCP_PORT}"
    local pcap
    pcap="$(reject_start_capture "$bpf")" || skip "could not start tcpdump on attacker VM"

    # Trigger: TCP connect attempt. Expect ECONNREFUSED (RST received).
    if ! reject_tcp_connect_refused "${AGENT_VM_IP}" "${REJECT_TCP_PORT}"; then
        reject_stop_capture "$pcap" >/dev/null 2>&1 || true
        return 1
    fi

    local local_pcap
    local_pcap="$(reject_stop_capture "$pcap")"

    # Capture must contain at least one RST sourced from the agent.
    local rst_count
    rst_count="$(reject_count_rst "$local_pcap" "${AGENT_VM_IP}")"
    rst_count="${rst_count:-0}"
    [ "$rst_count" -ge 1 ] || {
        echo "expected ≥1 RST sourced from ${AGENT_VM_IP} in ${local_pcap}, got ${rst_count}" >&2
        return 1
    }

    # The agent's `rejected` metric must have grown. The kernel-metrics
    # collection loop polls the eBPF maps on a 10s tick, so poll for up to
    # ~18s for the counter to reflect the reject rather than reading once.
    local rejected_after grew=0 i
    for ((i = 0; i < 18; i++)); do
        rejected_after="$(_metric_or_zero ebpfsentinel_packets_total \
            '{interface="FIREWALL_METRICS",action="rejected"}')"
        if [ "$(echo "$rejected_after > $rejected_before" | bc -l)" = "1" ]; then
            grew=1
            break
        fi
        sleep 1
    done
    [ "$grew" = "1" ] || {
        echo "rejected counter did not grow: before=${rejected_before} after=${rejected_after}" >&2
        return 1
    }
}

@test "TCP reject RST has valid checksum and swapped src/dst" {
    local iface
    iface="$(_attacker_iface)"
    export REJECT_CAPTURE_IFACE="$iface"

    local bpf="tcp port ${REJECT_TCP_PORT}"
    local pcap
    pcap="$(reject_start_capture "$bpf")" || skip "could not start tcpdump on attacker VM"

    reject_tcp_connect_refused "${AGENT_VM_IP}" "${REJECT_TCP_PORT}" || true

    local local_pcap
    local_pcap="$(reject_stop_capture "$pcap")"

    # First RST must have src=agent, dst=attacker, srcport=REJECT_TCP_PORT.
    reject_first_rst_swapped "$local_pcap" \
        "${ATTACKER_VM_IP}" "${AGENT_VM_IP}" "${REJECT_TCP_PORT}" \
        || {
            echo "first RST in ${local_pcap} did not match swapped 4-tuple" >&2
            tshark -r "$local_pcap" -Y "tcp.flags.reset == 1" 2>/dev/null | head -3 >&2 || true
            return 1
        }

    reject_assert_checksums_valid "$local_pcap"
}

@test "UDP reject rule: ICMP Dest-Port-Unreachable observed on attacker" {
    local iface
    iface="$(_attacker_iface)"
    export REJECT_CAPTURE_IFACE="$iface"

    local bpf="icmp and src host ${AGENT_VM_IP}"
    local pcap
    pcap="$(reject_start_capture "$bpf")" || skip "could not start tcpdump on attacker VM"

    # Trigger UDP packet to the reject port. send_udp_from_ns wraps ncat -u.
    send_udp_from_ns "${AGENT_VM_IP}" "${REJECT_UDP_PORT}" "PROBE" 2 || true

    local local_pcap
    local_pcap="$(reject_stop_capture "$pcap")"

    local icmp_count
    icmp_count="$(reject_count_icmp_unreach "$local_pcap" "${AGENT_VM_IP}")"
    icmp_count="${icmp_count:-0}"
    [ "$icmp_count" -ge 1 ] || {
        echo "expected ≥1 ICMP Dest-Port-Unreachable from ${AGENT_VM_IP} in ${local_pcap}, got ${icmp_count}" >&2
        tshark -r "$local_pcap" 2>/dev/null | head -5 >&2 || true
        return 1
    }

    reject_assert_checksums_valid "$local_pcap"
}

@test "whitelisted source NOT rejected (no RST when src is in whitelist)" {
    if ! "$EBPF_SCAPY_PY" -c "import scapy.all" >/dev/null 2>&1; then
        echo "scapy not available — cannot forge whitelisted-source SYN" >&2
        return 1
    fi

    local iface
    iface="$(_attacker_iface)"
    export REJECT_CAPTURE_IFACE="$iface"

    local bpf="tcp and src host ${AGENT_VM_IP} and src port ${REJECT_TCP_PORT}"
    local pcap
    pcap="$(reject_start_capture "$bpf")" || skip "could not start tcpdump on attacker VM"

    # Send a SYN with a spoofed source inside the whitelist subnet.
    # The agent must NOT emit a forged RST in response (whitelist allow
    # fires before the reject rule). Use sudo for raw-socket access.
    sudo -n "$EBPF_SCAPY_PY" - <<PY 2>/dev/null || true
from scapy.all import IP, TCP, send
pkt = IP(src="${WHITELIST_PROBE_SRC}", dst="${AGENT_VM_IP}") / \
      TCP(sport=33333, dport=${REJECT_TCP_PORT}, flags="S", seq=1000)
send(pkt, count=3, inter=0.1, verbose=False)
PY

    sleep 2
    local local_pcap
    local_pcap="$(reject_stop_capture "$pcap")"

    local rst_count
    rst_count="$(reject_count_rst "$local_pcap" "${AGENT_VM_IP}")"
    rst_count="${rst_count:-0}"
    [ "$rst_count" -eq 0 ] || {
        echo "whitelisted source should NOT receive a RST, got ${rst_count}" >&2
        tshark -r "$local_pcap" 2>/dev/null | head -5 >&2 || true
        return 1
    }
}
