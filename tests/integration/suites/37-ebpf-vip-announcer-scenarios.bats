#!/usr/bin/env bats
# 37-ebpf-vip-announcer-scenarios.bats — L2 VIP announcer eBPF scenarios
#
# Validates the bounded XDP ARP responder + userspace gratuitous ARP:
#   * a speaker answers ARP for an owned VIP with its own NIC MAC
#   * a speaker does NOT answer ARP for a non-VIP address
#   * gratuitous ARP is emitted on speaker takeover (takeover metric)
#   * the per-VIP forged-reply metric increments
#   * a standby node is completely silent (split-brain safe)
#
# Requires: root, kernel >= 5.17, bpftool, python3 + scapy

load '../lib/helpers'
load '../lib/ebpf_helpers'

VIP_ADDR="10.200.0.50"
NON_VIP_ADDR="10.200.0.99"

require_scapy() {
    "$EBPF_SCAPY_PY" -c 'import scapy.all' 2>/dev/null || { echo "scapy not available" >&2; return 1; }
}

# Send a broadcast ARP request for $1 from inside the test netns and echo
# the responder's hardware address (empty if no reply within the timeout).
arp_probe() {
    local target="$1"
    ip netns exec "$EBPF_TEST_NS" "$EBPF_SCAPY_PY" - "$EBPF_VETH_NS" "$target" <<'PY'
import sys
from scapy.all import Ether, ARP, srp
iface, target = sys.argv[1], sys.argv[2]
ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
    iface=iface, timeout=3, retry=2, verbose=0,
)
if ans:
    print(ans[0][1].hwsrc)
PY
}

host_mac() {
    cat "/sys/class/net/${EBPF_VETH_HOST}/address"
}

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-vip-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-vip-announcer.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-vip-$$}"
    rm -f "${PREPARED_CONFIG:-}"
    rm -f "${STANDBY_CONFIG:-}"
}

# ── Speaker: answers ARP for an owned VIP ────────────────────────────

@test "speaker answers ARP for owned VIP with its own NIC MAC" {
    require_root
    require_scapy

    sleep 2
    local responder expected
    responder="$(arp_probe "$VIP_ADDR")"
    expected="$(host_mac)"

    [ -n "$responder" ] || {
        echo "no ARP reply received for VIP $VIP_ADDR" >&2
        return 1
    }
    local got want
    got="$(echo "$responder" | tr 'A-F' 'a-f')"
    want="$(echo "$expected" | tr 'A-F' 'a-f')"
    [ "$got" = "$want" ] || {
        echo "ARP reply MAC $got != NIC MAC $want" >&2
        return 1
    }
}

# ── Speaker: silent for a non-VIP address ────────────────────────────

@test "speaker does NOT answer ARP for a non-VIP address" {
    require_root
    require_scapy

    local responder
    responder="$(arp_probe "$NON_VIP_ADDR")"
    [ -z "$responder" ] || {
        echo "unexpected ARP reply for non-VIP $NON_VIP_ADDR: $responder" >&2
        return 1
    }
}

# ── Gratuitous ARP on takeover (metric) ──────────────────────────────

@test "gratuitous ARP emitted on speaker takeover" {
    require_root

    # announce_takeover() emits one gratuitous ARP per owned VIP and bumps
    # the takeover counter exactly once on the transition into speaker.
    local value
    value="$(wait_for_metric ebpfsentinel_lb_vip_takeovers_total 1 20 '{vip="web-vip"}')" || {
        echo "takeover metric never reached >= 1" >&2
        return 1
    }
    [ -n "$value" ]
}

# ── Per-VIP forged-reply metric ──────────────────────────────────────

@test "lb_vip_arp_replies_total increments after an ARP for the VIP" {
    require_root
    require_scapy

    arp_probe "$VIP_ADDR" >/dev/null
    arp_probe "$VIP_ADDR" >/dev/null

    # The kernel per-CPU counter is mirrored into Prometheus on a 15s
    # cadence — allow one full refresh cycle plus slack.
    local value
    value="$(wait_for_metric ebpfsentinel_lb_vip_arp_replies_total 1 25 '{vip="web-vip"}')" || {
        echo "arp replies metric never reached >= 1" >&2
        return 1
    }
    [ -n "$value" ]
}

# ── Standby is split-brain safe (silent) ─────────────────────────────

@test "standby node never answers ARP for the VIP" {
    require_root
    require_scapy

    stop_ebpf_agent 2>/dev/null || true
    sleep 1

    STANDBY_CONFIG="$(prepare_ebpf_config \
        "${FIXTURE_DIR}/config-ebpf-vip-announcer-standby.yaml" \
        "/tmp/ebpfsentinel-test-vip-standby-$$.yaml")"
    export STANDBY_CONFIG

    start_ebpf_agent "$STANDBY_CONFIG"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    sleep 2

    local responder
    responder="$(arp_probe "$VIP_ADDR")"
    [ -z "$responder" ] || {
        echo "standby answered ARP for VIP (split-brain!): $responder" >&2
        return 1
    }

    # A standby must never have emitted a gratuitous ARP / takeover.
    local takeovers
    takeovers="$(get_metrics_value ebpfsentinel_lb_vip_takeovers_total '{vip="web-vip"}')" || true
    [ -z "$takeovers" ] || [ "$takeovers" = "0" ] || {
        echo "standby recorded a takeover: $takeovers" >&2
        return 1
    }
}
