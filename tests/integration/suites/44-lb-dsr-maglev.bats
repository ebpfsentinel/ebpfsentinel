#!/usr/bin/env bats
# 44-lb-dsr-maglev.bats — L4 LB DSR + Maglev disruption-bound, 3-VM.
#
# Drives a real client→VIP→backend flow across the three-VM transit
# topology (client .20, agent .10 dual-NIC, backend .30) and asserts:
#
#   * the agent's XDP load balancer L2-forwards the client packet to the
#     backend with the client src IP and the VIP dst IP both preserved
#     (proves L2 direct-server-return: no DNAT of the dst, no SNAT/proxy
#     of the src)
#   * the in-kernel Maglev ring rebuilds with < 2/N entries reassigned
#     when one backend is removed (consistent-hash disruption bound)
#   * the XDP ARP responder answers ARP for the VIP on the client subnet
#   * a gratuitous ARP is emitted on speaker takeover (metric incremented)
#   * the agent does NOT alert on its own ARP announcements
#     (is_self_announced predicate — ARP-guard foundation)
#
# Requires: 3-VM mode (EBPF_3VM_MODE=true), root on each VM, kernel >= 6.9
# on the agent, bpftool + tcpdump on agent + backend, python3 + scapy
# available locally (attacker VM).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/lb_helpers'

LB_SERVICE_ID="dsr-svc"
LB_SERVICE_PORT="80"
LB_BACKEND_PORT="80"
LB_BACKEND_ADDR="${BACKEND_VM_IP:-192.168.57.30}"
LB_RING_SIZE="${LB_MAGLEV_RING_SIZE:-65537}"

setup_file() {
    skip_if_not_3vm
    require_kernel 6 9
    require_tool curl
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lbdsr-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-lb-dsr.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    route_via_agent backend >/dev/null 2>&1 || true
    start_backend_service nginx "$LB_BACKEND_PORT" || true
    set_backend_arp >/dev/null 2>&1 || true
}

teardown_file() {
    delete_lb_service "$LB_SERVICE_ID" >/dev/null 2>&1 || true
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lbdsr-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# EBPF_SCAPY_PY (the scapy venv interpreter) is resolved in ebpf_helpers.
require_scapy() {
    "$EBPF_SCAPY_PY" -c 'import scapy.all' 2>/dev/null || { echo "scapy not available" >&2; return 1; }
}

agent_iface_mac() {
    # Echo the agent's MAC on the client-side NIC (eth1 in 3VM mode).
    _agent_ssh cat "/sys/class/net/${EBPF_AGENT_INTERFACE:-eth1}/address"
}

# ── DSR end-to-end ───────────────────────────────────────────────────

@test "DSR: agent L2-forwards to backend with client src and VIP dst intact" {
    skip_if_not_3vm

    # Pin one backend on the same L2 segment as the agent's backend NIC.
    local rc
    rc="$(register_backends \
        "$LB_SERVICE_ID" "$LB_SERVICE_PORT" round_robin l2dsr \
        "b1:${LB_BACKEND_ADDR}:${LB_BACKEND_PORT}")"
    [[ "$rc" =~ ^(200|201)$ ]] || {
        echo "register_backends returned ${rc}" >&2
        return 1
    }
    sleep 2

    # Bind VIP to the backend loopback so the kernel there accepts the
    # DSR-delivered packet (dst IP still the VIP) and nginx answers from it.
    _backend_ssh_sudo ip addr add "${LB_VIP_ADDR}/32" dev lo 2>/dev/null || true

    # Capture the DSR signature entirely on the backend's ingress NIC. Doing so
    # keeps every tcpdump off the agent's backend-side NIC (eth2), which is the
    # XDP_REDIRECT egress device: on vmxnet3 a promiscuous-mode toggle (which
    # starting a capture forces) resets the driver's XDP RX/TX rings, dropping
    # the in-flight redirect this very test is trying to observe. Capturing only
    # on the backend leaves the agent's datapath undisturbed.
    #
    # The filter `src host <client> and dst host <VIP>` is a complete DSR proof:
    #   * dst = VIP (not the backend's real IP) -> the agent left L3 untouched,
    #     i.e. no DNAT rewrite of the destination.
    #   * src = the original client (not the agent) -> no SNAT / proxy hairpin;
    #     a full L4 proxy or SNAT fallback would rewrite the source to the agent
    #     and this filter would match nothing.
    # A single frame matching both is only possible under true L2 direct-server-
    # return forwarding, so the presence check below is both the positive signal
    # and the anti-DNAT/anti-SNAT negative in one.
    local pcap_backend
    pcap_backend="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" \
        "src host ${ATTACKER_VM_IP:-192.168.56.20} and dst host ${LB_VIP_ADDR} and tcp port ${LB_SERVICE_PORT}")" \
        || soft_skip "tcpdump unavailable on backend VM"

    # Drive client->VIP requests. curl is only a traffic generator here: in a
    # routed 3-VM topology the DSR reply races the capture window, so curl_rc
    # is informational and the assertion rests on the capture, not on it.
    local curl_rc=0
    curl -s --max-time 5 -o /dev/null "http://${LB_VIP_ADDR}:${LB_SERVICE_PORT}/" || curl_rc=$?
    curl -s --max-time 5 -o /dev/null "http://${LB_VIP_ADDR}:${LB_SERVICE_PORT}/" || true

    sleep 1
    local fwd_pcap
    fwd_pcap="$(stop_capture backend "$pcap_backend")"

    _backend_ssh_sudo ip addr del "${LB_VIP_ADDR}/32" dev lo 2>/dev/null || true

    # The DSR-forwarded packet reached the backend with client src + VIP dst
    # intact (proves L2 forwarding with no DNAT and no SNAT).
    local fwd_count
    fwd_count="$(tcpdump -nr "$fwd_pcap" 2>/dev/null | wc -l)"
    [ "${fwd_count:-0}" -ge 1 ] || {
        echo "backend saw no DSR-forwarded packet for VIP ${LB_VIP_ADDR} (curl_rc=${curl_rc})" >&2
        return 1
    }
}

# ── Maglev disruption bound ──────────────────────────────────────────

@test "Maglev: < 2/N ring entries reassigned on backend removal" {
    skip_if_not_3vm
    delete_lb_service "$LB_SERVICE_ID" >/dev/null 2>&1 || true
    sleep 1

    # Four maglev backends on the same backend host (distinct ports).
    # The Maglev ring is built from backend IDs, so the LB map sees N=4
    # regardless of whether each backend is wire-reachable.
    local rc4
    rc4="$(register_backends \
        "$LB_SERVICE_ID" "$LB_SERVICE_PORT" maglev l2dsr \
        "b1:${LB_BACKEND_ADDR}:8001" \
        "b2:${LB_BACKEND_ADDR}:8002" \
        "b3:${LB_BACKEND_ADDR}:8003" \
        "b4:${LB_BACKEND_ADDR}:8004")"
    [[ "$rc4" =~ ^(200|201)$ ]] || {
        echo "register_backends N=4 returned ${rc4}" >&2
        return 1
    }
    sleep 2

    local before="${DATA_DIR}/maglev-before.txt"
    dump_maglev_table "$before" || soft_skip "LB_MAGLEV map not available on agent VM"

    delete_lb_service "$LB_SERVICE_ID" >/dev/null
    sleep 1
    local rc3
    rc3="$(register_backends \
        "$LB_SERVICE_ID" "$LB_SERVICE_PORT" maglev l2dsr \
        "b1:${LB_BACKEND_ADDR}:8001" \
        "b2:${LB_BACKEND_ADDR}:8002" \
        "b3:${LB_BACKEND_ADDR}:8003")"
    [[ "$rc3" =~ ^(200|201)$ ]] || {
        echo "register_backends N=3 returned ${rc3}" >&2
        return 1
    }
    sleep 2

    local after="${DATA_DIR}/maglev-after.txt"
    dump_maglev_table "$after" || soft_skip "LB_MAGLEV map not available on agent VM (post-rebuild)"

    local remapped bound
    remapped="$(count_remapped_flows "$before" "$after")"
    # 2/N safety bound: ring_size * 2 / 4 = ring_size / 2 with N=4.
    bound=$((LB_RING_SIZE / 2))
    [ "${remapped:-0}" -lt "${bound}" ] || {
        echo "maglev disruption ${remapped} >= 2/N bound ${bound}" >&2
        return 1
    }
}

# ── VIP ARP responder ────────────────────────────────────────────────

@test "VIP ARP responder answers on the client subnet with agent's MAC" {
    skip_if_not_3vm
    require_scapy
    sleep 2

    local responder expected got want
    responder="$(sudo -n "$EBPF_SCAPY_PY" - "${EBPF_AGENT_INTERFACE:-eth1}" "${LB_VIP_ADDR}" <<'PY'
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
)" || true

    [ -n "$responder" ] || {
        echo "no ARP reply for VIP ${LB_VIP_ADDR}" >&2
        return 1
    }
    expected="$(agent_iface_mac)"
    got="$(echo "$responder" | tr 'A-F' 'a-f')"
    want="$(echo "$expected" | tr 'A-F' 'a-f')"
    [ "$got" = "$want" ] || {
        echo "ARP reply MAC ${got} != agent NIC MAC ${want}" >&2
        return 1
    }
}

# ── Gratuitous ARP on takeover ───────────────────────────────────────

@test "gratuitous ARP emitted on speaker takeover (metric)" {
    skip_if_not_3vm
    local value
    value="$(wait_for_metric ebpfsentinel_lb_vip_takeovers_total 1 20 '{vip="dsr-vip"}')" || {
        echo "takeover metric never reached >= 1" >&2
        return 1
    }
    [ -n "$value" ]
}

# ── Self-ARP not alerted (is_self_announced) ─────────────────────────

@test "is_self_announced(): agent does not alert on its own VIP ARP" {
    skip_if_not_3vm
    require_scapy

    # Drive a few ARP probes for the VIP so the forged-reply path emits
    # frames the agent's own monitoring would observe.
    "$EBPF_SCAPY_PY" - "${EBPF_AGENT_INTERFACE:-eth1}" "${LB_VIP_ADDR}" <<'PY' >/dev/null 2>&1 || true
import sys
from scapy.all import Ether, ARP, srp
iface, target = sys.argv[1], sys.argv[2]
for _ in range(3):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
        iface=iface, timeout=1, retry=0, verbose=0)
PY
    sleep 2

    # The alerts endpoint must contain no anomaly tied to the VIP IP /
    # the agent's own MAC. We deliberately accept any unrelated alert
    # but a hit on src_ip == VIP would mean is_self_announced() failed.
    local body
    body="$(api_get /api/v1/alerts 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || soft_skip "alerts endpoint returned ${HTTP_STATUS}"

    local self_alerts
    self_alerts="$(echo "$body" \
        | jq --arg vip "$LB_VIP_ADDR" \
             '[(.alerts // .) | .[]? | select((.src_ip // .source_ip // "") == $vip)] | length' \
        2>/dev/null)" || self_alerts="0"
    [ "${self_alerts:-0}" -eq 0 ] || {
        echo "agent raised ${self_alerts} self-alerts for VIP ${LB_VIP_ADDR}" >&2
        return 1
    }
}
