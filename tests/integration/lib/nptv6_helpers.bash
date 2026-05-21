#!/usr/bin/env bash
# nptv6_helpers.bash — IPv6 packet crafting + capture assertion for suite 54.
#
# NPTv6 (RFC 6296) is a stateless, checksum-neutral prefix translation.
# We assert it from the outside: ship an IPv6 packet from the attacker
# whose source address sits in the configured internal prefix, capture
# on the backend (post-transit), and confirm the source-prefix swap.
#
# Requires: vm_helpers.bash already sourced. The attacker VM ships scapy
# at /opt/scapy-venv (see setup-attacker.sh); the backend ships tcpdump.

# _attacker_ssh defined elsewhere — guard against duplicate definition.
if ! declare -F _attacker_ssh >/dev/null 2>&1; then
    _attacker_ssh() {
        ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
            -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "vagrant@${ATTACKER_VM_IP}" -- "$@"
    }
fi

# scapy_send_ipv6_via <src_v6> <dst_v6> [count] [iface]
#
# Drive scapy on the attacker to emit count IPv6/UDP packets with the
# given source / destination addresses. UDP is used (not TCP) so the
# kernel on the attacker doesn't ARP/NDP-resolve a route for the
# rewritten external prefix. Echoes 0 on success.
scapy_send_ipv6_via() {
    local src="${1:?usage: scapy_send_ipv6_via <src_v6> <dst_v6> [count] [iface]}"
    local dst="${2:?usage: scapy_send_ipv6_via <src_v6> <dst_v6> [count] [iface]}"
    local count="${3:-3}"
    local iface="${4:-eth1}"
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" -- \
        sudo /opt/scapy-venv/bin/python3 - "${src}" "${dst}" "${count}" "${iface}" <<'PY'
import sys
from scapy.all import IPv6, UDP, send

src, dst, count, iface = sys.argv[1:]
count = int(count)
for i in range(count):
    pkt = IPv6(src=src, dst=dst) / UDP(sport=30000 + i, dport=4546) / b"nptv6-probe"
    send(pkt, iface=iface, verbose=0)
PY
}

# capture_backend_ipv6 <output_pcap> <duration_s> [iface]
#
# Start tcpdump on the backend, capturing IPv6 traffic for duration_s
# seconds, then SCP the pcap back to the agent host into output_pcap.
capture_backend_ipv6() {
    local outfile="${1:?usage: capture_backend_ipv6 <output_pcap> <duration> [iface]}"
    local duration="${2:?usage: capture_backend_ipv6 <output_pcap> <duration> [iface]}"
    local iface="${3:-eth1}"
    local remote="/tmp/nptv6-cap-$$.pcap"
    _backend_ssh_sudo timeout "${duration}" \
        tcpdump -i "${iface}" -n -w "${remote}" 'ip6' >/dev/null 2>&1 || true
    scp -i "${BACKEND_SSH_KEY}" -o StrictHostKeyChecking=no \
        "vagrant@${BACKEND_VM_IP}:${remote}" "${outfile}" >/dev/null 2>&1 || return 1
    _backend_ssh_sudo rm -f "${remote}" 2>/dev/null || true
}

# assert_ipv6_src_prefix <pcap> <expected_prefix> [min_packets]
#
# Parse <pcap> with tcpdump -nr and count IPv6 packets whose source address
# starts with <expected_prefix>. Echoes the match count, returns 0 when
# >= min_packets (default 1).
assert_ipv6_src_prefix() {
    local pcap="${1:?usage: assert_ipv6_src_prefix <pcap> <prefix> [min]}"
    local prefix="${2:?usage: assert_ipv6_src_prefix <pcap> <prefix> [min]}"
    local min="${3:-1}"
    [ -s "${pcap}" ] || {
        echo "0"
        return 1
    }
    local hits
    hits="$(tcpdump -nr "${pcap}" 2>/dev/null \
        | awk -v p="${prefix}" '
            $0 ~ "IP6 "p { c++ }
            END { print c+0 }
        ')"
    echo "${hits:-0}"
    [ "${hits:-0}" -ge "${min}" ]
}

# nptv6_list_cli
#
# Run `ebpfsentinel-agent nat nptv6 list --output json` on the agent VM and
# echo the parsed JSON. The CLI talks to the local agent on its HTTP port,
# so a running agent is required.
nptv6_list_cli() {
    _agent_ssh_sudo \
        ebpfsentinel-agent --output json nat nptv6 list 2>/dev/null \
        || _agent_ssh_sudo ebpfsentinel-agent nat nptv6 list 2>/dev/null
}
