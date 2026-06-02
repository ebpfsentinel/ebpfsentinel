#!/usr/bin/env bash
# scrub_helpers.bash — Byte-level pcap assertions for tc-scrub.
#
# Backend captures crafted client → backend packets after they transit
# the agent's tc-scrub. The pcap is fetched locally; these helpers run
# tcpdump (-v -n) against it and grep the verbose decoder lines for
# IPv4 / TCP fields the scrub program rewrites.
#
# Requires: tcpdump on the bats runner (attacker VM provisions it).
#
# Helpers echo "ok" or the offending value on stdout and return 0 / 1
# accordingly so callers can do plain bats `[ "$(...)" = "ok" ]` checks.

# _scrub_dump_lines <pcap> <bpf>
# Run tcpdump on the local pcap with verbose IP/TCP decoding and grep
# the BPF filter. Echoes the matching lines.
_scrub_dump_lines() {
    local pcap="${1:?usage: _scrub_dump_lines <pcap> <bpf>}"
    local bpf="${2:?usage: _scrub_dump_lines <pcap> <bpf>}"
    [ -s "$pcap" ] || return 1
    tcpdump -nvr "$pcap" "$bpf" 2>/dev/null
}

# assert_ttl_ge <pcap> <bpf> <min_ttl>
#
# Verify every matching packet has TTL >= min_ttl. Returns 0 when all
# packets pass, 1 when any packet falls below. Echoes the first offender
# (or "ok" on success).
assert_ttl_ge() {
    local pcap="${1:?usage: assert_ttl_ge <pcap> <bpf> <min_ttl>}"
    local bpf="${2:?usage: assert_ttl_ge <pcap> <bpf> <min_ttl>}"
    local min_ttl="${3:?usage: assert_ttl_ge <pcap> <bpf> <min_ttl>}"
    local lines bad
    lines="$(_scrub_dump_lines "$pcap" "$bpf")" || { echo "empty pcap"; return 1; }
    [ -n "$lines" ] || { echo "no matching packets"; return 1; }
    bad="$(echo "$lines" | awk -v m="$min_ttl" '
        match($0, /ttl [0-9]+/) {
            ttl = substr($0, RSTART + 4, RLENGTH - 4) + 0
            if (ttl < m) { print "ttl=" ttl; exit }
        }')"
    if [ -n "$bad" ]; then
        echo "$bad"
        return 1
    fi
    echo "ok"
}

# assert_mss_le <pcap> <bpf> <max_mss>
#
# Verify TCP MSS option <= max_mss for every SYN packet matching the BPF.
# Packets without MSS option are ignored. Returns 0/1 like assert_ttl_ge.
assert_mss_le() {
    local pcap="${1:?usage: assert_mss_le <pcap> <bpf> <max_mss>}"
    local bpf="${2:?usage: assert_mss_le <pcap> <bpf> <max_mss>}"
    local max_mss="${3:?usage: assert_mss_le <pcap> <bpf> <max_mss>}"
    local lines bad
    lines="$(_scrub_dump_lines "$pcap" "$bpf")" || { echo "empty pcap"; return 1; }
    [ -n "$lines" ] || { echo "no matching packets"; return 1; }
    bad="$(echo "$lines" | awk -v m="$max_mss" '
        match($0, /mss [0-9]+/) {
            mss = substr($0, RSTART + 4, RLENGTH - 4) + 0
            if (mss > m) { print "mss=" mss; exit }
        }')"
    if [ -n "$bad" ]; then
        echo "$bad"
        return 1
    fi
    echo "ok"
}

# assert_df_cleared <pcap> <bpf>
#
# Verify no matching packet carries the IPv4 DF flag. tcpdump prints
# "flags [DF]" when DF is set; "flags [none]" when cleared.
assert_df_cleared() {
    local pcap="${1:?usage: assert_df_cleared <pcap> <bpf>}"
    local bpf="${2:?usage: assert_df_cleared <pcap> <bpf>}"
    local lines
    lines="$(_scrub_dump_lines "$pcap" "$bpf")" || { echo "empty pcap"; return 1; }
    [ -n "$lines" ] || { echo "no matching packets"; return 1; }
    if echo "$lines" | grep -qE 'flags \[DF[^]]*\]'; then
        echo "DF still set"
        return 1
    fi
    echo "ok"
}

# assert_ip_id_not <pcap> <bpf> <forbidden_id>
#
# Verify no matching packet carries the forbidden IPv4 identification
# value. tcpdump prints "id NNN," in the verbose IP header decode.
assert_ip_id_not() {
    local pcap="${1:?usage: assert_ip_id_not <pcap> <bpf> <forbidden>}"
    local bpf="${2:?usage: assert_ip_id_not <pcap> <bpf> <forbidden>}"
    local forbidden="${3:?usage: assert_ip_id_not <pcap> <bpf> <forbidden>}"
    local lines hits
    lines="$(_scrub_dump_lines "$pcap" "$bpf")" || { echo "empty pcap"; return 1; }
    [ -n "$lines" ] || { echo "no matching packets"; return 1; }
    hits="$(echo "$lines" | awk -v f="$forbidden" '
        match($0, /id [0-9]+/) {
            id = substr($0, RSTART + 3, RLENGTH - 3) + 0
            if (id == f) { c++ }
        }
        END { print c+0 }')"
    if [ "${hits:-0}" -gt 0 ]; then
        echo "ip-id=${forbidden} kept on ${hits} packet(s)"
        return 1
    fi
    echo "ok"
}

# scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]
#
# Drive scapy on the attacker VM to emit count crafted TCP SYNs with the
# given header values toward dst_ip:port (port hardcoded to 80 — the
# backend's nginx listens). Bash-side wrapper for use in 3-VM suites.
# Echoes the remote scapy exit code on stdout (0 = sent).
scapy_send_via() {
    local dst_ip="${1:?usage: scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]}"
    local ttl="${2:?usage: scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]}"
    local ip_id="${3:?usage: scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]}"
    local mss="${4:?usage: scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]}"
    local df="${5:?usage: scapy_send_via <dst_ip> <ttl> <ip_id> <mss> <df> [count]}"
    local count="${6:-1}"
    # Pass a non-empty sentinel ("none") for the DF-clear case. An empty-string
    # argv element is silently dropped when ssh re-joins the remote command with
    # spaces and the login shell re-splits it, which would shift `count` into the
    # flags slot and crash the unpack below — so every positional must be
    # non-empty over the wire. The python side maps "none" back to no flags.
    local flags="DF"
    [ "$df" = "0" ] && flags="none"
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" -- \
        sudo /opt/scapy-venv/bin/python3 - "${dst_ip}" "${ttl}" "${ip_id}" "${mss}" "${flags}" "${count}" <<'PY'
import random
import sys
from scapy.all import IP, TCP, send

dst, ttl, ip_id, mss, flags, count = sys.argv[1:]
ttl = int(ttl); ip_id = int(ip_id); mss = int(mss); count = int(count)
flags = "" if flags == "none" else flags
# Fresh source-port base per invocation: reusing fixed ports across the
# suite's tests lets the agent's conntrack/stateful-firewall state from an
# earlier test drop a later test's reused 4-tuple, so the transit never
# reaches the backend and the capture comes back empty.
base = random.randint(20000, 60000)
for i in range(count):
    pkt = IP(dst=dst, ttl=ttl, id=ip_id, flags=flags) / \
          TCP(sport=base + i, dport=80, flags="S", seq=0,
              options=[('MSS', mss)])
    send(pkt, verbose=0)
PY
}

# scapy_send_fragment_via <dst_ip> [count]
#
# Drive scapy on the attacker VM to emit `count` fragmented IPv4 datagrams
# toward dst_ip (a large UDP payload split with scapy's fragment()). Each
# emitted IP fragment carries MF set or a non-zero fragment offset, which is
# exactly what tc-scrub's drop_fragments path refuses. Used to assert that a
# scrubbing gateway drops fragments before forwarding them to the backend.
scapy_send_fragment_via() {
    local dst_ip="${1:?usage: scapy_send_fragment_via <dst_ip> [count]}"
    local count="${2:-1}"
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" -- \
        sudo /opt/scapy-venv/bin/python3 - "${dst_ip}" "${count}" <<'PY'
import random
import sys
from scapy.all import IP, UDP, fragment, send

dst, count = sys.argv[1:]
count = int(count)
base = random.randint(20000, 60000)
for i in range(count):
    # 2000-byte payload over a 576-byte fragsize => several fragments, all of
    # which have MF set or a non-zero offset.
    pkt = IP(dst=dst, id=40000 + i) / UDP(sport=base + i, dport=9) / (b"X" * 2000)
    for frag in fragment(pkt, fragsize=576):
        send(frag, verbose=0)
PY
}
