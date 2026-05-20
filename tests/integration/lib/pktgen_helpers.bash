#!/usr/bin/env bash
# pktgen_helpers.bash — Drive the kernel pktgen module from BATS suites.
#
# pktgen is auto-loaded on the attacker VM (Story 34.3) via
# /etc/modules-load.d/pktgen.conf. This helper opens /proc/net/pktgen/*
# control files to configure a single TX thread, then echoes "start"
# into pgctrl. Rate is controlled via the "delay" knob (ns between
# packets); pktgen will run at the maximum the NIC + driver can
# sustain when delay=0.
#
# Topology assumption: BATS runs on the attacker VM (EBPF_2VM_MODE=true)
# and drives traffic locally out the attacker NIC toward the agent.
#
# Public entrypoints:
#   pktgen_run <duration_s> [pkt_size] [dport] [delay_ns]
#       Run pktgen for <duration_s>, then stop, then echo the realised
#       PPS to stdout. Side-effects: writes /tmp/pktgen-<iface>.stats.
#   pktgen_stop
#       Best-effort cleanup (rem_device_all + reset pgctrl).
#   pktgen_realised_pps
#       Parse the per-iface result file and echo the average pps.
#
# All helpers `skip` the calling test if pktgen is unavailable or if
# the suite is not running in 2-VM mode (real flood at >1 Mpps cannot
# be achieved against a host-local netns reliably and would skew the
# XDP-savings assertion).

PKTGEN_PROCROOT="${PKTGEN_PROCROOT:-/proc/net/pktgen}"
PKTGEN_KTHREAD="${PKTGEN_KTHREAD:-kpktgend_0}"
PKTGEN_IFACE="${PKTGEN_IFACE:-eth1}"
PKTGEN_PKT_SIZE_DEFAULT="${PKTGEN_PKT_SIZE_DEFAULT:-60}"
PKTGEN_DPORT_DEFAULT="${PKTGEN_DPORT_DEFAULT:-9}"
PKTGEN_DELAY_DEFAULT_NS="${PKTGEN_DELAY_DEFAULT_NS:-0}"

# ── Guards ────────────────────────────────────────────────────────────

# require_pktgen
# Skip the calling test if pktgen is not loaded / accessible.
require_pktgen() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "pktgen suite requires EBPF_2VM_MODE=true (real flood from attacker NIC)"
    fi
    if [ ! -d "$PKTGEN_PROCROOT" ]; then
        if ! sudo modprobe pktgen 2>/dev/null; then
            skip "pktgen kernel module unavailable on this host"
        fi
        sleep 0.2
    fi
    if [ ! -w "${PKTGEN_PROCROOT}/pgctrl" ]; then
        # /proc/net/pktgen/* requires root.
        if [ "$(id -u)" -ne 0 ]; then
            skip "pktgen control files require root on attacker VM"
        fi
    fi
    if [ ! -e "${PKTGEN_PROCROOT}/${PKTGEN_KTHREAD}" ]; then
        skip "pktgen thread ${PKTGEN_KTHREAD} missing under ${PKTGEN_PROCROOT}"
    fi
}

# _pktgen_validate_target <ip>
# Refuse to send pktgen at non-RFC1918 addresses.
_pktgen_validate_target() {
    local ip="${1:?usage: _pktgen_validate_target <ip>}"
    case "$ip" in
        10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*| \
        172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*| \
        172.28.*|172.29.*|172.30.*|172.31.*|192.168.*|127.*)
            return 0
            ;;
        *)
            skip "pktgen target ${ip} is not RFC1918 — refusing to flood"
            ;;
    esac
}

# _pktgen_resolve_dst_mac <ip> <iface>
# Resolve the destination MAC via the host ARP table; fall back to a
# kernel-prime ping when the entry is missing. Echoes the MAC.
_pktgen_resolve_dst_mac() {
    local ip="$1"
    local iface="$2"
    local mac
    mac="$(ip neigh show "$ip" dev "$iface" 2>/dev/null | awk '{print $5}' | head -1)"
    if [ -z "$mac" ] || [ "$mac" = "FAILED" ]; then
        ping -c 1 -W 1 -I "$iface" "$ip" >/dev/null 2>&1 || true
        sleep 0.2
        mac="$(ip neigh show "$ip" dev "$iface" 2>/dev/null | awk '{print $5}' | head -1)"
    fi
    echo "${mac:-}"
}

# ── Control wrappers ──────────────────────────────────────────────────

# _pg <file> <cmd>
# Echo into a /proc/net/pktgen control file. Uses sudo when not root.
_pg() {
    local target="${PKTGEN_PROCROOT}/$1"
    local cmd="$2"
    if [ "$(id -u)" -eq 0 ]; then
        echo "$cmd" > "$target"
    else
        echo "$cmd" | sudo tee "$target" >/dev/null
    fi
}

# pktgen_stop
# Best-effort teardown — safe to call from teardown handlers.
pktgen_stop() {
    if [ -e "${PKTGEN_PROCROOT}/pgctrl" ]; then
        _pg pgctrl "stop" 2>/dev/null || true
    fi
    if [ -e "${PKTGEN_PROCROOT}/${PKTGEN_KTHREAD}" ]; then
        _pg "${PKTGEN_KTHREAD}" "rem_device_all" 2>/dev/null || true
    fi
}

# pktgen_configure <iface> <dst_ip> <dst_mac> <pkt_size> <dport> <delay_ns>
# Wire one TX thread (kpktgend_0) onto <iface>, target <dst_ip>:<dport>
# with the given packet size and inter-packet delay (ns).
pktgen_configure() {
    local iface="${1:?usage: pktgen_configure <iface> <dst_ip> <dst_mac> <pkt_size> <dport> <delay_ns>}"
    local dst_ip="${2:?dst_ip required}"
    local dst_mac="${3:?dst_mac required}"
    local pkt_size="${4:-$PKTGEN_PKT_SIZE_DEFAULT}"
    local dport="${5:-$PKTGEN_DPORT_DEFAULT}"
    local delay_ns="${6:-$PKTGEN_DELAY_DEFAULT_NS}"

    pktgen_stop
    _pg "${PKTGEN_KTHREAD}" "add_device ${iface}"

    _pg "${iface}" "count 0"          # 0 = run until stopped
    _pg "${iface}" "clone_skb 1000"   # share one skb; reduces alloc overhead
    _pg "${iface}" "pkt_size ${pkt_size}"
    _pg "${iface}" "delay ${delay_ns}"
    _pg "${iface}" "dst ${dst_ip}"
    _pg "${iface}" "dst_mac ${dst_mac}"
    _pg "${iface}" "udp_src_min 1024"
    _pg "${iface}" "udp_src_max 65535"
    _pg "${iface}" "udp_dst_min ${dport}"
    _pg "${iface}" "udp_dst_max ${dport}"
    _pg "${iface}" "flag IPSRC_RND"
}

# pktgen_run <duration_s> [pkt_size] [dport] [delay_ns]
# Launch a pre-configured pktgen thread (call pktgen_configure first)
# for <duration_s>, then stop and echo the achieved pps to stdout.
# Stats also captured to /tmp/pktgen-<iface>.stats.
pktgen_run() {
    local duration="${1:?usage: pktgen_run <duration_s> [pkt_size] [dport] [delay_ns]}"
    local pkt_size="${2:-$PKTGEN_PKT_SIZE_DEFAULT}"
    local dport="${3:-$PKTGEN_DPORT_DEFAULT}"
    local delay_ns="${4:-$PKTGEN_DELAY_DEFAULT_NS}"

    require_pktgen

    local iface="$PKTGEN_IFACE"
    local dst_ip="${AGENT_VM_IP:-${AGENT_HOST:-127.0.0.1}}"
    _pktgen_validate_target "$dst_ip"

    local dst_mac
    dst_mac="$(_pktgen_resolve_dst_mac "$dst_ip" "$iface")"
    if [ -z "$dst_mac" ]; then
        skip "could not resolve MAC for ${dst_ip} on ${iface}"
    fi

    pktgen_configure "$iface" "$dst_ip" "$dst_mac" "$pkt_size" "$dport" "$delay_ns"

    # pgctrl start blocks until completion when count > 0, but with
    # count=0 it returns immediately. Drive duration via a kill-style
    # timer that issues "stop" after <duration> seconds.
    ( sleep "$duration"; _pg pgctrl "stop" 2>/dev/null || true ) &
    local stopper=$!

    _pg pgctrl "start"

    wait "$stopper" 2>/dev/null || true
    sleep 0.2

    # Persist stats and return realised pps.
    local stats_file="/tmp/pktgen-${iface}.stats"
    cat "${PKTGEN_PROCROOT}/${iface}" 2>/dev/null | tee "$stats_file" >/dev/null || true
    pktgen_realised_pps
}

# pktgen_realised_pps
# Parse the per-iface result line from the last pktgen run and echo the
# average pps. Returns 0 even if the result is missing (echoes "0").
pktgen_realised_pps() {
    local iface="$PKTGEN_IFACE"
    local stats="${PKTGEN_PROCROOT}/${iface}"
    if [ ! -r "$stats" ]; then
        echo "0"
        return 0
    fi
    # Line shape: "  pps NNN ..."
    local pps
    pps="$(grep -E "^[[:space:]]*[0-9]+pps" "$stats" 2>/dev/null | awk '{print $1}' | head -1)"
    if [ -z "$pps" ]; then
        pps="$(awk '/pps/ && $1 ~ /^[0-9]+pps/ {gsub("pps","",$1); print $1; exit}' "$stats" 2>/dev/null)"
    fi
    pps="${pps//pps/}"
    echo "${pps:-0}"
}
