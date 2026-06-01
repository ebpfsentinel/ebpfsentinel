#!/usr/bin/env bash
# reject_helpers.bash — Wire-level assertions for the xdp-firewall-reject
# tail-call program. Captures inbound RST / ICMP-Unreachable replies on
# the attacker VM and validates them with tcpdump + tshark.
#
# Public entrypoints:
#   require_reject_tools                       — skip if tcpdump/tshark/ncat missing
#   reject_start_capture <bpf-filter>          — start tcpdump on attacker, echo pcap path
#   reject_stop_capture <pcap-path>            — stop tcpdump, return local pcap path
#   reject_count_rst <pcap> [src_ip]           — count RST packets sourced from src_ip
#   reject_count_icmp_unreach <pcap> [src_ip]  — count ICMP type 3 code 3 from src_ip
#   reject_assert_checksums_valid <pcap>       — tshark -V over pcap, no checksum errors
#   reject_first_rst_swapped <pcap> <orig_src> <orig_dst> <orig_dport>
#       — verify the first RST has src/dst swapped vs the original SYN
#   reject_tcp_connect_refused <host> <port>   — TCP connect, succeed iff ECONNREFUSED

REJECT_TOOL_PORT_TCP="${REJECT_TOOL_PORT_TCP:-8081}"
REJECT_TOOL_PORT_UDP="${REJECT_TOOL_PORT_UDP:-9999}"

# ── Guards ────────────────────────────────────────────────────────────

require_reject_tools() {
    local tool
    for tool in tcpdump tshark ncat; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            skip "${tool} not available on attacker VM"
        fi
    done
}

# ── Local capture (runs on attacker VM directly) ─────────────────────

# reject_start_capture <bpf-filter>
# Start a background tcpdump locally on the attacker VM and echo the
# pcap path on stdout. Caller must invoke reject_stop_capture to flush.
reject_start_capture() {
    local bpf="${1:?usage: reject_start_capture <bpf-filter>}"
    local iface="${REJECT_CAPTURE_IFACE:-eth1}"

    local pcap="/tmp/reject-cap-$$-$(date +%s).pcap"
    local pidfile="${pcap}.pid"
    local readyfile="${pcap}.ready"

    # Capture tcpdump's startup banner so we can block until it is actually
    # listening. A fixed `sleep` races the trigger on virtual NICs: the kernel
    # receives the forged RST (ncat reports "refused") but the capture isn't
    # live yet, so the pcap shows zero RSTs — a false negative.
    sudo -n nohup tcpdump -n -U -w "$pcap" -i "$iface" "$bpf" \
        >/dev/null 2>"$readyfile" &
    echo $! > "$pidfile"
    # tcpdump uses sudo so the PID we captured isn't its real pid;
    # rely on the pidfile-by-filename pattern below.

    # Wait up to 5s for "listening on <iface>", then a short extra settle so
    # the AF_PACKET ring is fully attached before the caller fires traffic.
    local waited=0
    while [ "$waited" -lt 50 ]; do
        grep -q "listening on" "$readyfile" 2>/dev/null && break
        sleep 0.1
        waited=$((waited + 1))
    done
    sleep 0.3
    echo "$pcap"
}

# reject_stop_capture <pcap-path>
# Stop the matching tcpdump and chown the pcap so non-root tshark can
# read it. Returns the pcap path on stdout.
reject_stop_capture() {
    local pcap="${1:?usage: reject_stop_capture <pcap-path>}"

    # Drain the kernel capture ring BEFORE signalling tcpdump. On SIGTERM
    # tcpdump flushes only the frames its userspace read loop has already
    # pulled off the AF_PACKET ring — it does NOT drain entries still queued
    # in the ring. On virtual NICs (vmxnet3) that userspace read lags the
    # kernel by a beat, so a forged reply that lands microseconds after the
    # trigger can still be sitting unread in the ring when the caller stops
    # the capture, yielding an empty pcap (false negative). This settle lets
    # tcpdump's read loop catch up so the reply is committed to the file.
    sleep "${REJECT_CAPTURE_DRAIN_SECS:-2}"

    sudo -n pkill -f "tcpdump.*-w ${pcap}" 2>/dev/null || true
    sleep 1
    sudo -n chown "$(id -u):$(id -g)" "$pcap" 2>/dev/null || true
    rm -f "${pcap}.pid" "${pcap}.ready" 2>/dev/null || true
    echo "$pcap"
}

# ── Pcap parsing ──────────────────────────────────────────────────────

# reject_count_rst <pcap> [src_ip]
# Count packets where tcp.flags.reset == 1 (optionally filtered by source).
reject_count_rst() {
    local pcap="${1:?usage: reject_count_rst <pcap> [src_ip]}"
    local src="${2:-}"
    [ -s "$pcap" ] || { echo 0; return 0; }

    local filter="tcp.flags.reset == 1"
    [ -n "$src" ] && filter="${filter} and ip.src == ${src}"

    tshark -r "$pcap" -Y "$filter" 2>/dev/null | wc -l
}

# reject_count_icmp_unreach <pcap> [src_ip]
# Count ICMP Destination-Port-Unreachable packets (type 3 code 3),
# optionally filtered by source address.
reject_count_icmp_unreach() {
    local pcap="${1:?usage: reject_count_icmp_unreach <pcap> [src_ip]}"
    local src="${2:-}"
    [ -s "$pcap" ] || { echo 0; return 0; }

    local filter="icmp.type == 3 and icmp.code == 3"
    [ -n "$src" ] && filter="${filter} and ip.src == ${src}"

    tshark -r "$pcap" -Y "$filter" 2>/dev/null | wc -l
}

# reject_assert_checksums_valid <pcap>
# Walk every packet through tshark -V and assert no "[incorrect" or
# "checksum incorrect" string appears. Allows pcaps where the kernel
# offloaded checksums on egress: only flags failures for INBOUND frames.
reject_assert_checksums_valid() {
    local pcap="${1:?usage: reject_assert_checksums_valid <pcap>}"
    [ -s "$pcap" ] || return 0

    if tshark -r "$pcap" -V 2>/dev/null | grep -E "checksum.*incorrect|checksum: 0x[0-9a-f]+ \[incorrect" >/dev/null; then
        echo "reject_assert_checksums_valid: pcap ${pcap} contains a packet with an invalid checksum" >&2
        tshark -r "$pcap" -V 2>/dev/null \
            | grep -E "checksum.*incorrect|checksum: 0x[0-9a-f]+ \[incorrect" \
            | head -3 >&2
        return 1
    fi
    return 0
}

# reject_first_rst_swapped <pcap> <orig_src> <orig_dst> <orig_dport>
# Assert the first RST in pcap has ip.src == orig_dst, ip.dst == orig_src,
# tcp.srcport == orig_dport. Returns 0 if any RST matches, 1 otherwise.
reject_first_rst_swapped() {
    local pcap="${1:?usage: reject_first_rst_swapped <pcap> <orig_src> <orig_dst> <orig_dport>}"
    local orig_src="${2:?missing orig_src}"
    local orig_dst="${3:?missing orig_dst}"
    local orig_dport="${4:?missing orig_dport}"

    [ -s "$pcap" ] || return 1
    local filter="tcp.flags.reset == 1 and ip.src == ${orig_dst} and ip.dst == ${orig_src} and tcp.srcport == ${orig_dport}"
    local match
    match="$(tshark -r "$pcap" -Y "$filter" 2>/dev/null | head -1)"
    [ -n "$match" ]
}

# ── Triggers ──────────────────────────────────────────────────────────

# reject_tcp_connect_refused <host> <port>
# Returns 0 iff the TCP connect failed with ECONNREFUSED (host returned
# RST), 1 if it timed out or succeeded.
reject_tcp_connect_refused() {
    local host="${1:?usage: reject_tcp_connect_refused <host> <port>}"
    local port="${2:?missing port}"

    # ncat -w 3 returns:
    #   exit 1 + stderr "Connection refused" → reject succeeded
    #   exit 1 + stderr "timed out"          → silent drop (NOT what we want)
    #   exit 0                               → port open (not under test)
    local err
    err="$(ncat -w 3 "$host" "$port" </dev/null 2>&1)"
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "reject_tcp_connect_refused: unexpected success connecting to ${host}:${port}" >&2
        return 1
    fi
    if echo "$err" | grep -qiE "refused|reset"; then
        return 0
    fi
    echo "reject_tcp_connect_refused: ncat to ${host}:${port} did not return refused/reset: ${err}" >&2
    return 1
}
