#!/usr/bin/env bash
# syncookie_helpers.bash — Drive the xdp-ratelimit-syncookie tail-call
# program. Two attackers exercise the program from opposite sides:
#   - Real socket (state-keeping) — completes the 3-way handshake using
#     the cookie returned by the agent's SYN-ACK.
#   - Spoofed source (scapy) — never sends the cookie ACK because the
#     source is unreachable; cookie validation cannot complete.
#
# Public entrypoints:
#   require_syncookie_tools
#   syncookie_start_target <port>          — start ncat listener on agent
#   syncookie_stop_target <port>
#   syncookie_real_flood <port> <count>    — SYN flood via hping3 (real src)
#   syncookie_real_connect <port>          — single completed ncat connect
#   syncookie_spoofed_flood <port> <count> — scapy SYN flood w/ rand src
#   nstat_read <key>                       — read one nstat -az counter
#                                             from the agent VM

SYNCOOKIE_TARGET_PORT="${SYNCOOKIE_TARGET_PORT:-11443}"
SYNCOOKIE_TARGET_PID_FILE="${SYNCOOKIE_TARGET_PID_FILE:-/tmp/ebpfsentinel-syncookie-target.pid}"

# ── Guards ────────────────────────────────────────────────────────────

require_syncookie_tools() {
    local tool
    for tool in ncat python3 hping3 nstat; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            skip "${tool} not available on attacker VM"
        fi
    done
    if ! "$EBPF_SCAPY_PY" -c "import scapy.all" >/dev/null 2>&1; then
        skip "scapy not installed on attacker VM (run the attacker provisioner)"
    fi
}

# ── Agent-side TCP listener ───────────────────────────────────────────

# syncookie_start_target <port>
# Start a background ncat listener on the agent VM. Used as the target
# of the SYN flood so legitimate sockets can complete the handshake.
syncookie_start_target() {
    local port="${1:-$SYNCOOKIE_TARGET_PORT}"

    # setsid detaches ncat into its own session so the SSH channel closes and
    # the call returns instead of blocking on the listener's inherited fds.
    # The listener's existence is confirmed by the ss poll below, not by this
    # command's exit status (a backgrounded remote start can report success
    # before the socket is bound, or the transport can return non-zero while
    # the listener is in fact up).
    _agent_ssh_sudo "setsid sh -c 'ncat -lk -p ${port} >/dev/null 2>&1 </dev/null & echo \$! > ${SYNCOOKIE_TARGET_PID_FILE}'" \
        >/dev/null 2>&1 || true

    # Wait up to 5 s for the socket to be listening.
    local i
    for i in 1 2 3 4 5; do
        if _agent_ssh "ss -ltn 'sport = :${port}'" 2>/dev/null \
            | grep -q ":${port}"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# syncookie_stop_target [port]
# Kill the ncat listener started by syncookie_start_target.
syncookie_stop_target() {
    local port="${1:-$SYNCOOKIE_TARGET_PORT}"
    _agent_ssh_sudo sh -c "[ -f ${SYNCOOKIE_TARGET_PID_FILE} ] && kill \$(cat ${SYNCOOKIE_TARGET_PID_FILE}) 2>/dev/null; rm -f ${SYNCOOKIE_TARGET_PID_FILE}; pkill -f 'ncat -lk -p ${port}' 2>/dev/null || true" \
        >/dev/null 2>&1 || true
}

# ── Real (state-keeping) attacker ─────────────────────────────────────

# syncookie_real_flood <port> <count>
# hping3 SYN flood from the attacker's real source IP. The legitimate
# attacker keeps state, so its kernel will send the cookie ACK back.
syncookie_real_flood() {
    local port="${1:-$SYNCOOKIE_TARGET_PORT}"
    local count="${2:-2000}"
    local target="${AGENT_VM_IP:-${AGENT_HOST}}"

    sudo -n hping3 -S -p "$port" -c "$count" -i u500 "$target" \
        >/dev/null 2>&1 || true
}

# syncookie_real_connect <port>
# A single ncat TCP connect from the real source — must complete the
# 3-way handshake to prove the cookie path round-trips correctly.
syncookie_real_connect() {
    local port="${1:-$SYNCOOKIE_TARGET_PORT}"
    local target="${AGENT_VM_IP:-${AGENT_HOST}}"

    : | ncat -w 5 "$target" "$port" >/dev/null 2>&1
}

# ── Spoofed-source (no-state) attacker ────────────────────────────────

# syncookie_spoofed_flood <port> <count>
# Scapy SYN flood with randomised spoofed source IPs in the 198.18.0.0/15
# benchmark range (RFC2544). These hosts do NOT exist, so the legitimate
# 3-way handshake completion path can never run for them — kernel
# TcpExtSyncookiesRecv must stay flat for this traffic class.
syncookie_spoofed_flood() {
    local port="${1:-$SYNCOOKIE_TARGET_PORT}"
    local count="${2:-200}"
    local target="${AGENT_VM_IP:-${AGENT_HOST}}"

    sudo -n "$EBPF_SCAPY_PY" - <<PY 2>/dev/null || true
from random import randint
from scapy.all import IP, TCP, send
target = "${target}"
port = ${port}
count = ${count}
batch = []
for _ in range(count):
    src = "198.18.{}.{}".format(randint(0, 255), randint(1, 254))
    batch.append(IP(src=src, dst=target) / TCP(
        sport=randint(1024, 65535),
        dport=port,
        flags="S",
        seq=randint(1, 0xFFFFFFFF),
    ))
send(batch, inter=0.001, verbose=False)
PY
}

# ── nstat reader (agent VM) ───────────────────────────────────────────

# nstat_read <key>
# Read one -az counter on the agent VM. -z resets only the in-memory
# accumulator; we want the cumulative value, so we use `nstat -anz` then
# parse the row. Returns 0 if the counter is absent (typical when no
# cookies have been sent yet on a fresh kernel boot).
nstat_read() {
    local key="${1:?usage: nstat_read <key>}"
    local val
    val="$(_agent_ssh "nstat -az ${key} 2>/dev/null | awk 'NR==2 {print \$2}'" 2>/dev/null)"
    [ -z "$val" ] && val=0
    echo "$val"
}
