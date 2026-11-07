#!/usr/bin/env bats
# 107-identity-across-hosts.bats - a connection between two machines, read
# on the agent's machine with the process that opened it, and with nothing
# named on the far end it was not told about.
#
# The suite asserts:
#
#   * A TCP connection a program on the agent's host opens to the other
#     machine is listed by the agent with that program's pid and executable,
#     and the other machine receives it from the agent's address: the name
#     is this end's, the bytes crossed the wire.
#   * A UDP datagram the same program sends to the other machine is named
#     the same way, read at sendmsg rather than at connect.
#   * Neither flow carries a peer: no list of the other machines' addresses
#     was handed to this agent, so the address at the far end stays an
#     address, and is never given a name inferred from anything else.
#
# What crosses the wire here is the address; the name of the process at
# the far end only reaches this node through a list another agent
# publishes and a console hands on, and the routes that publish and take
# that list are the enterprise agent's, so the two-end reading is asserted
# beside them and not on this lane.
#
# Two machines: bats runs on the attacker VM, the agent on the agent VM.
#
# Requires: root, jq, python3, ssh to the agent VM (the 2VM lane).

load '../lib/helpers'
load '../lib/ebpf_helpers'

TCP_PORT=47107
UDP_PORT=47108
# Same path on the agent VM, outside /tmp so the lane's rewrite of the
# fixture's data paths leaves it alone.
REMOTE_DIR="/var/tmp/ebpfsentinel-identity"

setup_file() {
    require_root
    require_tool jq
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 107 needs a second machine at the far end (2VM lane only)"
    fi
    _agent_ssh true || env_skip "cannot SSH to the agent VM"

    export ATTACKER_IP="${ATTACKER_VM_IP:-192.168.56.20}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-identity-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    _stop_far_end
    _stop_caller

    # The caller is a copy of python3 under a name of its own, so the
    # executable the agent reads back can only be this program's.
    _agent_ssh_sudo bash -c "'rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR} && \
        cp \"\$(readlink -f \"\$(command -v python3)\")\" ${REMOTE_DIR}/id-caller && \
        chmod 0755 ${REMOTE_DIR}/id-caller'" || {
        echo "could not stage the caller on the agent VM" >&2
        return 1
    }
    _write_caller >"${DATA_DIR}/caller.py"
    _agent_scp "${DATA_DIR}/caller.py" "${REMOTE_DIR}/caller.py" || return 1

    # The kernel's conntrack follows a host's own connection once something
    # hooks it; a stateful rule that accepts everything is that something.
    _agent_ssh_sudo nft delete table inet ebpfsentinel_suite107 2>/dev/null || true
    _agent_ssh_sudo nft add table inet ebpfsentinel_suite107
    _agent_ssh_sudo nft "'add chain inet ebpfsentinel_suite107 out { type filter hook output priority 0; policy accept; }'"
    _agent_ssh_sudo nft add rule inet ebpfsentinel_suite107 out ct state new counter accept

    _start_far_end || { echo "the far end did not start listening" >&2; return 1; }

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-identity-across-hosts.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program cgroup-attribution 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the socket hooks never reported themselves attached" >&2; return 1; }
    }

    # The program starts after the hooks, so its sockets are recorded.
    _agent_ssh_sudo "setsid nohup env PYTHONHOME=/usr ${REMOTE_DIR}/id-caller ${REMOTE_DIR}/caller.py \
        ${ATTACKER_IP} ${TCP_PORT} ${UDP_PORT} ${REMOTE_DIR}/caller.pid \
        >${REMOTE_DIR}/caller.log 2>&1 </dev/null &" || return 1
    local attempt=0
    while [ "${attempt}" -lt 40 ]; do
        CALLER_PID="$(_agent_ssh cat "${REMOTE_DIR}/caller.pid" 2>/dev/null)" || CALLER_PID=""
        [ -n "${CALLER_PID}" ] && break
        sleep 0.25
        attempt=$((attempt + 1))
    done
    [ -n "${CALLER_PID}" ] || {
        _agent_ssh cat "${REMOTE_DIR}/caller.log" >&2 || true
        echo "the caller did not start on the agent VM" >&2
        return 1
    }
    export CALLER_PID
}

teardown_file() {
    _stop_caller
    stop_ebpf_agent 2>/dev/null || true
    _stop_far_end
    _agent_ssh_sudo nft delete table inet ebpfsentinel_suite107 2>/dev/null || true
    _agent_ssh_sudo rm -rf "${REMOTE_DIR}" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-identity-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _write_caller - the program on the agent's host: one TCP connection to
# the far end, held open, and a datagram to it once a second.
_write_caller() {
    cat <<'PY'
import os, socket, sys, time
host, tcp_port, udp_port, pidfile = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
tcp = socket.create_connection((host, tcp_port), timeout=10)
tcp.sendall(b"hello from the agent host\n")
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(pidfile + ".tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename(pidfile + ".tmp", pidfile)
for _ in range(120):
    udp.sendto(b"datagram from the agent host\n", (host, udp_port))
    time.sleep(1)
PY
}

# _start_far_end - a TCP and a UDP listener on this machine, each writing
# down the address it was reached from.
_start_far_end() {
    python3 - "${ATTACKER_IP}" "${TCP_PORT}" "${UDP_PORT}" "${DATA_DIR}" >/dev/null 2>&1 3>&- <<'PY' &
import socket, sys, threading
host, tcp_port, udp_port, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, tcp_port)); s.listen(4)
    held = []
    while True:
        c, a = s.accept(); held.append(c)
        open(f"{out}/tcp-from", "w").write(a[0])
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((host, udp_port))
    while True:
        _, a = s.recvfrom(2048)
        open(f"{out}/udp-from", "w").write(a[0])
threading.Thread(target=udp, daemon=True).start()
tcp()
PY
    echo $! >"${DATA_DIR}/far-end.pid"
    local attempt=0
    while [ "${attempt}" -lt 40 ]; do
        ss -ltn | grep -q "${ATTACKER_IP}:${TCP_PORT} " && return 0
        sleep 0.25
        attempt=$((attempt + 1))
    done
    return 1
}

_stop_far_end() {
    [ -f "${DATA_DIR:-/nonexistent}/far-end.pid" ] &&
        kill "$(cat "${DATA_DIR}/far-end.pid")" 2>/dev/null || true
    pkill -f "python3 - ${ATTACKER_IP:-192.168.56.20} ${TCP_PORT}" 2>/dev/null || true
}

_stop_caller() {
    _agent_ssh_sudo pkill -f "${REMOTE_DIR}/id-caller" 2>/dev/null || true
}

# _flow <protocol number> <port> - the agent's row for the caller's flow to
# the far end, once it carries a workload.
_flow() {
    local proto="$1" port="$2" attempt=0 row
    while [ "${attempt}" -lt 20 ]; do
        row="$(api_get '/api/v1/conntrack/connections?limit=10000' 2>/dev/null |
            jq -c --arg dst "${ATTACKER_IP}" --argjson port "${port}" --argjson proto "${proto}" \
                '[.[] | select(.dst_ip == $dst and .dst_port == $port and .protocol == $proto and .workload != null)] | first // empty' \
                2>/dev/null)" || row=""
        [ -n "${row}" ] && { echo "${row}"; return 0; }
        sleep 1
        attempt=$((attempt + 1))
    done
    api_get '/api/v1/conntrack/connections?limit=10000' 2>/dev/null |
        jq -c --arg dst "${ATTACKER_IP}" '[.[] | select(.dst_ip == $dst)]' >&2 || true
    return 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a TCP connection to the other machine is named by the process on this end" {
    local row
    row="$(_flow 6 "${TCP_PORT}")"
    [ -n "${row}" ]
    jq -e --arg src "${AGENT_VM_IP}" '.src_ip == $src' <<<"${row}"
    jq -e --argjson pid "${CALLER_PID}" '.workload.pid == $pid' <<<"${row}"
    jq -e --arg exe "${REMOTE_DIR}/id-caller" '.workload.exe == $exe' <<<"${row}"

    # The far end was reached from the agent's address: the flow crossed.
    [ "$(cat "${DATA_DIR}/tcp-from")" = "${AGENT_VM_IP}" ]
}

@test "a UDP datagram to the other machine is named by the same process" {
    local row
    row="$(_flow 17 "${UDP_PORT}")"
    [ -n "${row}" ]
    jq -e --argjson pid "${CALLER_PID}" '.workload.pid == $pid' <<<"${row}"
    jq -e --arg exe "${REMOTE_DIR}/id-caller" '.workload.exe == $exe' <<<"${row}"
    [ "$(cat "${DATA_DIR}/udp-from")" = "${AGENT_VM_IP}" ]
}

@test "the far end carries no name the agent was not handed" {
    local rows
    rows="$(api_get '/api/v1/conntrack/connections?limit=10000' |
        jq -c --arg dst "${ATTACKER_IP}" '[.[] | select(.dst_ip == $dst and .workload != null)]')"
    [ "$(jq 'length' <<<"${rows}")" -ge 2 ]
    jq -e 'all(.[]; .workload.peer == null)' <<<"${rows}"
}
