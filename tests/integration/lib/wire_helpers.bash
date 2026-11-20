#!/usr/bin/env bash
# wire_helpers.bash - listeners on the agent side of the wire, for suites that
# need a TCP conversation to complete before the behaviour they assert exists.
#
# EBPF_HOST_IP is the address the agent listens on: an address of this machine
# on the local lane, the agent VM on the two- and three-machine lanes. A client
# driven by send_tcp_from_ns reaches that address from the attacking side. With
# no listener there, the handshake is refused, no payload segment is ever
# written, and a parser, a conntrack entry or a deny counter that depends on the
# payload has nothing to see: the test then measures the absence of a listener.
#
# Load after ebpf_helpers (needs EBPF_HOST_IP, EBPF_TEST_NS and, on the remote
# lanes, _agent_ssh_sudo / _agent_scp from vm_helpers).

_wire_remote_lane() {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || [ "${EBPF_3VM_MODE:-false}" = "true" ]
}

# wire_client <command...> - run a client tool on the attacking side: the test
# netns locally, this whole machine on the remote lanes.
wire_client() {
    if _wire_remote_lane; then
        "$@"
    else
        ip netns exec "${EBPF_TEST_NS}" "$@"
    fi
}

# wire_start_listener <port> [responder-script] - one TCP listener on
# EBPF_HOST_IP, recv-only or driven by the responder script. Returns non-zero
# when the port is not accepting connections after two seconds, so a test
# never sends into a listener that is not there.
wire_start_listener() {
    local port="${1:?usage: wire_start_listener <port> [responder-script]}"
    local responder="${2:-}"
    if _wire_remote_lane; then
        local remote_cmd
        if [ -n "${responder}" ]; then
            local remote_resp="/tmp/ebpfsentinel-wire-responder-${port}.sh"
            _agent_scp "${responder}" "${remote_resp}" >/dev/null 2>&1 || return 1
            _agent_ssh_sudo chmod +x "${remote_resp}" >/dev/null 2>&1 || return 1
            remote_cmd="ncat -l ${EBPF_HOST_IP} ${port} -k --exec ${remote_resp}"
        else
            remote_cmd="ncat -l ${EBPF_HOST_IP} ${port} -k --recv-only"
        fi
        _agent_ssh_sudo "setsid nohup ${remote_cmd} >/dev/null 2>&1 </dev/null &" \
            >/dev/null 2>&1 || return 1
        _WIRE_REMOTE_PORTS="${_WIRE_REMOTE_PORTS:-} ${port}"
    else
        if [ -n "${responder}" ]; then
            ncat -l "${EBPF_HOST_IP}" "${port}" -k --exec "${responder}" >/dev/null 2>&1 &
        else
            ncat -l "${EBPF_HOST_IP}" "${port}" -k --recv-only >/dev/null 2>&1 &
        fi
        _WIRE_LISTENER_PIDS="${_WIRE_LISTENER_PIDS:-} $!"
    fi

    local attempt=0
    while [ "${attempt}" -lt 20 ]; do
        if _wire_listening "${port}"; then
            return 0
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "no listener accepting on ${EBPF_HOST_IP}:${port}" >&2
    return 1
}

# _wire_listening <port> - true once a socket is listening on the port, on
# whichever side of the wire the listener runs.
_wire_listening() {
    local port="$1"
    if _wire_remote_lane; then
        _agent_ssh "ss -tlnH 'sport = :${port}'" 2>/dev/null | grep -q .
    else
        ss -tlnH "sport = :${port}" 2>/dev/null | grep -q .
    fi
}

# wire_stop_listeners - stop every listener wire_start_listener started.
wire_stop_listeners() {
    local p port
    # shellcheck disable=SC2086
    for p in ${_WIRE_LISTENER_PIDS:-}; do
        kill "${p}" 2>/dev/null || true
        wait "${p}" 2>/dev/null || true
    done
    _WIRE_LISTENER_PIDS=""
    # shellcheck disable=SC2086
    for port in ${_WIRE_REMOTE_PORTS:-}; do
        # The trailing bracket expression matches the space after the port in
        # the listener's command line and nothing in this pkill's own, which
        # carries the pattern literally.
        _agent_ssh_sudo "pkill -f 'ncat -l ${EBPF_HOST_IP} ${port}[ ]'" >/dev/null 2>&1 || true
    done
    _WIRE_REMOTE_PORTS=""
}

# l7_counter <action-or-protocol> - the L7 decision counter the agent bumps
# once per inspected payload: `deny`, `allow`, `log`, `reject` for a rule
# match, the protocol label (`http`, `tls`, ...) when no rule matched. Prints
# 0 while the counter has no line yet.
l7_counter() {
    local value attempt
    # A series not exported yet is a zero; an endpoint that did not answer is
    # not, and reading it as one makes a counter go backwards.
    for attempt in 1 2 3; do
        if value="$(get_metrics_value ebpfsentinel_packets_total \
            "{interface=\"l7\",action=\"$1\"}" 2>/dev/null)"; then
            echo "${value:-0}"
            return 0
        fi
        sleep 1
    done
    echo "the metrics endpoint did not answer for the l7 ${1} counter" >&2
    return 1
}

# wait_l7_counter_above <label> <before> [max_seconds] - wait until the L7
# counter passes <before>; prints the last value read. The counter is written
# by the userspace pipeline as each payload is judged, so a few seconds cover
# the ring buffer drain.
wait_l7_counter_above() {
    local label="$1" before="$2" max="${3:-15}" i value=0
    for i in $(seq 1 "${max}"); do
        value="$(l7_counter "${label}")" || value="${before}"
        [ "${value%.*}" -gt "${before%.*}" ] && break
        sleep 1
    done
    echo "${value}"
}
