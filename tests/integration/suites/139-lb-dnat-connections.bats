#!/usr/bin/env bats
# 139-lb-dnat-connections.bats - L4 load balancer in DNAT mode, 3-VM.
#
# Three backends listen on the backend VM (ports 9001-9003), each answering
# with its own port. The client opens TCP connections to the VIP; the agent
# rewrites each to a backend, and the backend's reply comes back through the
# agent, which puts the VIP back as its source. Asserts:
#
#   * every connection completes across three round-robin backends: a
#     connection whose packets were spread over several backends, or whose
#     reply kept the backend's address, would be reset or time out
#   * a 3:1:1 weighted service spreads new connections in that proportion
#   * least_conn sends new connections away from backends holding open ones
#   * no rewritten packet reaches the backend with a checksum it drops
#
# Requires: 3-VM mode (EBPF_3VM_MODE=true), kernel >= 6.18 on the agent,
# python3 on the backend VM, curl and ncat on the client VM.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/lb_helpers'

LB_BACKEND_ADDR="${BACKEND_VM_IP:-192.168.57.30}"
LB_PORTS=(9001 9002 9003)

setup_file() {
    skip_if_not_3vm
    require_kernel 6 12
    require_tool curl
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lbdnat-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-lb-dnat.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    route_via_agent backend >/dev/null 2>&1 || true

    # A native XDP attach resets some NICs: measure once the node forwards
    # between its two sides again.
    local i
    for i in $(seq 1 20); do
        _backend_ssh "ping -c1 -W1 ${ATTACKER_VM_IP:-192.168.56.20}" >/dev/null 2>&1 && break
        sleep 1
    done

    local port
    for port in "${LB_PORTS[@]}"; do
        _backend_ssh_sudo systemctl stop "lb-dnat-${port}" >/dev/null 2>&1 || true
        _backend_ssh "mkdir -p /tmp/lb-dnat-${port} && echo ${port} > /tmp/lb-dnat-${port}/index.html"
        _backend_ssh_sudo systemd-run --unit "lb-dnat-${port}" \
            python3 -m http.server "$port" --bind 0.0.0.0 --directory "/tmp/lb-dnat-${port}" \
            >/dev/null || return 1
    done
    for port in "${LB_PORTS[@]}"; do
        for i in $(seq 1 10); do
            _backend_ssh "nc -z -w1 127.0.0.1 ${port}" 2>/dev/null && break
            sleep 1
        done
    done
}

teardown_file() {
    local svc port
    for svc in dnat-rr dnat-weighted dnat-least; do
        delete_lb_service "$svc" >/dev/null 2>&1 || true
    done
    for port in "${LB_PORTS[@]}"; do
        _backend_ssh_sudo systemctl stop "lb-dnat-${port}" >/dev/null 2>&1 || true
        _backend_ssh "rm -rf /tmp/lb-dnat-${port}" >/dev/null 2>&1 || true
    done
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lbdnat-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _register <svc> <port> <algo> <w1> <w2> <w3> - the three backends, weighted.
_register() {
    local svc="$1" port="$2" algo="$3"
    local rc
    rc="$(register_backends "$svc" "$port" "$algo" dnat \
        "b9001:${LB_BACKEND_ADDR}:9001:$4" \
        "b9002:${LB_BACKEND_ADDR}:9002:$5" \
        "b9003:${LB_BACKEND_ADDR}:9003:$6")"
    [[ "$rc" =~ ^(200|201)$ ]] || {
        echo "register_backends ${svc} returned ${rc}" >&2
        return 1
    }
    sleep 2
}

# _connect <port> <n> - open n connections to the VIP one after the other,
# print the backend port each answered from, "fail" for one that did not
# complete.
_connect() {
    local port="$1" n="$2" i body
    for i in $(seq 1 "$n"); do
        body="$(curl -s --max-time 3 "http://${LB_VIP_ADDR}:${port}/" 2>/dev/null)" || body=""
        echo "${body:-fail}"
    done
}

# _count <file> <value>
_count() {
    grep -cx "$2" "$1" || true
}

# _csum_errors - packets the backend's kernel dropped on a bad checksum.
_csum_errors() {
    _backend_ssh "nstat -az IpExtInCsumErrors" | awk '/IpExtInCsumErrors/ {print $2}'
}

@test "every connection through three round-robin backends completes" {
    _register dnat-rr 8081 round_robin 1 1 1

    _connect 8081 30 > "${DATA_DIR}/rr.txt"

    local failed
    failed="$(_count "${DATA_DIR}/rr.txt" fail)"
    [ "$failed" -eq 0 ] || {
        echo "${failed} of 30 connections did not complete" >&2
        sort "${DATA_DIR}/rr.txt" | uniq -c >&2
        return 1
    }
    local port
    for port in "${LB_PORTS[@]}"; do
        [ "$(_count "${DATA_DIR}/rr.txt" "$port")" -ge 1 ] || {
            echo "backend ${port} answered none of 30 connections" >&2
            sort "${DATA_DIR}/rr.txt" | uniq -c >&2
            return 1
        }
    done
}

@test "a 3:1:1 weighted service spreads connections in that proportion" {
    _register dnat-weighted 8082 weighted 3 1 1

    local csum_before
    csum_before="$(_csum_errors)"
    _connect 8082 100 > "${DATA_DIR}/weighted.txt"

    local failed heavy light2 light3
    failed="$(_count "${DATA_DIR}/weighted.txt" fail)"
    heavy="$(_count "${DATA_DIR}/weighted.txt" 9001)"
    light2="$(_count "${DATA_DIR}/weighted.txt" 9002)"
    light3="$(_count "${DATA_DIR}/weighted.txt" 9003)"
    echo "# weighted spread: 9001=${heavy} 9002=${light2} 9003=${light3} fail=${failed}" >&3

    [ "$failed" -eq 0 ] || { echo "${failed} of 100 connections did not complete" >&2; return 1; }
    # A wrong incremental checksum loses about one packet in a few hundred:
    # the backend's own count says so where a timeout would only be likely.
    [ "$(_csum_errors)" -eq "${csum_before:-0}" ] || {
        echo "the backend dropped rewritten packets on a bad checksum" >&2
        return 1
    }
    # Expected 60/20/20; the bounds sit about four standard deviations out.
    [ "$heavy" -ge 40 ] && [ "$heavy" -le 80 ] || { echo "9001 took ${heavy} of 100, expected about 60" >&2; return 1; }
    [ "$light2" -ge 5 ] && [ "$light2" -le 37 ] || { echo "9002 took ${light2} of 100, expected about 20" >&2; return 1; }
    [ "$light3" -ge 5 ] && [ "$light3" -le 37 ] || { echo "9003 took ${light3} of 100, expected about 20" >&2; return 1; }
}

@test "least_conn sends new connections to the backend holding none" {
    _register dnat-least 8083 least_conn 1 1 1

    # Two idle connections stay open; least_conn puts them on two backends.
    local pids=() i
    for i in 1 2; do
        # Receive only: the backend waits for a request that never comes.
        ncat --recv-only --idle-timeout 60 "$LB_VIP_ADDR" 8083 >/dev/null 2>&1 &
        pids+=($!)
        sleep 1
    done

    # Which backends hold them, read on the backend side.
    local held=() port
    for port in "${LB_PORTS[@]}"; do
        if _backend_ssh "ss -Htn state established '( sport = :${port} )'" | grep -q .; then
            held+=("$port")
        fi
    done

    _connect 8083 10 > "${DATA_DIR}/least.txt"
    kill "${pids[@]}" 2>/dev/null || true

    [ "${#held[@]}" -eq 2 ] || {
        echo "the two held connections sit on: ${held[*]:-none}" >&2
        return 1
    }
    [ "$(_count "${DATA_DIR}/least.txt" fail)" -eq 0 ] || {
        echo "a connection did not complete" >&2
        sort "${DATA_DIR}/least.txt" | uniq -c >&2
        return 1
    }
    for port in "${held[@]}"; do
        [ "$(_count "${DATA_DIR}/least.txt" "$port")" -eq 0 ] || {
            echo "backend ${port} holds an open connection yet took new ones" >&2
            sort "${DATA_DIR}/least.txt" | uniq -c >&2
            return 1
        }
    done
}
