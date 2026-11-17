#!/usr/bin/env bats
# 143-interface-groups.bats - a firewall rule scoped to a group of interfaces
# applies on the group's members and nowhere else, and `!group` is its exact
# complement.
#
# The fixture puts the test link in `inside` and a second watched link, a
# dummy, in `outside`, then denies one port per scope. A connection out of the
# namespace arrives on the watched link, so it must be refused where the
# scope is `inside`, `!outside` or the link named alone, and pass where it is
# `outside` or `!inside`. A rule that ignored its scope would refuse all five
# ports; one that never matched a group would refuse none.
#
# Requires: root, kernel >= 6.12, ncat, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-iface-groups-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns
    ip link add ebpfgrp0 type dummy
    ip link set ebpfgrp0 up

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-interface-groups.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs not loaded (degraded mode)" >&2
        return 1
    }

    local port
    for port in 7301 7302 7303 7304 7305; do
        timeout 120 ncat -lk "$EBPF_HOST_IP" "$port" -c 'printf "GROUP-ANSWER\n"' >/dev/null 2>&1 &
    done
    sleep 0.5
}

teardown_file() {
    pkill -f "ncat -lk ${EBPF_HOST_IP} 730" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    ip link del ebpfgrp0 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-iface-groups-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _answered <port> - the namespace reached the host listener and read its answer.
_answered() {
    ip netns exec "$EBPF_TEST_NS" timeout 3 ncat --recv-only -w 2 "$EBPF_HOST_IP" "$1" </dev/null 2>/dev/null \
        | grep -q GROUP-ANSWER
}

@test "the agent loaded both groups and the five scoped rules" {
    api_get /api/v1/firewall/rules | jq -e '
        [.[] | select(.id | startswith("fw-group-") or . == "fw-iface-by-name")] | length == 5
    ' >/dev/null
}

@test "a rule scoped to the group holding the link refuses on it" {
    ! _answered 7301
}

@test "a rule scoped to a group the link is not in lets it through" {
    _answered 7302
}

@test "the complement of a group the link is not in refuses on it" {
    ! _answered 7303
}

@test "the complement of the group holding the link lets it through" {
    _answered 7304
}

@test "a rule naming the link alone refuses on it" {
    ! _answered 7305
}
