#!/usr/bin/env bats
# 145-alias-refresh-interval.bats - An alias refreshes on its own interval
# Requires: root, kernel >= 6.18, python3, ncat
#
# A url_table alias names the sources a deny rule drops, read from a list the
# suite serves on the host. GeoIP is off, which used to leave such an alias
# loaded once at start and never again. Each test rewrites the served list and
# reads the change off the datapath: the namespace reaches the host when it is
# not listed and is dropped once it is, within a few refresh intervals.

load '../lib/helpers'
load '../lib/ebpf_helpers'

LIST_PORT=9975
PROBE_PORT=9976
# The alias refreshes every 3 seconds; three intervals and change.
REFRESH_WAIT=12

setup_file() {
    require_root
    require_kernel 6 12
    require_tool python3
    require_tool ncat
    if [ "${EBPF_2VM_MODE:-false}" = "true" ] || [ "${EBPF_3VM_MODE:-false}" = "true" ]; then
        env_skip "suite 145 serves the list beside the agent (local lane only)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-alias-refresh-$$"
    export LIST_DIR="${DATA_DIR}/served"
    mkdir -p "$LIST_DIR"
    # Listed at start: an address nobody uses, so the namespace passes.
    serve_list "192.0.2.99"
    # Started without a subshell, so the pid written is the server's own and
    # killing it leaves nothing holding the descriptors bats waits on.
    timeout 600 python3 -m http.server "$LIST_PORT" --bind 127.0.0.1 \
        --directory "$LIST_DIR" >/dev/null 2>&1 3>&- &
    echo $! >"${DATA_DIR}/server.pid"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-alias-refresh.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        teardown_file
        return 1
    }

    timeout 600 ncat -lk "$EBPF_HOST_IP" "$PROBE_PORT" >/dev/null 2>&1 3>&- &
    echo $! >>"${DATA_DIR}/server.pid"
    sleep 1
}

teardown_file() {
    if [ -f "${DATA_DIR:-}/server.pid" ]; then
        xargs -r kill <"${DATA_DIR}/server.pid" 2>/dev/null || true
    fi
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-alias-refresh-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

# serve_list <address>... - what the list URL answers from now on.
serve_list() {
    printf '%s\n' "# written by suite 145" "$@" >"${LIST_DIR}/denylist.txt.tmp"
    mv "${LIST_DIR}/denylist.txt.tmp" "${LIST_DIR}/denylist.txt"
}

# reaches - true when a connection from the namespace to the host completes.
reaches() {
    ip netns exec "$EBPF_TEST_NS" ncat -z -w 2 "$EBPF_HOST_IP" "$PROBE_PORT" 2>/dev/null
}

# wait_until <expected: reach|dropped> - polls until the datapath agrees.
wait_until() {
    local want="${1:?usage: wait_until reach|dropped}"
    local i=0
    while [ "$i" -lt "$REFRESH_WAIT" ]; do
        if reaches; then
            [ "$want" = "reach" ] && return 0
        else
            [ "$want" = "dropped" ] && return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "still not ${want} after ${REFRESH_WAIT}s. Log tail:" >&2
    grep -i "alias" "$AGENT_LOG_FILE" | tail -10 >&2
    return 1
}

# ── Tests ──────────────────────────────────────────────────────────

@test "a source the served list does not name reaches the host" {
    require_root
    wait_until reach
}

@test "a source added to the served list is dropped without a restart or GeoIP" {
    require_root
    serve_list "192.0.2.99" "$EBPF_NS_IP"
    wait_until dropped
    grep -q "alias refreshed" "$AGENT_LOG_FILE"
}

@test "a source taken off the served list reaches the host again" {
    require_root
    serve_list "$EBPF_NS_IP"
    wait_until dropped
    serve_list "192.0.2.99"
    wait_until reach
}

@test "a list that cannot be read keeps the members last loaded" {
    require_root
    serve_list "$EBPF_NS_IP"
    wait_until dropped
    rm -f "${LIST_DIR}/denylist.txt"
    sleep "$REFRESH_WAIT"
    run reaches
    [ "$status" -ne 0 ]
}
