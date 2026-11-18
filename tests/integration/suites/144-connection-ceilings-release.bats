#!/usr/bin/env bats
# 144-connection-ceilings-release.bats - A connection ceiling counts open connections
# Requires: root, kernel >= 6.12, bpftool, ncat, ss
#
# conntrack.max_src_states caps the connections one source holds open, and a
# rule's max_states caps the connections open through that rule. The datapath
# counts a connection when it admits one; the agent gives the room back once
# the kernel conntrack table no longer holds it open. Each test opens up to the
# ceiling, shows the next one refused, closes everything and opens the same
# number again: a ceiling that only ever counted up refuses the second round.

load '../lib/helpers'
load '../lib/ebpf_helpers'

SOURCE_PORT=9973
RULE_PORT=9974
# The agent reconciles every 5 seconds and keeps a connection it admitted for
# 10 seconds whatever the table says, so 20 seconds is past both.
RELEASE_WAIT=20

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat
    require_tool ss

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ceilings-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-connection-ceilings.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }
    # The per-source ceiling is written when tc-conntrack loads, several
    # programs after the firewall the readiness probe answers on.
    wait_for_ebpf_program tc-conntrack 30 || {
        echo "tc-conntrack never reported loaded. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }
    grep -q "connection ceiling reconciler started" "$AGENT_LOG_FILE" || {
        echo "the agent never started giving ceilings back. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }

    # Listeners on the host that keep every connection they accept.
    local port
    for port in "$SOURCE_PORT" "$RULE_PORT"; do
        timeout 600 ncat -lk "$EBPF_HOST_IP" "$port" >/dev/null 2>&1 &
        echo $! >>"${DATA_DIR}/listeners.pid"
    done
    sleep 1
}

teardown_file() {
    close_all
    if [ -f "${DATA_DIR:-}/listeners.pid" ]; then
        xargs -r kill <"${DATA_DIR}/listeners.pid" 2>/dev/null || true
    fi
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ceilings-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    close_all
}

# ── Helpers ────────────────────────────────────────────────────────

# hold_open <port> <count>
# Opens <count> connections from the namespace to <port> and keeps each one
# open until close_all, each client reading from a sleep that never writes.
hold_open() {
    local port="${1:?usage: hold_open <port> <count>}"
    local count="${2:?usage: hold_open <port> <count>}"
    local i=0
    while [ "$i" -lt "$count" ]; do
        ip netns exec "$EBPF_TEST_NS" \
            timeout 120 sh -c "sleep 120 | ncat '$EBPF_HOST_IP' '$port'" \
            >/dev/null 2>&1 &
        echo $! >>"${DATA_DIR}/clients.pid"
        i=$((i + 1))
        # One at a time, so which ones are refused is the order they came in.
        sleep 0.3
    done
    # A refused client keeps retrying its SYN: give the admitted ones time to
    # complete and the refused ones time to be refused more than once.
    sleep 3
}

# established <port> - connections the namespace holds open to <port>.
established() {
    local port="${1:?usage: established <port>}"
    ip netns exec "$EBPF_TEST_NS" \
        ss -tnH state established "( dport = :${port} )" 2>/dev/null | wc -l
}

close_all() {
    if [ -f "${DATA_DIR:-}/clients.pid" ]; then
        xargs -r kill <"${DATA_DIR}/clients.pid" 2>/dev/null || true
        rm -f "${DATA_DIR}/clients.pid"
    fi
    ip netns exec "${EBPF_TEST_NS:-none}" pkill -f "ncat ${EBPF_HOST_IP:-none}" 2>/dev/null || true
}

# ── Per source ─────────────────────────────────────────────────────

@test "a source holds no more connections open than its ceiling" {
    require_root

    hold_open "$SOURCE_PORT" 5
    local open
    open="$(established "$SOURCE_PORT")"
    echo "open=${open}"
    [ "$open" -eq 3 ]
}

@test "a source that closed its connections opens as many again" {
    require_root

    hold_open "$SOURCE_PORT" 3
    [ "$(established "$SOURCE_PORT")" -eq 3 ]
    close_all
    sleep "$RELEASE_WAIT"

    hold_open "$SOURCE_PORT" 3
    local open
    open="$(established "$SOURCE_PORT")"
    echo "open after release=${open}"
    [ "$open" -eq 3 ] || {
        echo "closed connections still count against the source" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

# ── Per rule ───────────────────────────────────────────────────────

@test "a rule admits no more open connections than its max_states" {
    require_root

    sleep "$RELEASE_WAIT"
    hold_open "$RULE_PORT" 3
    local open
    open="$(established "$RULE_PORT")"
    echo "open=${open}"
    [ "$open" -eq 2 ]
}

@test "a rule whose connections closed admits as many again" {
    require_root

    sleep "$RELEASE_WAIT"
    hold_open "$RULE_PORT" 2
    [ "$(established "$RULE_PORT")" -eq 2 ]
    close_all
    sleep "$RELEASE_WAIT"

    hold_open "$RULE_PORT" 2
    local open
    open="$(established "$RULE_PORT")"
    echo "open after release=${open}"
    [ "$open" -eq 2 ] || {
        echo "closed connections still count against the rule" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}
