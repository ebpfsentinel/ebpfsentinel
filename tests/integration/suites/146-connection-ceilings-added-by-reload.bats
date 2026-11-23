#!/usr/bin/env bats
# 146-connection-ceilings-added-by-reload.bats - A ceiling a reload adds counts open connections
# Requires: root, kernel >= 6.18, bpftool, ncat, ss
#
# The agent starts with connection tracking on and no per-source ceiling, so
# at start there is nothing to enforce and nothing to give back. A reload then
# sets conntrack.max_src_states. From that reload on the source holds no more
# connections open than the ceiling, and closing them gives the room back: a
# ceiling enforced by the reload but never released refuses the second round,
# and one the reload never enforced admits every connection.

load '../lib/helpers'
load '../lib/ebpf_helpers'

PORT=9975
CEILING=3
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

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ceilings-reload-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-connection-ceilings-reload.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }
    wait_for_ebpf_program tc-conntrack 30 || {
        echo "tc-conntrack never reported loaded. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }

    # Same listener as the suite on ceilings set at start: ncat reading a
    # FIFO it holds open for writing itself keeps every connection it accepts.
    mkfifo "${DATA_DIR}/listener.fifo"
    timeout 900 ncat -lk "$EBPF_HOST_IP" "$PORT" \
        <>"${DATA_DIR}/listener.fifo" >/dev/null 2>&1 3>&- &
    echo $! >"${DATA_DIR}/listener.pid"
    sleep 1
}

teardown_file() {
    close_all
    if [ -f "${DATA_DIR:-}/listener.pid" ]; then
        xargs -r kill <"${DATA_DIR}/listener.pid" 2>/dev/null || true
    fi
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ceilings-reload-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    close_all
}

# ── Helpers ────────────────────────────────────────────────────────

# hold_open <count> - open <count> connections from the namespace to PORT and
# keep each one open until close_all.
hold_open() {
    local count="${1:?usage: hold_open <count>}"
    local i=0
    while [ "$i" -lt "$count" ]; do
        ip netns exec "$EBPF_TEST_NS" \
            timeout 120 sh -c "sleep 120 | ncat '$EBPF_HOST_IP' '$PORT'" \
            >/dev/null 2>&1 3>&- &
        echo $! >>"${DATA_DIR}/clients.pid"
        i=$((i + 1))
        sleep 0.3
    done
    # A refused client keeps retrying its SYN: give the admitted ones time to
    # complete and the refused ones time to be refused more than once.
    sleep 3
}

# established - connections the namespace holds open to PORT.
established() {
    ip netns exec "$EBPF_TEST_NS" \
        ss -tnH state established "( dport = :${PORT} )" 2>/dev/null | wc -l
}

close_all() {
    if [ -f "${DATA_DIR:-}/clients.pid" ]; then
        xargs -r kill <"${DATA_DIR}/clients.pid" 2>/dev/null || true
        rm -f "${DATA_DIR}/clients.pid"
    fi
    ip netns exec "${EBPF_TEST_NS:-none}" pkill -f "ncat ${EBPF_HOST_IP:-none}" 2>/dev/null || true
}

# reloads_done - how many conntrack reloads the agent has logged.
reloads_done() {
    grep -c "conntrack configuration reloaded" "$AGENT_LOG_FILE" 2>/dev/null || true
}

# ── Before the reload ──────────────────────────────────────────────

@test "the task that gives ceilings back runs before any ceiling is set" {
    require_root

    grep -q "connection ceiling reconciler started" "$AGENT_LOG_FILE" || {
        echo "nothing would give back a ceiling a reload adds. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

@test "with no ceiling a source holds as many connections as it opens" {
    require_root

    hold_open $((CEILING + 2))
    local open
    open="$(established)"
    echo "open=${open}"
    [ "$open" -eq $((CEILING + 2)) ]
}

# ── The reload ─────────────────────────────────────────────────────

@test "a reload sets a per-source ceiling" {
    require_root

    local before
    before="$(reloads_done)"
    sed -i "s/^  max_src_states: 0$/  max_src_states: ${CEILING}/" "$PREPARED_CONFIG"
    grep -q "^  max_src_states: ${CEILING}$" "$PREPARED_CONFIG"

    if type signal_agent &>/dev/null; then
        signal_agent HUP
    else
        kill -HUP "$(cat "$AGENT_PID_FILE")"
    fi

    local i
    for i in $(seq 1 30); do
        [ "$(reloads_done)" -gt "${before:-0}" ] && break
        sleep 1
    done
    [ "$(reloads_done)" -gt "${before:-0}" ] || {
        echo "the agent never reloaded. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    # The firewall's rules and the source ceilings are written in the same
    # reload, after the conntrack line: let it finish.
    sleep 2
}

# ── After the reload ───────────────────────────────────────────────

@test "after the reload a source holds no more connections open than the ceiling" {
    require_root

    hold_open $((CEILING + 2))
    local open
    open="$(established)"
    echo "open=${open}"
    [ "$open" -eq "$CEILING" ] || {
        echo "the ceiling the reload set is not enforced" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

@test "after the reload a source that closed its connections opens as many again" {
    require_root

    # The test before left the source at its ceiling.
    sleep "$RELEASE_WAIT"
    hold_open "$CEILING"
    [ "$(established)" -eq "$CEILING" ]
    close_all
    sleep "$RELEASE_WAIT"

    hold_open "$CEILING"
    local open
    open="$(established)"
    echo "open after release=${open}"
    [ "$open" -eq "$CEILING" ] || {
        echo "closed connections still count against the ceiling the reload set" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}
