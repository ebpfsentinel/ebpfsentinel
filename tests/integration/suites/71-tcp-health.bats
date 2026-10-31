#!/usr/bin/env bats
# 71-tcp-health.bats - retransmissions, resets and connections per edge.
#
# The TCP stack's own tracepoints are counted per pair of ends in the
# kernel, and the agent names both ends when it reads them. The clients
# run on the host and the listeners in the test namespace: one kernel holds
# both sockets, so each connection is seen from both ends.
#
# The suite asserts:
#
#   * The counter attaches and reports itself loaded.
#   * A SYN to a port nothing listens on is answered with a reset counted
#     under `no_listener`, and the connect it ends is counted as failed.
#   * A connection made and closed is counted as opened and as closed, on
#     the client end and on the server end.
#   * No event was lost to a full table, an unwritten layout or an
#     unreadable socket.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 71 runs its clients beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-tcp-health-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-tcp-health.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    # A listener started by a test outlives it; the namespace's own pid list
    # is what still names it here.
    ip netns pids "$EBPF_TEST_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-tcp-health-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _sum <family> <label regex> - the sum of every series of the family whose
# labels match, 0 when none does. Labels are matched as a regex because an
# edge carries several and the suite pins only the ones it provoked.
_sum() {
    local family="${1:?usage: _sum <family> <labels>}"
    local labels="${2:-}"
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/metrics" \
        | grep "^${family}{" | grep -E "${labels}" \
        | awk '{ s += $2 } END { printf "%d\n", s + 0 }'
}

# _wait_sum <family> <labels> <min> - polls until the sum reaches min.
# `/metrics` answers 30 scrapes a minute per peer past a burst of 10, so the
# poll keeps to one scrape every three seconds and never spends the burst.
_wait_sum() {
    local family="$1" labels="$2" min="$3"
    local attempt=0 value=0
    while [ "$attempt" -lt 10 ]; do
        value="$(_sum "$family" "$labels")"
        [ "$value" -ge "$min" ] && { echo "$value"; return 0; }
        sleep 3
        attempt=$((attempt + 1))
    done
    echo "$value"
    return 1
}

_listen() {
    local port="${1:?usage: _listen <port>}"
    ip netns exec "$EBPF_TEST_NS" ncat -l "$EBPF_NS_IP" "$port" -k >/dev/null 2>&1 &
    local attempt=0
    while [ "$attempt" -lt 25 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -tlnH "sport = :${port}" 2>/dev/null | grep -q . && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the TCP health counter attaches" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30
}

@test "a SYN to a closed port is a reset under no_listener and a failed connect" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    for _ in 1 2 3; do
        ncat -w 2 "${EBPF_NS_IP}" 7111 </dev/null >/dev/null 2>&1 || true
    done

    run _wait_sum ebpfsentinel_tcp_resets_total 'service="no_listener".*direction="sent"' 3
    [ "$status" -eq 0 ] || { echo "no-listener resets sent: ${output}, want at least 3" >&2; return 1; }

    run _wait_sum ebpfsentinel_tcp_resets_total 'role="client".*direction="received"' 3
    [ "$status" -eq 0 ] || { echo "resets received by the client: ${output}, want at least 3" >&2; return 1; }

    run _wait_sum ebpfsentinel_tcp_connections_total 'role="client".*outcome="failed"' 3
    [ "$status" -eq 0 ] || { echo "failed connects: ${output}, want at least 3" >&2; return 1; }
}

@test "a connection made and closed is opened and closed at both ends" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    _listen 7112
    for _ in 1 2 3; do
        echo x | ncat -w 2 "${EBPF_NS_IP}" 7112 >/dev/null 2>&1 || true
    done

    run _wait_sum ebpfsentinel_tcp_connections_total 'role="client".*outcome="opened"' 3
    [ "$status" -eq 0 ] || { echo "client connections opened: ${output}, want at least 3" >&2; return 1; }
    run _wait_sum ebpfsentinel_tcp_connections_total 'role="server".*outcome="opened"' 3
    [ "$status" -eq 0 ] || { echo "server connections opened: ${output}, want at least 3" >&2; return 1; }
    run _wait_sum ebpfsentinel_tcp_connections_total 'role="client".*outcome="closed"' 3
    [ "$status" -eq 0 ] || { echo "client connections closed: ${output}, want at least 3" >&2; return 1; }
    run _wait_sum ebpfsentinel_tcp_connections_total 'role="server".*outcome="closed"' 3
    [ "$status" -eq 0 ] || { echo "server connections closed: ${output}, want at least 3" >&2; return 1; }
}

@test "the hooks lost no event to a full table or an unwritten layout" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    # The previous tests polled the scrape endpoint; let its quota refill.
    sleep 3
    run curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/metrics"
    [ "$status" -eq 0 ] || { echo "metrics scrape failed: ${status}" >&2; return 1; }
    local edges uncounted
    edges="$(echo "$output" | grep -c '^ebpfsentinel_tcp_connections_total{' || true)"
    uncounted="$(echo "$output" | grep '^ebpfsentinel_tcp_health_uncounted_total ' | awk '{print $2}' | head -1)"
    [ "${edges:-0}" -gt 0 ] || { echo "no edge carries a connection count" >&2; return 1; }
    [ -n "$uncounted" ] || { echo "ebpfsentinel_tcp_health_uncounted_total is not exported" >&2; return 1; }
    [ "$uncounted" -eq 0 ] || { echo "events left uncounted: ${uncounted}" >&2; return 1; }
}
