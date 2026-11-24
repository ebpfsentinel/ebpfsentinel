#!/usr/bin/env bats
# 152-tcp-send-timestamps.bats - writes timed from the kernel's own
# transmit timestamps, per edge.
#
# A sock_ops program on the attribution cgroup root opts each established
# connection in to the timestamp callbacks and times one write in flight per
# socket to the queueing discipline, the driver and the acknowledgement. The
# clients run on the host and the listener in the test namespace.
#
# The suite asserts:
#
#   * The capability report names `tcp_send_timestamps` active: the floor
#     carries the callbacks, so an inactive entry is a refusal to explain.
#   * A write a client sends is timed to scheduled, sent and acked on its
#     edge.
#   * Turning the counter's timing off leaves the round-trip histogram
#     running and names the configuration in the report.
#   * No event was lost to a full table or a refused timestamp.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 152 runs its clients beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-tcp-send-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-tcp-send-timestamps.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    ip netns pids "$EBPF_TEST_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-tcp-send-$$}"
    rm -f "${PREPARED_CONFIG:-}" "${OFF_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _sum <family> <label regex> - the sum of every series of the family whose
# labels match, 0 when none does.
_sum() {
    local family="${1:?usage: _sum <family> <labels>}"
    local labels="${2:-}"
    scrape_metrics \
        | grep "^${family}{" | grep -E "${labels}" \
        | awk '{ s += $2 } END { printf "%d\n", s + 0 }'
}

# _wait_sum <family> <labels> <min> - polls until the sum reaches min, one
# scrape every three seconds so the scrape quota is never spent.
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

# _capability <id> - the capability's entry in the report, compact JSON.
_capability() {
    api_get /api/v1/ebpf/kernel-features \
        | jq -c --arg id "$1" '.capabilities[]? | select(.id == $id)'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the capability report names the timing of writes active" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    local entry
    entry="$(_capability tcp_send_timestamps)"
    [ -n "$entry" ] || { echo "tcp_send_timestamps missing from the report" >&2; return 1; }
    echo "$entry" | jq -e '.active == true' >/dev/null \
        || { echo "timing writes is off: ${entry}" >&2; return 1; }
}

@test "a write is timed by the kernel to scheduled, sent and acked" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    _listen 7114
    for _ in 1 2 3; do
        echo timed | ncat -w 2 "${EBPF_NS_IP}" 7114 >/dev/null 2>&1 || true
    done

    local stage
    for stage in scheduled sent acked; do
        run _wait_sum ebpfsentinel_tcp_send_latency_seconds_count "role=\"client\".*stage=\"${stage}\"" 3
        [ "$status" -eq 0 ] || { echo "client writes timed to ${stage}: ${output}, want at least 3" >&2; return 1; }
    done
}

@test "the hooks lost no event to a full table or a refused timestamp" {
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    sleep 3
    run scrape_metrics
    [ "$status" -eq 0 ] || { echo "metrics scrape failed: ${status}" >&2; return 1; }
    local uncounted
    uncounted="$(echo "$output" | grep '^ebpfsentinel_tcp_health_uncounted_total ' | awk '{print $2}' | head -1)"
    [ -n "$uncounted" ] || { echo "ebpfsentinel_tcp_health_uncounted_total is not exported" >&2; return 1; }
    [ "$uncounted" -eq 0 ] || { echo "events left uncounted: ${uncounted}" >&2; return 1; }
}

@test "with send_latency off the round trip is still sampled and the report names the configuration" {
    stop_ebpf_agent 2>/dev/null || true
    OFF_CONFIG="${DATA_DIR}/config-send-off.yaml"
    export OFF_CONFIG
    sed 's/^  send_latency: true$/  send_latency: false/' "$PREPARED_CONFIG" >"$OFF_CONFIG"
    grep -q '^  send_latency: false$' "$OFF_CONFIG" || { echo "the fixture carries no send_latency line" >&2; return 1; }

    start_ebpf_agent "$OFF_CONFIG"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded" >&2; return 1; }
    wait_for_ebpf_program "tracepoint-tcp-health" 30 || { echo "the TCP health counter did not attach" >&2; return 1; }

    local entry
    entry="$(_capability tcp_send_timestamps)"
    echo "$entry" | jq -e '.active == false and (.reason // "" | test("configuration"))' >/dev/null \
        || { echo "unexpected entry with send_latency off: ${entry}" >&2; return 1; }

    _listen 7115
    for _ in 1 2 3; do
        echo x | ncat -w 2 "${EBPF_NS_IP}" 7115 >/dev/null 2>&1 || true
    done
    run _wait_sum ebpfsentinel_tcp_rtt_seconds_count 'role="client"' 3
    [ "$status" -eq 0 ] || { echo "client round-trip samples: ${output}, want at least 3" >&2; return 1; }
    [ "$(_sum ebpfsentinel_tcp_send_latency_seconds_count '')" -eq 0 ] \
        || { echo "writes timed with send_latency off" >&2; return 1; }
}
