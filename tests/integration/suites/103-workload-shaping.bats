#!/usr/bin/env bats
# 103-workload-shaping.bats - one workload's egress held to a rate by its
# cgroup, read back through /api/v1/qos/shaping.
#
# The suite asserts:
#
#   * the shaping report lists the rule, and the interface carrying an fq
#     root qdisc as one where a departure time is honoured.
#   * a sender in the shaped cgroup is received at about its rate, while
#     the same sender outside the cgroup is received several times faster.
#   * the report lists the shaped cgroup with what the datapath counted
#     for it and the rate it achieved.
#   * an interface whose root qdisc is not fq is reported as one where the
#     shaper stands aside.
#
# Requires: root, kernel >= 6.12, jq, python3, tc.

load '../lib/helpers'
load '../lib/ebpf_helpers'

SHAPE_CGROUP="/sys/fs/cgroup/ebpf-shape-suite"
SHAPE_RATE_BPS=8000000
SINK_PORT=7311

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool tc

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 103 runs its sender beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-shape-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rmdir "$SHAPE_CGROUP" 2>/dev/null || true
    create_test_netns
    tc qdisc replace dev "$EBPF_VETH_HOST" root fq

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-workload-shaping.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "tc-qos" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "tc-qos did not load" >&2; return 1; }
    }
    mkdir -p "$SHAPE_CGROUP"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    tc qdisc del dev "${EBPF_VETH_HOST:-veth-ebpf0}" root 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rmdir "$SHAPE_CGROUP" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-shape-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# Receive TCP on $SINK_PORT inside the namespace for $1 seconds and print
# the bits per second received, while the sender command in $2 runs. A
# function named in $3 runs once the sender has started, while it sends.
_measure() {
    local secs="$1" sender="$2" during="${3:-}"
    ip netns exec "$EBPF_TEST_NS" python3 - "$EBPF_NS_IP" "$SINK_PORT" "$secs" >"${DATA_DIR}/rx" <<'PY' &
import socket, sys, time
host, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port)); srv.listen(1); srv.settimeout(10)
conn, _ = srv.accept()
conn.settimeout(1)
total, start = 0, time.monotonic()
while time.monotonic() - start < secs:
    try:
        data = conn.recv(1 << 16)
    except socket.timeout:
        continue
    if not data:
        break
    total += len(data)
print(int(total * 8 / (time.monotonic() - start)))
PY
    local rx=$!
    sleep 0.5
    bash -c "$sender" >/dev/null 2>&1 &
    local tx=$!
    [ -z "$during" ] || "$during"
    wait "$rx" || true
    kill "$tx" 2>/dev/null || true
    wait "$tx" 2>/dev/null || true
    cat "${DATA_DIR}/rx"
}

# A TCP sender writing as fast as the socket lets it, until killed.
_sender_cmd() {
    printf '%s' "exec python3 -c 'import socket; s=socket.create_connection((\"${EBPF_NS_IP}\", ${SINK_PORT})); b=bytes(65536)
while True: s.sendall(b)'"
}

# ── Tests ───────────────────────────────────────────────────────────

@test "GET /api/v1/qos/shaping lists the rule and the fq interface as honoured" {
    local body ok=""
    for _ in $(seq 1 15); do
        body="$(api_get /api/v1/qos/shaping)"
        _load_http_status
        if [ "$HTTP_STATUS" = "200" ] && [ "$(echo "$body" | jq -r --arg i "$EBPF_VETH_HOST" \
            '[.interfaces[] | select(.name == $i and .honoured == true)] | length')" = "1" ]; then
            ok=1; break
        fi
        sleep 1
    done
    [ -n "$ok" ] || { echo "interface not honoured: $HTTP_STATUS $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.supported')" = "true" ] || { echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.rules[] | select(.id == "shape-suite") | .rate_bps')" = "$SHAPE_RATE_BPS" ] || {
        echo "rule missing: $body" >&2
        return 1
    }
    [ "$(echo "$body" | jq -r --arg i "$EBPF_VETH_HOST" '.interfaces[] | select(.name == $i) | .root_qdisc')" = "fq" ] || {
        echo "root qdisc not read as fq: $body" >&2
        return 1
    }
}

@test "a sender in the shaped cgroup is held to its rate, the same sender outside it is not" {
    local free shaped
    free="$(_measure 4 "$(_sender_cmd)")"
    shaped="$(_measure 4 "echo \$\$ > ${SHAPE_CGROUP}/cgroup.procs; $(_sender_cmd)")"
    echo "unshaped ${free} bps, shaped ${shaped} bps" >&2

    [ -n "$free" ] && [ -n "$shaped" ] || { echo "no measurement" >&2; return 1; }
    # Held to the rate, with room for the burst before the first departure
    # time is set and for headers the rate does not count.
    [ "$shaped" -le $((SHAPE_RATE_BPS * 3 / 2)) ] || {
        echo "shaped sender at ${shaped} bps, above ${SHAPE_RATE_BPS}" >&2
        return 1
    }
    [ "$shaped" -ge $((SHAPE_RATE_BPS / 2)) ] || {
        echo "shaped sender starved at ${shaped} bps" >&2
        return 1
    }
    [ "$free" -ge $((SHAPE_RATE_BPS * 4)) ] || {
        echo "unshaped sender only at ${free} bps, the contrast proves nothing" >&2
        return 1
    }
}

# Read the report until it shows the shaped cgroup having sent more than
# a megabyte, and keep the last reading. A cgroup is listed while a task
# in it runs, so this is read while the sender sends.
_report_while_sending() {
    local body=""
    for _ in $(seq 1 8); do
        sleep 1
        body="$(api_get /api/v1/qos/shaping)"
        echo "$body" >"${DATA_DIR}/report"
        [ "$(echo "$body" | jq -r '[.cgroups[]? | select(.rule_id == "shape-suite") | .bytes] | first // 0')" -gt 1000000 ] && break
    done
}

@test "the report lists the shaped cgroup with its counters and achieved rate" {
    : >"${DATA_DIR}/report"
    _measure 10 "echo \$\$ > ${SHAPE_CGROUP}/cgroup.procs; $(_sender_cmd)" _report_while_sending >/dev/null
    local body
    body="$(cat "${DATA_DIR}/report")"
    [ -n "$body" ] || { echo "the report was never read" >&2; return 1; }
    local row
    row="$(echo "$body" | jq -c '[.cgroups[] | select(.rule_id == "shape-suite")] | first')"
    [ "$row" != "null" ] || { echo "shaped cgroup not listed: $body" >&2; return 1; }
    [ "$(echo "$row" | jq -r '.rate_bps')" = "$SHAPE_RATE_BPS" ] || { echo "$row" >&2; return 1; }
    [ "$(echo "$row" | jq -r '.bytes')" -gt 1000000 ] || { echo "datapath counted too little: $row" >&2; return 1; }
    [ "$(echo "$row" | jq -r '.cgroup // ""')" = "/ebpf-shape-suite" ] || { echo "cgroup path not read: $row" >&2; return 1; }
}

@test "an interface without fq is reported as one where the shaper stands aside" {
    tc qdisc replace dev "$EBPF_VETH_HOST" root pfifo
    local body ok=""
    for _ in $(seq 1 15); do
        body="$(api_get /api/v1/qos/shaping)"
        if [ "$(echo "$body" | jq -r --arg i "$EBPF_VETH_HOST" \
            '.interfaces[] | select(.name == $i) | "\(.root_qdisc) \(.honoured)"')" = "pfifo false" ]; then
            ok=1; break
        fi
        sleep 1
    done
    tc qdisc replace dev "$EBPF_VETH_HOST" root fq
    [ -n "$ok" ] || { echo "pfifo still reported as honoured: $body" >&2; return 1; }
}
