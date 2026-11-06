#!/usr/bin/env bats
# 90-network-readings.bats - what the node reads off its own network: flow
# records, the service graph, the kernel's drops by reason and the listeners
# it exposes.
#
# The suite asserts:
#
#   * A TCP connection the host opens is written as a flow record to the
#     JSON lines file, with its addresses, its ports, its transport and its
#     bytes, and the export status counts it as sent by that sink.
#   * HTTP requests from the test namespace to a server on the host land on
#     one service graph edge, observed and answered, and a window outside the
#     graph's range is refused rather than clamped.
#   * Datagrams sent to a port nothing listens on are counted by the kernel
#     drop counter as NO_SOCKET on the interface they arrived on.
#   * A listener bound after the agent started is reported with the
#     executable that bound it; one the firewall lets through is reachable by
#     the default policy, and one a deny rule names is closed by that rule.
#
# Requires: root, kernel >= 6.12, jq, python3, curl, nft.

load '../lib/helpers'
load '../lib/ebpf_helpers'

GRAPH_PORT=8880
FLOW_PORT=8881
OPEN_PORT=8882
CLOSED_PORT=8883
DEAD_PORT=8889

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool curl
    require_tool nft

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-readings-$$"
    mkdir -p "$DATA_DIR/www"
    echo ok > "$DATA_DIR/www/index.html"

    create_test_netns

    # The host's conntrack table only follows a connection once something
    # hooks it; a stateful rule that accepts everything is that something.
    nft add table inet ebpfsentinel_readings
    nft add chain inet ebpfsentinel_readings out '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet ebpfsentinel_readings out ct state new counter accept

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-network-readings.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }

    # Every server starts after the agent, so the bind hook sees each one.
    _serve host "$EBPF_HOST_IP" "$GRAPH_PORT" graph
    _serve ns "0.0.0.0" "$FLOW_PORT" flow
    _serve host "$EBPF_HOST_IP" "$OPEN_PORT" open
    _serve host "0.0.0.0" "$CLOSED_PORT" closed
    sleep 1
}

teardown_file() {
    local f
    for f in graph flow open closed; do
        [ -f "${DATA_DIR}/${f}.pid" ] && kill "$(cat "${DATA_DIR}/${f}.pid")" 2>/dev/null
    done
    nft delete table inet ebpfsentinel_readings 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# _serve <host|ns> <address> <port> <name> - a Python HTTP server, detached.
_serve() {
    local where="$1" address="$2" port="$3" name="$4"
    local run=()
    [ "$where" = "ns" ] && run=(ip netns exec "$EBPF_TEST_NS")
    setsid "${run[@]}" python3 -m http.server "$port" --bind "$address" \
        --directory "${DATA_DIR}/www" >"${DATA_DIR}/${name}.log" 2>&1 </dev/null &
    echo $! > "${DATA_DIR}/${name}.pid"
}

@test "a connection the host opens is written as a flow record and counted as sent" {
    curl -s -o /dev/null --max-time 5 "http://${EBPF_NS_IP}:${FLOW_PORT}/"

    local i line=""
    for i in $(seq 1 30); do
        line="$(jq -c --arg d "$EBPF_NS_IP" --argjson p "$FLOW_PORT" \
            'select(."destination.address" == $d and ."destination.port" == $p)' \
            "${DATA_DIR}/flows.jsonl" 2>/dev/null | head -1)"
        [ -n "$line" ] && break
        sleep 0.5
    done
    [ -n "$line" ] || {
        echo "# no record for ${EBPF_NS_IP}:${FLOW_PORT}" >&3
        cat "${DATA_DIR}/flows.jsonl" >&3 2>/dev/null
        false
    }
    [ "$(echo "$line" | jq -r '."source.address"')" = "$EBPF_HOST_IP" ]
    [ "$(echo "$line" | jq -r '."network.transport"')" = "tcp" ]
    [ "$(echo "$line" | jq -r '."ebpfsentinel.flow.bytes"')" -gt 0 ]
    [ "$(stat -c %a "${DATA_DIR}/flows.jsonl")" = "600" ]

    local body
    body="$(api_get /api/v1/flows/export)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(echo "$body" | jq -r '.enabled')" = "true" ]
    [ "$(echo "$body" | jq -r '.exported')" -ge 1 ]
    [ "$(echo "$body" | jq -r '[.sinks[] | select(.name | startswith("json-lines"))][0].records_sent')" -ge 1 ]
    [ "$(echo "$body" | jq -r '[.sinks[] | select(.name | startswith("json-lines"))][0].healthy')" = "true" ]
}

@test "HTTP requests to the host land on one service graph edge" {
    local n
    for n in 1 2 3; do
        ip netns exec "$EBPF_TEST_NS" curl -s -o /dev/null --max-time 5 \
            "http://${EBPF_HOST_IP}:${GRAPH_PORT}/"
    done

    local i body edge=""
    for i in $(seq 1 20); do
        body="$(api_get '/api/v1/services/graph?minutes=5')"
        edge="$(echo "$body" | jq -c --arg s "$EBPF_HOST_IP" --argjson p "$GRAPH_PORT" \
            '[.edges[] | select(.server.address == $s and .server_port == $p and .requests >= 3)] | first // empty')"
        [ -n "$edge" ] && break
        sleep 0.5
    done
    [ -n "$edge" ] || {
        echo "# no edge on ${GRAPH_PORT} with three requests: ${body}" >&3
        false
    }
    [ "$(echo "$edge" | jq -r '.protocol')" = "http" ]
    [ "$(echo "$edge" | jq -r '.client.address')" = "$EBPF_NS_IP" ]
    [ "$(echo "$edge" | jq -r '.answered')" -ge 1 ]

    api_get '/api/v1/services/graph?minutes=0' >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "400" ]
}

@test "datagrams to a port nothing listens on are counted as NO_SOCKET on their interface" {
    local body
    body="$(api_get /api/v1/ebpf/drop-reasons)"
    [ "$(echo "$body" | jq -r '.counting')" = "true" ] || {
        echo "# the drop counter is not counting: ${body}" >&3
        false
    }
    local before
    before="$(echo "$body" | jq --arg i "$EBPF_VETH_HOST" \
        '[.drops[] | select(.reason == "NO_SOCKET" and .interface == $i) | .packets] | add // 0')"

    ip netns exec "$EBPF_TEST_NS" python3 - "$EBPF_HOST_IP" "$DEAD_PORT" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(50):
    s.sendto(b"x", (sys.argv[1], int(sys.argv[2])))
PY

    local i now=0
    for i in $(seq 1 20); do
        body="$(api_get /api/v1/ebpf/drop-reasons)"
        now="$(echo "$body" | jq --arg i "$EBPF_VETH_HOST" \
            '[.drops[] | select(.reason == "NO_SOCKET" and .interface == $i) | .packets] | add // 0')"
        [ "$now" -ge $((before + 50)) ] && break
        sleep 0.5
    done
    [ "$now" -ge $((before + 50)) ] || {
        echo "# NO_SOCKET on ${EBPF_VETH_HOST} went from ${before} to ${now}: ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq -r '[.drops[] | select(.reason == "NO_SOCKET")][0].description')" != "null" ]
    [ "$(echo "$body" | jq -r '.total')" -ge "$now" ]
}

@test "a listener is reported with its binary, reachable or closed by the rule that names it" {
    local i body open="" closed=""
    for i in $(seq 1 20); do
        body="$(api_get /api/v1/exposure/listeners)"
        open="$(echo "$body" | jq -c --argjson p "$OPEN_PORT" \
            '[.listeners[] | select(.port == $p and .protocol == "tcp")] | first // empty')"
        closed="$(echo "$body" | jq -c --argjson p "$CLOSED_PORT" \
            '[.listeners[] | select(.port == $p and .protocol == "tcp")] | first // empty')"
        [ -n "$open" ] && [ -n "$closed" ] && break
        sleep 0.5
    done
    [ "$(echo "$body" | jq -r '.reading')" = "true" ]
    [ -n "$open" ] && [ -n "$closed" ] || {
        echo "# listeners on ${OPEN_PORT} and ${CLOSED_PORT} not both reported: ${body}" >&3
        false
    }

    [ "$(echo "$open" | jq -r '.address')" = "$EBPF_HOST_IP" ]
    [ "$(echo "$open" | jq -r '.scope')" = "address" ]
    assert_contains "$(echo "$open" | jq -r '.executable')" "python3"
    [ "$(echo "$open" | jq -r '.pid')" = "$(cat "${DATA_DIR}/open.pid")" ]
    [ "$(echo "$open" | jq -r '.reachable')" = "true" ]
    [ "$(echo "$open" | jq -r '.decided_by')" = "default_policy" ]

    [ "$(echo "$closed" | jq -r '.scope')" = "all_addresses" ]
    [ "$(echo "$closed" | jq -r '.reachable')" = "false" ]
    [ "$(echo "$closed" | jq -r '.decided_by')" = "rule" ]
    assert_contains "$(echo "$closed" | jq -r '.rule')" "fw-readings-deny-${CLOSED_PORT}"
    [ "$(echo "$closed" | jq -r '.class')" = "closed_by_policy" ]
}
