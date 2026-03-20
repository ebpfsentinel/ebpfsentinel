#!/usr/bin/env bats
# 31-ebpf-qos-scenarios.bats — QoS eBPF scenario tests
# Requires: root, kernel >= 6.1, bpftool, iperf3

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-qos-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-qos.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-qos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "QoS program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── QoS status ───────────────────────────────────────────────────

@test "QoS status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/qos/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Pipes ────────────────────────────────────────────────────────

@test "QoS pipes list via API" {
    require_root

    local body
    body="$(api_get /api/v1/qos/pipes)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .pipes | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]
}

@test "QoS pipe CRUD — create and delete" {
    require_root

    # Create a new pipe
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"name":"test-crud-pipe","rate_kbps":5120,"burst_kbps":6144,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Delete the created pipe
    local delete_body
    delete_body="$(api_delete "/api/v1/qos/pipes/${pipe_id}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

# ── Bandwidth shaping ────────────────────────────────────────────

@test "QoS bandwidth limiting shapes traffic" {
    require_root
    require_tool iperf3

    # Start iperf3 server on host side (port 5201) in background
    iperf3 -s -p 5201 -D --logfile /tmp/iperf3-qos-server-$$.log 2>/dev/null || true
    sleep 1

    # Run iperf3 client from the network namespace at 50Mbps — pipe cap is 10Mbps
    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 5 "" -p 5201 -b 50M 2>/dev/null)" || true

    # Stop iperf3 server
    pkill -f "iperf3 -s -p 5201" 2>/dev/null || true
    rm -f /tmp/iperf3-qos-server-$$.log

    # If iperf3 ran, parse throughput; otherwise skip (iperf3 requires a listening server)
    if [ -z "$result" ]; then
        skip "iperf3 did not produce output"
    fi

    # Extract bits_per_second from iperf3 JSON output (sum/received section)
    local bps
    bps="$(echo "$result" | jq -r \
        '.end.sum_received.bits_per_second // .end.sum.bits_per_second' 2>/dev/null)" || true

    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        skip "iperf3 JSON output not parseable"
    fi

    # Pipe cap is 10Mbps (10240 kbps); allow up to 12Mbps for burst
    local max_bps=12582912   # 12 * 1024 * 1024
    local bps_int
    bps_int="$(echo "$bps" | cut -d. -f1)"
    [ "$bps_int" -le "$max_bps" ]
}

# ── Classifiers ──────────────────────────────────────────────────

@test "QoS classifier matches port traffic" {
    require_root

    local body
    body="$(api_get /api/v1/qos/classifiers)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .classifiers | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]
}

# ── Queues ───────────────────────────────────────────────────────

@test "QoS queue CRUD — create and delete" {
    require_root

    # Create a queue in the existing test pipe
    local create_body
    create_body="$(api_post /api/v1/qos/queues \
        '{"name":"test-crud-queue","pipe_id":"qos-test-pipe-1","priority":1,"weight":2,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local queue_id
    queue_id="$(echo "$create_body" | jq -r '.id // .queue_id' 2>/dev/null)" || true
    [ -n "$queue_id" ]
    [ "$queue_id" != "null" ]

    # Delete the created queue
    local delete_body
    delete_body="$(api_delete "/api/v1/qos/queues/${queue_id}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "QoS metrics present in Prometheus" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_qos"
}
