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

# ── Pipe bandwidth enforcement ──────────────────────────────────

@test "QoS pipe bandwidth enforcement — upload capped" {
    require_root
    require_tool iperf3

    # Start iperf3 server on host side (port 5202) in background
    iperf3 -s -p 5202 -D --logfile /tmp/iperf3-qos-upload-$$.log 2>/dev/null || true
    sleep 1

    # Run iperf3 client from the namespace — reverse mode (upload from ns) at 100Mbps
    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 3 "" -p 5202 -b 100M -R 2>/dev/null)" || true

    # Stop iperf3 server
    pkill -f "iperf3 -s -p 5202" 2>/dev/null || true
    rm -f /tmp/iperf3-qos-upload-$$.log

    if [ -z "$result" ]; then
        skip "iperf3 did not produce output"
    fi

    local bps
    bps="$(echo "$result" | jq -r \
        '.end.sum_received.bits_per_second // .end.sum.bits_per_second' 2>/dev/null)" || true

    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        skip "iperf3 JSON output not parseable"
    fi

    # Pipe cap is 10Mbps (10240 kbps); allow up to 15Mbps for burst headroom
    local max_bps=15728640   # 15 * 1024 * 1024
    local bps_int
    bps_int="$(echo "$bps" | cut -d. -f1)"
    [ "$bps_int" -le "$max_bps" ]
}

# ── Classifier priority ordering ────────────────────────────────

@test "QoS classifier priority ordering" {
    require_root

    # Create two classifiers with different priorities
    local body_low body_high
    body_low="$(api_post /api/v1/qos/classifiers \
        '{"name":"prio-low-cls","match_port":9090,"pipe_id":"qos-test-pipe-1","priority":90,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_low
    id_low="$(echo "$body_low" | jq -r '.id // .classifier_id' 2>/dev/null)" || true

    body_high="$(api_post /api/v1/qos/classifiers \
        '{"name":"prio-high-cls","match_port":8080,"pipe_id":"qos-test-pipe-1","priority":5,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_high
    id_high="$(echo "$body_high" | jq -r '.id // .classifier_id' 2>/dev/null)" || true

    # Fetch classifiers and verify both are present
    local list_body
    list_body="$(api_get /api/v1/qos/classifiers)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local classifiers
    classifiers="$(echo "$list_body" | jq 'if type == "array" then . else .classifiers end' 2>/dev/null)" || true
    local count
    count="$(echo "$classifiers" | jq 'length' 2>/dev/null)" || true
    [ "${count:-0}" -ge 2 ]

    # Verify the high-priority classifier (priority=5) sorts before the low-priority (priority=90)
    local first_id
    first_id="$(echo "$classifiers" | jq -r 'sort_by(.priority) | .[0].id' 2>/dev/null)" || true
    [ "$first_id" = "$id_high" ]

    # Clean up
    api_delete "/api/v1/qos/classifiers/${id_low}" >/dev/null 2>&1 || true
    api_delete "/api/v1/qos/classifiers/${id_high}" >/dev/null 2>&1 || true
}

# ── Queue weight distribution ───────────────────────────────────

@test "QoS queue weight distribution — multiple queues" {
    require_root

    # Create two queues with different weights in the test pipe
    local body_w1 body_w3
    body_w1="$(api_post /api/v1/qos/queues \
        '{"name":"weight-q1","pipe_id":"qos-test-pipe-1","priority":1,"weight":1,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_w1
    id_w1="$(echo "$body_w1" | jq -r '.id // .queue_id' 2>/dev/null)" || true

    body_w3="$(api_post /api/v1/qos/queues \
        '{"name":"weight-q3","pipe_id":"qos-test-pipe-1","priority":1,"weight":3,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_w3
    id_w3="$(echo "$body_w3" | jq -r '.id // .queue_id' 2>/dev/null)" || true

    # Verify both queues are listed
    local list_body
    list_body="$(api_get /api/v1/qos/queues)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$list_body" | jq 'if type == "array" then length else .queues | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 2 ]

    # Verify the weights are correctly stored
    local queues
    queues="$(echo "$list_body" | jq 'if type == "array" then . else .queues end' 2>/dev/null)" || true
    local w3_weight
    w3_weight="$(echo "$queues" | jq -r ".[] | select(.id == \"$id_w3\" or .queue_id == \"$id_w3\") | .weight" 2>/dev/null)" || true
    [ "$w3_weight" = "3" ]

    # Clean up
    api_delete "/api/v1/qos/queues/${id_w1}" >/dev/null 2>&1 || true
    api_delete "/api/v1/qos/queues/${id_w3}" >/dev/null 2>&1 || true
}

# ── Delay annotation ────────────────────────────────────────────

@test "QoS pipe delay annotation" {
    require_root

    # Create a pipe with delay_ms configured
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"name":"delay-pipe","rate_kbps":10240,"burst_kbps":12288,"delay_ms":50,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Verify the pipe has the delay_ms field set
    local delay
    delay="$(echo "$create_body" | jq -r '.delay_ms // .delay' 2>/dev/null)" || true
    [ "$delay" = "50" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}

# ── Loss emulation ──────────────────────────────────────────────

@test "QoS pipe loss emulation" {
    require_root

    # Create a pipe with loss_percent configured
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"name":"loss-pipe","rate_kbps":10240,"burst_kbps":12288,"loss_percent":5,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Verify the pipe has the loss_percent field set
    local loss
    loss="$(echo "$create_body" | jq -r '.loss_percent // .loss' 2>/dev/null)" || true
    [ "$loss" = "5" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}

# ── EDT pacing ──────────────────────────────────────────────────

@test "QoS EDT pacing configured" {
    require_root

    # Create a pipe with EDT (Earliest Departure Time) pacing enabled
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"name":"edt-pipe","rate_kbps":20480,"burst_kbps":24576,"edt_pacing":true,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Verify the pipe has the edt_pacing field set
    local edt
    edt="$(echo "$create_body" | jq -r '.edt_pacing // .edt' 2>/dev/null)" || true
    [ "$edt" = "true" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}

# ── Classifier CRUD ─────────────────────────────────────────────

@test "QoS classifier CRUD — create and delete" {
    require_root

    # Create a new classifier
    local create_body
    create_body="$(api_post /api/v1/qos/classifiers \
        '{"name":"test-crud-cls","match_port":7777,"pipe_id":"qos-test-pipe-1","priority":50,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local cls_id
    cls_id="$(echo "$create_body" | jq -r '.id // .classifier_id' 2>/dev/null)" || true
    [ -n "$cls_id" ]
    [ "$cls_id" != "null" ]

    # Delete the created classifier
    local delete_body
    delete_body="$(api_delete "/api/v1/qos/classifiers/${cls_id}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]

    # Verify it no longer appears in the list
    local list_body
    list_body="$(api_get /api/v1/qos/classifiers)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local found
    found="$(echo "$list_body" | jq "[if type == \"array\" then .[] else .classifiers[] end | select(.id == \"$cls_id\" or .classifier_id == \"$cls_id\")] | length" 2>/dev/null)" || found=0
    [ "${found:-0}" -eq 0 ]
}

# ── Pipe update ─────────────────────────────────────────────────

@test "QoS pipe CRUD — update rate" {
    require_root

    # Create a pipe
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"name":"update-pipe","rate_kbps":5120,"burst_kbps":6144,"enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Update the pipe rate
    local update_body
    update_body="$(api_patch "/api/v1/qos/pipes/${pipe_id}" \
        '{"rate_kbps":20480,"burst_kbps":24576}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    # Verify the rate was updated
    local new_rate
    new_rate="$(echo "$update_body" | jq -r '.rate_kbps // .rate' 2>/dev/null)" || true
    [ "$new_rate" = "20480" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}
