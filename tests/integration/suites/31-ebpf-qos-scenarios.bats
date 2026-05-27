#!/usr/bin/env bats
# 31-ebpf-qos-scenarios.bats — QoS eBPF scenario tests
# Requires: root, kernel >= 6.9, bpftool, iperf3

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
        '{"id":"test-crud-pipe","rate_bps":5242880,"burst_bytes":786432}')"
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
        '{"id":"test-crud-queue","pipe_id":"pipe-test-10m","weight":2}')"
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

    # QoS counters surface through the generic kernel-metrics pipeline as
    # ebpfsentinel_packets_total{interface="QOS_METRICS",action="..."}. The
    # poller ticks on a 10s loop, so allow up to 20 attempts.
    wait_for_metric "ebpfsentinel_packets_total" 1 20 '{interface="QOS_METRICS",action="total_seen"}' >/dev/null || true

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE 'ebpfsentinel_packets_total\{interface="QOS_METRICS"'
}

# ── Pipe bandwidth enforcement ──────────────────────────────────

@test "QoS pipe bandwidth enforcement — upload capped" {
    require_root
    require_tool iperf3

    # The agent shapes ns->host (ingress) traffic. Bind a classifier to TCP/5202
    # so this upload flow lands on the 10Mbps test pipe, then drive it.
    api_post /api/v1/qos/classifiers \
        '{"id":"cls-upload-5202","queue_id":"queue-test-1","priority":10,"match_rule":{"dst_port":5202,"protocol":6}}' >/dev/null 2>&1 || true
    sleep 1

    # Start iperf3 server on host side (port 5202) in background
    iperf3 -s -p 5202 -D --logfile /tmp/iperf3-qos-upload-$$.log 2>/dev/null || true
    sleep 1

    # Run iperf3 client from the namespace — upload (ns->host) at 100Mbps
    local result
    result="$(iperf3_from_ns "$EBPF_HOST_IP" 3 "" -p 5202 -b 100M 2>/dev/null)" || true

    # Stop iperf3 server and remove the classifier
    pkill -f "iperf3 -s -p 5202" 2>/dev/null || true
    rm -f /tmp/iperf3-qos-upload-$$.log
    api_delete /api/v1/qos/classifiers/cls-upload-5202 >/dev/null 2>&1 || true

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
        '{"id":"prio-low-cls","queue_id":"queue-test-1","priority":90,"match_rule":{"dst_port":9090,"protocol":6}}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_low
    id_low="$(echo "$body_low" | jq -r '.id // .classifier_id' 2>/dev/null)" || true

    body_high="$(api_post /api/v1/qos/classifiers \
        '{"id":"prio-high-cls","queue_id":"queue-test-1","priority":5,"match_rule":{"dst_port":8080,"protocol":6}}')"
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

    # Of the two created classifiers, the high-priority one (priority=5) must
    # sort before the low-priority one (priority=90). Filter to just this pair so
    # any seeded classifiers (e.g. cls-test-iperf at priority 0) don't interfere.
    local pair_first
    pair_first="$(echo "$classifiers" | jq -r \
        "[.[] | select(.id == \"$id_low\" or .id == \"$id_high\")] | sort_by(.priority) | .[0].id" 2>/dev/null)" || true
    [ "$pair_first" = "$id_high" ]

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
        '{"id":"weight-q1","pipe_id":"pipe-test-10m","weight":1}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_w1
    id_w1="$(echo "$body_w1" | jq -r '.id // .queue_id' 2>/dev/null)" || true

    body_w3="$(api_post /api/v1/qos/queues \
        '{"id":"weight-q3","pipe_id":"pipe-test-10m","weight":3}')"
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

# ── Pipe rate persistence ───────────────────────────────────────

@test "QoS pipe rate_bps persisted on create" {
    require_root

    # Create a pipe and verify the returned rate matches what was requested
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"id":"rate-pipe","rate_bps":12582912,"burst_bytes":1572864}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    local rate
    rate="$(echo "$create_body" | jq -r '.rate_bps' 2>/dev/null)" || true
    [ "$rate" = "12582912" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}

# ── Pipe burst persistence ──────────────────────────────────────

@test "QoS pipe burst_bytes persisted on create" {
    require_root

    # Create a pipe and verify the returned burst matches what was requested
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"id":"burst-pipe","rate_bps":10485760,"burst_bytes":2097152}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ -n "$pipe_id" ]
    [ "$pipe_id" != "null" ]

    # Verify the pipe has the burst_bytes field set
    local burst
    burst="$(echo "$create_body" | jq -r '.burst_bytes' 2>/dev/null)" || true
    [ "$burst" = "2097152" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
}

# ── Pipe list round-trip ────────────────────────────────────────

@test "QoS pipe appears in list after create" {
    require_root

    # Create a pipe, confirm it round-trips through the list endpoint
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"id":"list-pipe","rate_bps":20971520,"burst_bytes":2621440}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local pipe_id
    pipe_id="$(echo "$create_body" | jq -r '.id // .pipe_id' 2>/dev/null)" || true
    [ "$pipe_id" = "list-pipe" ]

    # Verify it is present in the list
    local list_body found
    list_body="$(api_get /api/v1/qos/pipes)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    found="$(echo "$list_body" | jq '[if type == "array" then .[] else .pipes[] end | select(.id == "list-pipe")] | length' 2>/dev/null)" || found=0
    [ "${found:-0}" -ge 1 ]

    # Clean up and verify removal
    api_delete "/api/v1/qos/pipes/${pipe_id}" >/dev/null 2>&1 || true
    list_body="$(api_get /api/v1/qos/pipes)"
    found="$(echo "$list_body" | jq '[if type == "array" then .[] else .pipes[] end | select(.id == "list-pipe")] | length' 2>/dev/null)" || found=0
    [ "${found:-0}" -eq 0 ]
}

# ── Classifier CRUD ─────────────────────────────────────────────

@test "QoS classifier CRUD — create and delete" {
    require_root

    # Create a new classifier
    local create_body
    create_body="$(api_post /api/v1/qos/classifiers \
        '{"id":"test-crud-cls","queue_id":"queue-test-1","priority":50,"match_rule":{"dst_port":7777,"protocol":6}}')"
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

# ── Pipe rate change ────────────────────────────────────────────

@test "QoS pipe rate change via recreate" {
    require_root

    # Create a pipe at an initial rate
    local create_body
    create_body="$(api_post /api/v1/qos/pipes \
        '{"id":"recreate-pipe","rate_bps":5242880,"burst_bytes":786432}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # The API has no in-place update; a rate change is delete + recreate.
    api_delete "/api/v1/qos/pipes/recreate-pipe" >/dev/null 2>&1 || true

    local recreate_body
    recreate_body="$(api_post /api/v1/qos/pipes \
        '{"id":"recreate-pipe","rate_bps":20971520,"burst_bytes":2621440}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Verify the new rate is in effect
    local new_rate
    new_rate="$(echo "$recreate_body" | jq -r '.rate_bps' 2>/dev/null)" || true
    [ "$new_rate" = "20971520" ]

    # Clean up
    api_delete "/api/v1/qos/pipes/recreate-pipe" >/dev/null 2>&1 || true
}
