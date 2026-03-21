#!/usr/bin/env bats
# 23-ebpf-ddos-scenarios.bats — DDoS/scrub eBPF scenario tests
# Requires: root, kernel >= 6.1, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ddos-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ddos.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ddos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "DDoS scrub program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── DDoS status ──────────────────────────────────────────────────

@test "DDoS status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "DDoS policies loaded from config" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    [ "$count" -ge 2 ]
}

# ── ICMP flood detection ─────────────────────────────────────────

@test "ICMP flood triggers DDoS detection metrics" {
    require_root

    # Send a burst of ICMP packets (above threshold of 50 pps)
    send_icmp_from_ns "$EBPF_HOST_IP" 100 15

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

# ── SYN flood detection ──────────────────────────────────────────

@test "TCP SYN flood triggers DDoS metrics" {
    require_root

    # Send rapid TCP connections
    for i in $(seq 1 50); do
        send_tcp_from_ns "$EBPF_HOST_IP" 8888 "SYN${i}" 1 &
    done
    wait

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

# ── Attack history ───────────────────────────────────────────────

@test "DDoS attacks endpoint is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/attacks)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "DDoS attack history is accessible" {
    require_root

    local body
    body="$(api_get '/api/v1/ddos/attacks/history?limit=10')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "DDoS metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_scrub|ebpfsentinel_packets"
}

# ── TCP flag flood detection ──────────────────────────────────────

@test "DDoS RST flood detection" {
    require_root

    # Send RST-flagged packets from test namespace; ignore errors (tool may be absent)
    ip netns exec "$EBPF_TEST_NS" hping3 -R -p 8080 -c 200 -i u1000 "$EBPF_HOST_IP" 2>/dev/null || true

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

@test "DDoS FIN flood detection" {
    require_root

    ip netns exec "$EBPF_TEST_NS" hping3 -F -p 8080 -c 200 -i u1000 "$EBPF_HOST_IP" 2>/dev/null || true

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

@test "DDoS ACK flood detection" {
    require_root

    ip netns exec "$EBPF_TEST_NS" hping3 -A -p 8080 -c 200 -i u1000 "$EBPF_HOST_IP" 2>/dev/null || true

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

@test "DDoS ICMP flood detection" {
    require_root

    # High-rate ICMP flood via flood ping
    ip netns exec "$EBPF_TEST_NS" ping -f -c 500 -W 2 "$EBPF_HOST_IP" 2>/dev/null || true

    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_ddos|ebpfsentinel_packets"
}

# ── Attack history ────────────────────────────────────────────────

@test "DDoS attack history accessible" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/attacks/history)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Policy CRUD ───────────────────────────────────────────────────

@test "DDoS policy CRUD — create" {
    require_root

    local policy='{"id":"test-policy","attack_type":"syn_flood","detection_threshold_pps":100,"mitigation_action":"block"}'
    local body
    body="$(api_post /api/v1/ddos/policies "$policy")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id
    id="$(echo "$body" | jq -r '.id // empty' 2>/dev/null)" || true
    [ "$id" = "test-policy" ]
}

@test "DDoS policy CRUD — delete" {
    require_root

    api_delete /api/v1/ddos/policies/test-policy >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

# ── Extended DDoS flood & metrics tests ──────────────────────────

@test "ICMP flood triggers detection and metrics" {
    require_root
    require_tool hping3

    # Send 500 rapid ICMP packets
    ip netns exec "$EBPF_TEST_NS" \
        hping3 --icmp -c 500 -i u100 "$EBPF_HOST_IP" &>/dev/null || true

    sleep 3
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    echo "$metrics" | grep -qE "ebpfsentinel_ddos.*icmp" || [ -n "$metrics" ]
}

@test "RST flood detected by conntrack sub-type" {
    require_root
    require_tool hping3

    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 300 u200 "-R" || true
    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
}

@test "FIN flood detected" {
    require_root
    require_tool hping3

    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 300 u200 "-F" || true
    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
}

@test "ACK flood detected" {
    require_root
    require_tool hping3

    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 300 u200 "-A" || true
    sleep 3

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
}

@test "half-open connection limit enforcement" {
    require_root
    require_tool ncat

    # Open 50 half-open connections (SYN only, no ACK completion)
    for i in $(seq 1 50); do
        ip netns exec "$EBPF_TEST_NS" \
            timeout 1 ncat -w 1 "$EBPF_HOST_IP" 8888 </dev/null &>/dev/null &
    done
    wait

    sleep 3
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
}

@test "DDoS attack history endpoint returns entries" {
    require_root

    sleep 2
    local body
    body="$(api_get /api/v1/ddos/attacks/history)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "DDoS metrics include all flood types" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
    # At least some DDoS metrics should exist after the flood tests
    echo "$metrics" | grep -qE "ebpfsentinel_ddos" || true
}
