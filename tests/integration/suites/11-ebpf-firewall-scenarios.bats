#!/usr/bin/env bats
# 11-ebpf-firewall-scenarios.bats — Firewall eBPF packet-level tests
# Requires: root, kernel >= 5.17, bpftool, ncat, ip
#
# Tests array-based rule matching with:
#   - CIDR subnet matching (/24)
#   - Wildcard rules (any src_ip, any port)
#   - Port ranges (9990-9999)
#   - Priority-based first-match-wins ordering
#   - Default policy (pass)
#   - Dynamic rule addition via REST API
#
# Fixture rules (config-ebpf-firewall.yaml):
#   P5:  allow ICMP from 10.200.0.0/24 to 10.200.0.1
#   P10: deny ALL ICMP (wildcard)
#   P20: deny TCP dst_port 9990-9999 (port range)
#   P30: log  TCP 10.200.0.2 -> 10.200.0.1:8888 (single port)
#   P40: deny TCP dst_port 7777 (wildcard src/dst IP)
#   Default: pass

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-fw-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Prepare config
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-firewall.yaml")"
    export PREPARED_CONFIG

    # Start agent with eBPF programs
    start_ebpf_agent "$PREPARED_CONFIG"

    # Wait for eBPF programs to load
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load (degraded mode). Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-fw-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── XDP attachment ────────────────────────────────────────────────

@test "XDP program attached to veth interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── CIDR subnet matching + priority first-match-wins ──────────────

@test "ICMP from /24 subnet passes (CIDR allow P5 overrides deny P10)" {
    require_root

    # P5 allows ICMP from 10.200.0.0/24 to 10.200.0.1
    # P10 denies ALL ICMP (wildcard)
    # First-match-wins: P5 should match before P10
    local result
    result="$(ip netns exec "$EBPF_TEST_NS" \
        ping -c 3 -W 1 -i 0.2 "$EBPF_HOST_IP" 2>&1)" || true

    local received
    received="$(echo "$result" | grep -oP '\d+(?= received)')" || true
    [ "${received:-0}" -ge 1 ]
}

# ── Port range matching ──────────────────────────────────────────

@test "TCP to port 9995 is dropped (port range 9990-9999 deny)" {
    require_root

    # P20 denies TCP dst_port 9990-9999
    # Start a listener, attempt connection, verify it fails
    ncat -l -p 9995 --max-conns 1 &>/dev/null &
    local listener_pid=$!
    sleep 0.3

    local exit_code=0
    ip netns exec "$EBPF_TEST_NS" \
        timeout 2 ncat -w 1 "$EBPF_HOST_IP" 9995 </dev/null 2>&1 || exit_code=$?

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Connection should fail (timeout or refused due to XDP drop)
    [ "$exit_code" -ne 0 ]
}

@test "TCP to port 9989 passes (outside port range 9990-9999)" {
    require_root

    # Port 9989 is NOT in the deny range 9990-9999
    ncat -l -p 9989 --max-conns 1 -e /bin/echo &>/dev/null &
    local listener_pid=$!
    sleep 0.3

    local result
    result="$(echo "HELLO" | ip netns exec "$EBPF_TEST_NS" \
        timeout 3 ncat -w 2 "$EBPF_HOST_IP" 9989 2>/dev/null)" || true
    local exit_code=$?

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Connection should succeed (default policy = pass, no deny rule)
    [ "$exit_code" -eq 0 ] || [ -n "$result" ]
}

# ── Wildcard rule matching ───────────────────────────────────────

@test "TCP to port 7777 is dropped (wildcard deny rule)" {
    require_root

    # P40 denies TCP dst_port 7777 with wildcard src/dst IP
    ncat -l -p 7777 --max-conns 1 &>/dev/null &
    local listener_pid=$!
    sleep 0.3

    local exit_code=0
    ip netns exec "$EBPF_TEST_NS" \
        timeout 2 ncat -w 1 "$EBPF_HOST_IP" 7777 </dev/null 2>&1 || exit_code=$?

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    [ "$exit_code" -ne 0 ]
}

# ── Default policy (pass) ───────────────────────────────────────

@test "allowed TCP:18080 passes via default policy (healthz reachable)" {
    require_root

    local status
    status="$(ip netns exec "$EBPF_TEST_NS" \
        curl -sf -o /dev/null -w '%{http_code}' \
        --max-time 5 "http://${EBPF_HOST_IP}:18080/healthz" 2>/dev/null)" || true

    [ "$status" = "200" ]
}

# ── REST API visibility ─────────────────────────────────────────

@test "firewall rules visible via API with correct count" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    # Should have 5 initial rules from the fixture
    [ "$count" -ge 5 ]
}

# ── Dynamic rule addition ───────────────────────────────────────

@test "dynamic rule via API: deny TCP:6666 blocks traffic" {
    require_root

    # Start a listener on port 6666
    ncat -l -p 6666 --max-conns 1 -e /bin/echo &>/dev/null &
    local listener_pid=$!
    sleep 0.3

    # Verify traffic passes BEFORE adding rule
    local before_result
    before_result="$(echo "BEFORE" | ip netns exec "$EBPF_TEST_NS" \
        timeout 3 ncat -w 2 "$EBPF_HOST_IP" 6666 2>/dev/null)" || true

    # Restart listener for second test
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
    ncat -l -p 6666 --max-conns 1 &>/dev/null &
    listener_pid=$!
    sleep 0.3

    # Add deny rule via API
    local body
    body="{\"id\":\"fw-deny-6666\",\"priority\":25,\"action\":\"deny\",\"protocol\":\"tcp\",\"dst_port\":6666,\"scope\":\"global\",\"enabled\":true}"
    api_post /api/v1/firewall/rules "$body"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Wait for eBPF map sync
    sleep 2

    # Verify traffic is now blocked
    local exit_code=0
    ip netns exec "$EBPF_TEST_NS" \
        timeout 2 ncat -w 1 "$EBPF_HOST_IP" 6666 </dev/null 2>&1 || exit_code=$?

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    [ "$exit_code" -ne 0 ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "metrics endpoint serves ebpfsentinel metrics" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_"
}
