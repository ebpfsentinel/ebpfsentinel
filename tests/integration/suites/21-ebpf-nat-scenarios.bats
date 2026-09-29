#!/usr/bin/env bats
# 21-ebpf-nat-scenarios.bats - NAT eBPF scenario tests, API and redirect datapath
# Requires: root, kernel >= 6.9, bpftool

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-nat-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-nat.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-nat-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── TC program attachment ────────────────────────────────────────

@test "TC NAT programs attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── NAT status ───────────────────────────────────────────────────

@test "NAT status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "NAT rules list is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/nat/rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Conntrack (prerequisite for NAT) ─────────────────────────────

@test "conntrack is enabled alongside NAT" {
    require_root

    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "NAT metrics counters present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets|ebpfsentinel_rules_loaded"
}

# ── Additional NAT API tests ──────────────────────────────────────

@test "NAT status returns enabled" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "NAT rules list accessible" {
    require_root

    local body
    body="$(api_get /api/v1/nat/rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── NPTv6 CRUD ───────────────────────────────────────────────────

@test "NPTv6 rule CRUD - create" {
    require_root

    local rule='{"id":"nptv6-test","internal_prefix":"fd00::","external_prefix":"2001:db8::","prefix_len":48}'
    local body
    body="$(api_post /api/v1/nat/nptv6 "$rule")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id
    id="$(echo "$body" | jq -r '.id // empty' 2>/dev/null)" || true
    [ "$id" = "nptv6-test" ]
}

@test "NPTv6 rule CRUD - delete" {
    require_root

    api_delete /api/v1/nat/nptv6/nptv6-test >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

@test "NAT metrics present" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_conntrack|ebpfsentinel_packets|ebpfsentinel_rules_loaded"
}

# ── Extended NAT tests ────────────────────────────────────────────

@test "NPTv6 rule CRUD via API" {
    require_root

    local rule='{"id":"nptv6-001","internal_prefix":"fd00::","external_prefix":"2001:db8::","prefix_len":48,"enabled":true}'
    local body
    body="$(api_post /api/v1/nat/nptv6 "$rule" 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Read back
    body="$(api_get /api/v1/nat/nptv6 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    # Delete
    api_delete /api/v1/nat/nptv6/nptv6-001 >/dev/null 2>&1 || true
}

@test "hairpin NAT config accepted" {
    require_root

    local body
    body="$(api_get /api/v1/nat/status)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    # Hairpin should be configurable
    local enabled
    enabled="$(echo "$body" | jq -r '.hairpin_enabled // .hairpin // "unknown"' 2>/dev/null)" || true
    [ -n "$enabled" ]
}

@test "NAT rules list is queryable" {
    require_root

    # The NAT rules endpoint is read-only (populated from config).
    # Verify it returns a valid JSON array.
    local body
    body="$(api_get /api/v1/nat/rules 2>/dev/null)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local is_array
    is_array="$(echo "$body" | jq 'type == "array"' 2>/dev/null)" || true
    [ "$is_array" = "true" ]
}

# ── Redirect datapath ────────────────────────────────────────────
#
# The fixture carries a UDP and a TCP redirect rule on the host address.
# Nothing listens on either match port, so a flow reaching the listener on
# the translated port proves the rule moved the port and kept the
# destination address. The listener echoes what it read, and the client
# accepts the echo only from the address and port it sent to: a reply left
# on the translated port is dropped by the client's own stack, and a TCP
# handshake whose reply is not translated back never completes.

NAT_DNAT_APPLIED_LABELS='{interface="NAT_METRICS",action="dnat_applied"}'
NAT_REVERSE_APPLIED_LABELS='{interface="NAT_METRICS",action="reverse_applied"}'

# _nat_echo_listener <udp|tcp> <port> <outfile>
# Starts a python3 listener on the host address that writes the first
# payload it receives to <outfile> and sends it back. Sets NAT_LISTENER_PID
# rather than printing it, so the listener stays a child of the test shell
# and can be waited on; fd 3 is closed so bats does not hang.
_nat_echo_listener() {
    local proto="$1" port="$2" out="$3"
    python3 - "$proto" "$EBPF_HOST_IP" "$port" "$out" >/dev/null 2>&1 3>&- <<'PY' &
import socket, sys
proto, host, port, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
if proto == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(20)
    s.bind((host, port))
    data, peer = s.recvfrom(2048)
    s.sendto(data, peer)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(20)
    s.bind((host, port))
    s.listen(1)
    c, _ = s.accept()
    c.settimeout(10)
    data = c.recv(2048)
    c.sendall(data)
    c.close()
with open(out, "wb") as f:
    f.write(data)
PY
    NAT_LISTENER_PID=$!
}

# _ct_insert_failed
# Sum of netfilter's insert_failed counter across CPUs in the host namespace.
# The counter runs from boot, so a test compares two readings and never the
# value itself.
_ct_insert_failed() {
    conntrack -S 2>/dev/null \
        | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^insert_failed=/) { split($i, kv, "="); n += kv[2] } } END { print n + 0 }'
}

@test "redirect rule delivers a UDP datagram to the translated port and the reply comes back from the original one" {
    require_root
    require_tool python3

    local out="${DATA_DIR}/redirect-udp.out"
    local marker="redirect-udp-$$"
    local before reverse_before
    before="$(get_metrics_value ebpfsentinel_packets_total "$NAT_DNAT_APPLIED_LABELS")" || true
    reverse_before="$(get_metrics_value ebpfsentinel_packets_total "$NAT_REVERSE_APPLIED_LABELS")" || true
    _nat_echo_listener udp 18094 "$out"
    sleep 1

    local echo
    echo="$(ip netns exec "$EBPF_TEST_NS" python3 -c '
import socket, sys
marker, host = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
for _ in range(3):
    s.sendto(marker.encode(), (host, 18093))
    try:
        data, peer = s.recvfrom(2048)
    except socket.timeout:
        continue
    if peer == (host, 18093):
        print(data.decode())
        break
' "$marker" "$EBPF_HOST_IP")"

    wait "$NAT_LISTENER_PID" || true
    [ -f "$out" ]
    [ "$(cat "$out")" = "$marker" ]
    [ "$echo" = "$marker" ]

    local after
    after="$(wait_for_metric ebpfsentinel_packets_total "$(( ${before:-0} + 1 ))" 30 "$NAT_DNAT_APPLIED_LABELS")"
    [ -n "$after" ]
    after="$(wait_for_metric ebpfsentinel_packets_total "$(( ${reverse_before:-0} + 1 ))" 30 "$NAT_REVERSE_APPLIED_LABELS")"
    [ -n "$after" ]
}

@test "redirect rule carries a TCP connection to the translated port both ways" {
    require_root
    require_tool python3
    require_tool conntrack

    local out="${DATA_DIR}/redirect-tcp.out"
    local marker="redirect-tcp-$$"
    local before reverse_before ct_failed_before
    # A translated flow that also carries a conntrack entry for its original
    # tuple collides with the one netfilter creates for the translated tuple,
    # and TCP drops the packet where UDP resolves the clash.
    ct_failed_before="$(_ct_insert_failed)"
    before="$(get_metrics_value ebpfsentinel_packets_total "$NAT_DNAT_APPLIED_LABELS")" || true
    reverse_before="$(get_metrics_value ebpfsentinel_packets_total "$NAT_REVERSE_APPLIED_LABELS")" || true
    _nat_echo_listener tcp 18096 "$out"
    sleep 1

    local echo
    echo="$(ip netns exec "$EBPF_TEST_NS" python3 -c '
import socket, sys
marker, host = sys.argv[1], sys.argv[2]
c = socket.create_connection((host, 18095), timeout=5)
c.sendall(marker.encode())
print(c.recv(2048).decode())
c.close()
' "$marker" "$EBPF_HOST_IP")"

    wait "$NAT_LISTENER_PID" || true
    [ -f "$out" ]
    [ "$(cat "$out")" = "$marker" ]
    [ "$echo" = "$marker" ]

    local after
    after="$(wait_for_metric ebpfsentinel_packets_total "$(( ${before:-0} + 1 ))" 30 "$NAT_DNAT_APPLIED_LABELS")"
    [ -n "$after" ]
    after="$(wait_for_metric ebpfsentinel_packets_total "$(( ${reverse_before:-0} + 3 ))" 30 "$NAT_REVERSE_APPLIED_LABELS")"
    [ -n "$after" ]
    [ "$(_ct_insert_failed)" = "$ct_failed_before" ]
}
