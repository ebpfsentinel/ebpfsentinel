#!/usr/bin/env bats
# 153-xdp-multi-buffer-frames.bats - XDP verdicts on frames larger than one buffer
# Requires: root, kernel >= 6.18, jq, python3
#
# The XDP programs load declaring multi-buffer frames where the kernel lets
# them pull the head of such a frame into its first buffer
# (bpf_xdp_pull_data), which the agent reports as the xdp_pull_data
# capability. The suite asserts:
#
#   * The kernel-features route reports the capability on the lane's kernel,
#     and the start-up log does not say the XDP programs fell back.
#   * With the veth pair at a 9000-byte MTU, the firewall attaches in driver
#     mode: a program that does not declare multi-buffer frames is refused
#     there by the veth driver.
#   * An 8000-byte datagram to a refused port is dropped in XDP and counted,
#     and one to any other port is delivered whole.
#   * The frags_pulled counter is published beside the firewall's others.
#
# A veth keeps a frame's headers in its first buffer, so the pull itself
# never fires here: the counter is read for its presence, not its value.

load '../lib/helpers'
load '../lib/ebpf_helpers'

DENIED_PORT=9555
OPEN_PORT=9556
JUMBO_MTU=9000
DATAGRAM=8000

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-multi-buffer-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns
    # Both ends before the agent attaches: the veth driver checks the MTU
    # against the program's declaration when the program attaches.
    ip link set dev "$EBPF_VETH_HOST" mtu "$JUMBO_MTU"
    ip netns exec "$EBPF_TEST_NS" ip link set dev "$EBPF_VETH_NS" mtu "$JUMBO_MTU"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-jumbo-frames.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_counters FIREWALL_METRICS 30 || return 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-multi-buffer-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

# receive_one <port> <out> - wait up to 5 seconds on the host for one UDP
# datagram on <port>, and write its length to <out> (nothing on a timeout).
# Run in the background, so the datagram is sent while it waits.
receive_one() {
    python3 - "$EBPF_HOST_IP" "$1" >"$2" 2>/dev/null <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.settimeout(5)
try:
    data, _ = s.recvfrom(65535)
    print(len(data))
except socket.timeout:
    pass
PY
}

# send_jumbo <port> - one DATAGRAM-byte UDP datagram from the namespace,
# sent with the don't-fragment bit so it leaves as one frame.
send_jumbo() {
    ip netns exec "$EBPF_TEST_NS" python3 - "$EBPF_HOST_IP" "$1" "$DATAGRAM" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2: refuse to fragment.
s.setsockopt(socket.IPPROTO_IP, 10, 2)
s.sendto(b"\x00" * int(sys.argv[3]), (sys.argv[1], int(sys.argv[2])))
PY
}

# ── The capability ─────────────────────────────────────────────────

@test "the kernel-features route reports xdp_pull_data active" {
    local body entry
    body="$(api_get /api/v1/ebpf/kernel-features)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    entry="$(echo "$body" | jq -c '.capabilities[] | select(.id == "xdp_pull_data")')"
    [ -n "$entry" ] || {
        echo "the route does not answer xdp_pull_data" >&2
        return 1
    }
    echo "$entry" | jq -e '.active == true' >/dev/null || {
        echo "xdp_pull_data is off on this kernel: ${entry}" >&2
        return 1
    }
    ! grep -q 'bpf_xdp_pull_data is not usable here' "$AGENT_LOG_FILE"
}

@test "the firewall attaches in driver mode on a 9000-byte link" {
    local link
    link="$(ip -d link show dev "$EBPF_VETH_HOST")"
    echo "$link"
    echo "$link" | grep -Eq 'mtu 9000'
    # `xdp` alone is driver mode; generic mode prints `xdpgeneric`.
    echo "$link" | grep -Eq '(^| )xdp( |$)|prog/xdp id' || {
        echo "no driver-mode XDP program on ${EBPF_VETH_HOST}" >&2
        return 1
    }
    ! echo "$link" | grep -q 'xdpgeneric'
}

# ── Verdicts on multi-buffer frames ────────────────────────────────

@test "a jumbo datagram to an open port is delivered whole" {
    local out="${DATA_DIR}/open.len" pid
    receive_one "$OPEN_PORT" "$out" &
    pid=$!
    sleep 0.5
    send_jumbo "$OPEN_PORT"
    wait "$pid" || true
    echo "received=$(cat "$out")"
    [ "$(cat "$out")" = "$DATAGRAM" ]
}

@test "a jumbo datagram to a refused port is dropped in XDP and counted" {
    local out="${DATA_DIR}/denied.len" pid before after
    before="$(ebpf_counter FIREWALL_METRICS dropped)"
    receive_one "$DENIED_PORT" "$out" &
    pid=$!
    sleep 0.5
    send_jumbo "$DENIED_PORT"
    wait "$pid" || true
    [ ! -s "$out" ] || {
        echo "the refused port received $(cat "$out") bytes" >&2
        return 1
    }
    after="$(ebpf_counter_above FIREWALL_METRICS dropped "${before:-0}")"
    [ "$after" -gt "${before:-0}" ] || {
        dump_ebpf_counters FIREWALL_METRICS >&2
        return 1
    }
}

@test "the frags_pulled counter is published with the firewall's others" {
    scrape_metrics | grep -q 'interface="FIREWALL_METRICS",action="frags_pulled"' || {
        dump_ebpf_counters FIREWALL_METRICS >&2
        return 1
    }
}
