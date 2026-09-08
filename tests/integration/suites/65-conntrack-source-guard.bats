#!/usr/bin/env bats
# 65-conntrack-source-guard.bats - Per-source connection guard scenarios
# Requires: root, kernel >= 6.9, bpftool, ncat
#
# The guard lives in xdp-firewall and is driven entirely by the conntrack
# section: max_src_conn_rate over conn_rate_window_secs, with a source that
# goes past it refused on the XDP fast path for overload_ttl_secs. This
# suite asserts the whole path, from the YAML keys to a dropped packet.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Two IPv6 sources inside one /64. The guard keys on the whole address, so
# these are two sources rather than one prefix, and the shared /64 is what
# makes that worth asserting.
EBPF_HOST_V6="fd00:65::1"
EBPF_NS_V6_A="fd00:65::2"
EBPF_NS_V6_B="fd00:65::3"
EBPF_V6_PREFIX_LEN="64"

# create_test_netns assigns IPv4 only, so the v6 addresses are layered on top
# of the veth pair it made rather than pushed into the shared helper.
_assign_v6_to_veth() {
    ip addr add "${EBPF_HOST_V6}/${EBPF_V6_PREFIX_LEN}" nodad \
        dev "${EBPF_VETH_HOST}" 2>/dev/null || true
    local addr
    for addr in "$EBPF_NS_V6_A" "$EBPF_NS_V6_B"; do
        ip netns exec "$EBPF_TEST_NS" \
            ip addr add "${addr}/${EBPF_V6_PREFIX_LEN}" nodad \
                dev "${EBPF_VETH_NS}" 2>/dev/null || true
    done
    # Even with DAD off, the addresses take a moment to leave tentative.
    sleep 1
}

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ctguard-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns
    _assign_v6_to_veth

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-conntrack-guard.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ctguard-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

# firewall_metric <action_label>
# Reads the cumulative xdp-firewall counter mirrored onto packets_total by
# the kernel metrics poll loop.
firewall_metric() {
    local action="${1:?usage: firewall_metric <action>}"

    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local body
    body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || return 1

    local value
    value="$(echo "$body" | grep "^ebpfsentinel_packets_total{" | \
        grep 'interface="FIREWALL_METRICS"' | \
        grep "action=\"${action}\"" | \
        awk '{print $2}' | head -1)"

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "0"
    else
        echo "${value%%.*}"
    fi
}

# knock <count>
# Opens <count> TCP connections from the namespace to the guarded port.
knock() {
    local count="${1:?usage: knock <count>}"
    local i=0
    while [ "$i" -lt "$count" ]; do
        send_tcp_from_ns "$EBPF_HOST_IP" 9971 "GUARD" 1
        i=$((i + 1))
    done
}

# knock_v6 <source_address> <count>
# The same knock over IPv6, from a source address the caller names, because
# the whole point is which of two neighbours is being judged.
knock_v6() {
    local src="${1:?usage: knock_v6 <source_address> <count>}"
    local count="${2:?usage: knock_v6 <source_address> <count>}"
    local i=0
    while [ "$i" -lt "$count" ]; do
        ip netns exec "$EBPF_TEST_NS" \
            timeout 2 ncat -6 -s "$src" -w 1 "$EBPF_HOST_V6" 9971 \
            </dev/null >/dev/null 2>&1 || true
        i=$((i + 1))
    done
}

# ── The guard is configurable at all ────────────────────────────────

@test "conntrack section carries the per-source guard" {
    require_root

    grep -q "max_src_conn_rate: 3" "$PREPARED_CONFIG"
    grep -q "conn_rate_window_secs: 60" "$PREPARED_CONFIG"
    grep -q "overload_ttl_secs: 3600" "$PREPARED_CONFIG"

    # The agent accepted those keys rather than starting on defaults.
    local body
    body="$(api_get /api/v1/conntrack/status)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(echo "$body" | jq -r '.enabled' 2>/dev/null)" = "true" ]
}

# ── The rate ceiling is enforced ────────────────────────────────────

@test "a source past the connection rate is dropped" {
    require_root

    local before
    before="$(firewall_metric "dropped")"

    # Three connections are inside the ceiling, the rest are not. Every one
    # of them matches the allow rule, so each reaches the guard.
    knock 12

    # The poll loop mirrors the kernel counters on its own interval.
    sleep 12

    local after
    after="$(firewall_metric "dropped")"
    local delta=$((after - before))

    echo "firewall dropped before=${before} after=${after} delta=${delta}"

    [ "$delta" -ge 1 ] || {
        echo "the guard let every connection through: no packet was dropped" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

# ── An overloaded source stays refused ──────────────────────────────

@test "an overloaded source keeps being refused on the fast path" {
    require_root

    # The previous test took this source past the ceiling, so the mark is
    # already set and its window is an hour wide. Everything sent now is
    # refused before a rule is looked at.
    local before
    before="$(firewall_metric "dropped")"

    knock 4

    sleep 12

    local after
    after="$(firewall_metric "dropped")"
    local delta=$((after - before))

    echo "firewall dropped before=${before} after=${after} delta=${delta}"

    [ "$delta" -ge 1 ] || {
        echo "an overloaded source was served again inside its overload window" >&2
        return 1
    }
}

# ── The ceiling is the whole address, not the prefix ────────────────

@test "a v6 source past the connection rate is dropped" {
    require_root

    local before
    before="$(firewall_metric "dropped")"

    knock_v6 "$EBPF_NS_V6_A" 12

    sleep 12

    local after
    after="$(firewall_metric "dropped")"
    local delta=$((after - before))

    echo "firewall dropped before=${before} after=${after} delta=${delta}"

    [ "$delta" -ge 1 ] || {
        echo "the guard let every v6 connection through: no packet was dropped" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

@test "a neighbour in the same /64 is judged on its own address" {
    require_root

    # The previous test took fd00:65::2 past the ceiling and left its mark
    # standing for an hour. fd00:65::3 shares its /64 and has sent nothing,
    # so a key that stopped at the prefix would refuse it here.
    local before
    before="$(firewall_metric "dropped")"

    # Three is the ceiling rather than past it, so nothing this source sends
    # is refused on its own account either.
    knock_v6 "$EBPF_NS_V6_B" 3

    sleep 12

    local after
    after="$(firewall_metric "dropped")"
    local delta=$((after - before))

    echo "firewall dropped before=${before} after=${after} delta=${delta}"

    [ "$delta" -eq 0 ] || {
        echo "a source was refused for its neighbour's traffic: the guard is keyed on the prefix" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}
