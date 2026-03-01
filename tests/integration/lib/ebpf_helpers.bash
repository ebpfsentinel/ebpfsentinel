#!/usr/bin/env bash
# ebpf_helpers.bash — Shared helpers for eBPF scenario tests (suites 11-15, 18-23)
#
# Agent launch strategy:
#   1. Local binary + local eBPF programs (cargo xtask ebpf-build)
#   2. Fallback: docker run with ebpfsentinel:latest (--network host --privileged)
#
# Provides:
#   - Skip guards (root, kernel version, tool availability)
#   - Network namespace / veth pair creation and teardown
#   - Packet generation wrappers (TCP, UDP, ICMP, SYN flood, iperf3)
#   - Config template preparation
#   - Alert / metrics polling helpers

EBPF_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source core helpers if not already loaded
if [ -z "${PROJECT_ROOT:-}" ]; then
    source "${EBPF_HELPERS_DIR}/helpers.bash"
fi

# ── Constants ────────────────────────────────────────────────────────

EBPF_TEST_NS="${EBPF_TEST_NS:-ebpf-test-ns}"
EBPF_VETH_HOST="${EBPF_VETH_HOST:-veth-ebpf0}"
EBPF_VETH_NS="${EBPF_VETH_NS:-veth-ebpf1}"
EBPF_HOST_IP="${EBPF_HOST_IP:-10.200.0.1}"
EBPF_NS_IP="${EBPF_NS_IP:-10.200.0.2}"
EBPF_SUBNET="${EBPF_SUBNET:-24}"

# Docker image for fallback agent launch
EBPF_DOCKER_IMAGE="${EBPF_DOCKER_IMAGE:-ebpfsentinel:latest}"

# Container name used when running via Docker
EBPF_DOCKER_CONTAINER="ebpfsentinel-test-$$"

# Tracks whether the agent was started via Docker (for stop_ebpf_agent)
EBPF_AGENT_VIA_DOCKER="false"

# ── Skip guards ──────────────────────────────────────────────────────

# require_root — skip test/suite if not running as root
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        skip "requires root privileges"
    fi
}

# require_kernel <major> <minor> — skip if kernel is older than given version
require_kernel() {
    local req_major="${1:-5}"
    local req_minor="${2:-17}"
    local kernel_major kernel_minor
    kernel_major="$(uname -r | cut -d. -f1)"
    kernel_minor="$(uname -r | cut -d. -f2)"
    if [ "$kernel_major" -lt "$req_major" ] || \
       { [ "$kernel_major" -eq "$req_major" ] && [ "$kernel_minor" -lt "$req_minor" ]; }; then
        skip "kernel $(uname -r) < ${req_major}.${req_minor}"
    fi
}

# require_tool <command> — skip if command is not in PATH
require_tool() {
    local tool="${1:?usage: require_tool <command>}"
    if ! command -v "$tool" &>/dev/null; then
        skip "${tool} not installed"
    fi
}

# _has_local_ebpf — returns 0 if local binary + eBPF programs exist
_has_local_ebpf() {
    local ebpf_dir="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -x "${PROJECT_ROOT}/target/release/ebpfsentinel-agent" ] && \
    [ -d "$ebpf_dir" ] && \
    [ -f "${ebpf_dir}/xdp-firewall" ]
}

# _has_docker_image — returns 0 if Docker image is available
_has_docker_image() {
    command -v docker &>/dev/null && \
    docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qF "$EBPF_DOCKER_IMAGE"
}

# require_ebpf_env — skip if neither local eBPF nor Docker image available
require_ebpf_env() {
    if _has_local_ebpf; then
        return 0
    fi
    if _has_docker_image; then
        return 0
    fi
    skip "no eBPF environment (no local build, no Docker image '${EBPF_DOCKER_IMAGE}')"
}

# ── Network namespace / veth pair management ─────────────────────────

# create_test_netns — creates a veth pair with one end in a network namespace
#   Host side: $EBPF_VETH_HOST  with $EBPF_HOST_IP/$EBPF_SUBNET
#   NS side:   $EBPF_VETH_NS    with $EBPF_NS_IP/$EBPF_SUBNET   inside $EBPF_TEST_NS
create_test_netns() {
    # Clean up any leftover state
    destroy_test_netns 2>/dev/null || true

    # Create namespace
    ip netns add "$EBPF_TEST_NS"

    # Create veth pair
    ip link add "$EBPF_VETH_HOST" type veth peer name "$EBPF_VETH_NS"

    # Move peer into namespace
    ip link set "$EBPF_VETH_NS" netns "$EBPF_TEST_NS"

    # Configure host side
    ip addr add "${EBPF_HOST_IP}/${EBPF_SUBNET}" dev "$EBPF_VETH_HOST"
    ip link set "$EBPF_VETH_HOST" up

    # Configure namespace side
    ip netns exec "$EBPF_TEST_NS" ip addr add "${EBPF_NS_IP}/${EBPF_SUBNET}" dev "$EBPF_VETH_NS"
    ip netns exec "$EBPF_TEST_NS" ip link set "$EBPF_VETH_NS" up
    ip netns exec "$EBPF_TEST_NS" ip link set lo up

    # Wait for interfaces to be fully up
    sleep 0.5
}

# destroy_test_netns — tear down namespace and veth pair
destroy_test_netns() {
    ip netns del "$EBPF_TEST_NS" 2>/dev/null || true
    ip link delete "$EBPF_VETH_HOST" 2>/dev/null || true
}

# ── Packet generation helpers ────────────────────────────────────────

# send_tcp_from_ns <dst_ip> <dst_port> [data] [timeout_secs]
send_tcp_from_ns() {
    local dst="${1:?usage: send_tcp_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: send_tcp_from_ns <dst_ip> <dst_port>}"
    local data="${3:-TESTDATA}"
    local timeout="${4:-2}"

    echo "$data" | ip netns exec "$EBPF_TEST_NS" \
        timeout "$timeout" ncat -w "$timeout" "$dst" "$port" 2>/dev/null || true
}

# send_udp_from_ns <dst_ip> <dst_port> [data] [timeout_secs]
send_udp_from_ns() {
    local dst="${1:?usage: send_udp_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: send_udp_from_ns <dst_ip> <dst_port>}"
    local data="${3:-TESTDATA}"
    local timeout="${4:-2}"

    echo "$data" | ip netns exec "$EBPF_TEST_NS" \
        timeout "$timeout" ncat -u -w "$timeout" "$dst" "$port" 2>/dev/null || true
}

# send_icmp_from_ns <dst_ip> [count] [timeout_secs]
send_icmp_from_ns() {
    local dst="${1:?usage: send_icmp_from_ns <dst_ip>}"
    local count="${2:-3}"
    local timeout="${3:-5}"

    ip netns exec "$EBPF_TEST_NS" \
        ping -c "$count" -W 1 -i 0.2 "$dst" 2>/dev/null || true
}

# hping3_flood_from_ns <dst_ip> <dst_port> [count] [interval]
hping3_flood_from_ns() {
    local dst="${1:?usage: hping3_flood_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: hping3_flood_from_ns <dst_ip> <dst_port>}"
    local count="${3:-100}"
    local interval="${4:-u1000}"   # microseconds between packets

    ip netns exec "$EBPF_TEST_NS" \
        hping3 -S -p "$port" -c "$count" -i "$interval" "$dst" 2>/dev/null || true
}

# iperf3_from_ns <dst_ip> [duration_secs] [protocol_flag] [extra_args...]
iperf3_from_ns() {
    local dst="${1:?usage: iperf3_from_ns <dst_ip> [duration] [proto_flag]}"
    local duration="${2:-5}"
    local proto="${3:-}"
    shift 3 2>/dev/null || true

    ip netns exec "$EBPF_TEST_NS" \
        iperf3 -c "$dst" -t "$duration" $proto --json "$@" 2>/dev/null
}

# ── Agent lifecycle (eBPF-aware) ─────────────────────────────────────

# start_ebpf_agent <config_file> [extra_args...]
# Tries local binary first, falls back to docker run.
# Set FORCE_DOCKER=true to skip local binary check and always use Docker.
# Sets EBPF_AGENT_VIA_DOCKER so stop_ebpf_agent knows how to clean up.
start_ebpf_agent() {
    local config_file="${1:?usage: start_ebpf_agent <config_file> [extra_args...]}"
    shift

    # Kill stale agent / container
    stop_ebpf_agent 2>/dev/null || true

    # Kill any process still listening on our ports
    _kill_port_holders "${AGENT_HTTP_PORT}" "${AGENT_GRPC_PORT}"

    local port_wait=0
    while { ss -tlnp 2>/dev/null | grep -qE ":(${AGENT_HTTP_PORT}|${AGENT_GRPC_PORT}) "; } && [ "$port_wait" -lt 10 ]; do
        sleep 0.3
        port_wait=$((port_wait + 1))
    done

    mkdir -p "$DATA_DIR"

    # ── Strategy 1: local binary with local eBPF programs ──
    if [ "${FORCE_DOCKER:-false}" != "true" ] && _has_local_ebpf; then
        EBPF_AGENT_VIA_DOCKER="false"
        export AGENT_BIN="${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
        export EBPF_PROGRAM_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
        echo "  [strategy] Using local binary: $AGENT_BIN" >&2

        EBPF_PROGRAM_DIR="${EBPF_PROGRAM_DIR}" \
        "$AGENT_BIN" --config "$config_file" "$@" \
            >"$AGENT_LOG_FILE" 2>&1 &
        AGENT_PID=$!
        echo "$AGENT_PID" > "$AGENT_PID_FILE"

    # ── Strategy 2: docker run with --network host ──
    elif _has_docker_image; then
        EBPF_AGENT_VIA_DOCKER="true"
        echo "  [strategy] Using Docker container: $EBPF_DOCKER_IMAGE" >&2

        # Stop leftover container with same name
        docker rm -f "$EBPF_DOCKER_CONTAINER" >/dev/null 2>&1 || true

        docker run -d \
            --name "$EBPF_DOCKER_CONTAINER" \
            --network host \
            --privileged \
            -v "${config_file}:${config_file}:ro" \
            -v "${DATA_DIR}:${DATA_DIR}" \
            -v /sys/fs/bpf:/sys/fs/bpf \
            -v /sys/kernel/debug:/sys/kernel/debug:ro \
            "$EBPF_DOCKER_IMAGE" \
            --config "$config_file" "$@" >/dev/null

        # Write container PID for process checks
        sleep 0.5
        AGENT_PID="$(docker inspect --format '{{.State.Pid}}' "$EBPF_DOCKER_CONTAINER" 2>/dev/null)" || true
        echo "${AGENT_PID:-0}" > "$AGENT_PID_FILE"

        # Mirror Docker logs to AGENT_LOG_FILE for debug access
        docker logs -f "$EBPF_DOCKER_CONTAINER" >"$AGENT_LOG_FILE" 2>&1 &

    else
        echo "No local eBPF build and no Docker image — cannot start agent" >&2
        return 1
    fi

    # Wait for agent to be ready
    sleep 0.3
    wait_for_agent >/dev/null || {
        echo "Agent failed to start. Log:" >&2
        if [ "$EBPF_AGENT_VIA_DOCKER" = "true" ]; then
            docker logs "$EBPF_DOCKER_CONTAINER" 2>&1 | tail -20 >&2
        else
            tail -20 "$AGENT_LOG_FILE" >&2
        fi
        return 1
    }
}

# stop_ebpf_agent — stop agent launched by start_ebpf_agent
stop_ebpf_agent() {
    if [ "${EBPF_AGENT_VIA_DOCKER}" = "true" ]; then
        docker rm -f "$EBPF_DOCKER_CONTAINER" >/dev/null 2>&1 || true
        rm -f "$AGENT_PID_FILE"
        EBPF_AGENT_VIA_DOCKER="false"
    else
        stop_agent 2>/dev/null || true
    fi
}

# start_ebpf_agent_docker <config_file> [extra_args...]
# Forces Docker launch (skips _has_local_ebpf check).
# Convenience wrapper for performance tests that always test the Docker path.
start_ebpf_agent_docker() {
    FORCE_DOCKER=true start_ebpf_agent "$@"
}

# ── Config preparation ──────────────────────────────────────────────

# prepare_ebpf_config <fixture_file> [output_file]
# Substitutes __INTERFACE__, __DATA_DIR__, __EBPF_DIR__ placeholders.
# Returns path to prepared config.
prepare_ebpf_config() {
    local fixture="${1:?usage: prepare_ebpf_config <fixture_file>}"
    local output="${2:-/tmp/ebpfsentinel-test-ebpf-$$.yaml}"

    local data_dir="${DATA_DIR:-/tmp/ebpfsentinel-test-data-$$}"
    local ebpf_dir="${EBPF_PROGRAM_DIR:-${PROJECT_ROOT}/target/bpfel-unknown-none/release}"

    mkdir -p "$data_dir"

    local whitelist_subnet="${WHITELIST_SUBNET:-10.200.0.0/24}"

    sed -e "s|__INTERFACE__|${EBPF_VETH_HOST}|g" \
        -e "s|__DATA_DIR__|${data_dir}|g" \
        -e "s|__EBPF_DIR__|${ebpf_dir}|g" \
        -e "s|__WHITELIST_SUBNET__|${whitelist_subnet}|g" \
        "$fixture" > "$output"

    echo "$output"
}

# ── Polling helpers ─────────────────────────────────────────────────

# wait_for_alert <jq_filter> [max_attempts] [interval_secs]
# The alerts API returns {"alerts": [...], ...}. The filter is applied to
# the unwrapped .alerts array so callers can use `.[] | select(...)`.
wait_for_alert() {
    local filter="${1:?usage: wait_for_alert <jq_filter>}"
    local max="${2:-30}"
    local interval="${3:-1}"
    local attempt=0

    while [ "$attempt" -lt "$max" ]; do
        local body
        body="$(api_get /api/v1/alerts 2>/dev/null)" || true
        if [ -n "$body" ]; then
            local alerts
            alerts="$(echo "$body" | jq '.alerts // .' 2>/dev/null)" || alerts="$body"
            local match
            match="$(echo "$alerts" | jq -r "$filter" 2>/dev/null)" || true
            if [ -n "$match" ] && [ "$match" != "null" ]; then
                echo "$match"
                return 0
            fi
        fi
        sleep "$interval"
        attempt=$((attempt + 1))
    done
    return 1
}

# get_blacklist_count [max_attempts]
get_blacklist_count() {
    local max="${1:-5}"
    local attempt=0

    while [ "$attempt" -lt "$max" ]; do
        local body
        body="$(api_get /api/v1/ips/blacklist 2>/dev/null)" || true
        if [ -n "$body" ]; then
            local count
            count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
            if [ -n "$count" ] && [ "$count" != "null" ]; then
                echo "$count"
                return 0
            fi
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "0"
}

# get_metrics_value <metric_name> [label_filter]
get_metrics_value() {
    local metric="${1:?usage: get_metrics_value <metric_name>}"
    local label_filter="${2:-}"

    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local body
    body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || return 1

    if [ -n "$label_filter" ]; then
        echo "$body" | grep "^${metric}${label_filter}" | awk '{print $2}' | head -1
    else
        echo "$body" | grep "^${metric}" | head -1 | awk '{print $2}'
    fi
}

# wait_for_metric <metric_name> [min_value] [max_attempts] [label_filter]
wait_for_metric() {
    local metric="${1:?usage: wait_for_metric <metric_name>}"
    local min_value="${2:-1}"
    local max="${3:-30}"
    local label_filter="${4:-}"
    local attempt=0

    while [ "$attempt" -lt "$max" ]; do
        local value
        value="$(get_metrics_value "$metric" "$label_filter")" || true
        if [ -n "$value" ] && [ "$(echo "$value >= $min_value" | bc -l 2>/dev/null)" = "1" ]; then
            echo "$value"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

# wait_for_ebpf_loaded [max_attempts]
# Polls /readyz until ebpf_loaded is true.
wait_for_ebpf_loaded() {
    local max="${1:-30}"
    local attempt=0

    while [ "$attempt" -lt "$max" ]; do
        local body
        body="$(api_get /readyz 2>/dev/null)" || true
        local loaded
        loaded="$(echo "$body" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
        if [ "$loaded" = "true" ]; then
            return 0
        fi
        # Early exit: if agent is healthy but ebpf_loaded is explicitly false,
        # it's running in degraded mode (eBPF programs not available).
        if [ -n "$body" ] && [ "$loaded" = "false" ]; then
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}
