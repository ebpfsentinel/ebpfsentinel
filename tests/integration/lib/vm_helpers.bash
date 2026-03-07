#!/usr/bin/env bash
# vm_helpers.bash — Cross-VM test helpers for 2-VM topology
#
# Sourced automatically by ebpf_helpers.bash when EBPF_2VM_MODE=true.
# Overrides network namespace, agent lifecycle, and packet generation
# functions to work across the private network (192.168.56.0/24).
#
# Topology:
#   Agent VM   (192.168.56.10) — runs ebpfsentinel-agent, reached via SSH
#   Attacker VM (192.168.56.20) — runs BATS tests, sends traffic locally

VM_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Constants (override) ──────────────────────────────────────────
AGENT_VM_IP="${AGENT_VM_IP:-192.168.56.10}"
ATTACKER_VM_IP="${ATTACKER_VM_IP:-192.168.56.20}"
AGENT_SSH_KEY="${AGENT_SSH_KEY:-${HOME}/.ssh/agent_key}"
AGENT_SSH_CMD="ssh -i ${AGENT_SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 vagrant@${AGENT_VM_IP}"

# Override host/URL to point at agent VM
AGENT_HOST="${AGENT_VM_IP}"
BASE_URL="http://${AGENT_VM_IP}:${AGENT_HTTP_PORT}"
TLS_URL="https://${AGENT_VM_IP}:${AGENT_TLS_PORT}"
GRPC_ADDR="${AGENT_VM_IP}:${AGENT_GRPC_PORT}"

# The agent's interface on the private network
EBPF_AGENT_INTERFACE="eth1"
# For iperf3/ping from attacker, target the agent VM IP directly
EBPF_HOST_IP="${AGENT_VM_IP}"
EBPF_NS_IP="${ATTACKER_VM_IP}"

# Remote paths on agent VM
_REMOTE_CONFIG_DIR="/tmp/ebpfsentinel-test-configs"
_REMOTE_DATA_DIR="/tmp/ebpfsentinel-test-data"
_REMOTE_LOG_FILE="/tmp/ebpfsentinel-test.log"
_REMOTE_PID_FILE="/tmp/ebpfsentinel-test.pid"

# ── SSH helper ────────────────────────────────────────────────────

# _agent_ssh <command...>
# Runs a command on the agent VM via SSH. Returns the remote exit code.
_agent_ssh() {
    if [ $# -eq 0 ]; then
        echo "usage: _agent_ssh <command...>" >&2
        return 1
    fi
    $AGENT_SSH_CMD -- "$@"
}

# _agent_ssh_sudo <command...>
# Runs a command on the agent VM via SSH with sudo.
_agent_ssh_sudo() {
    if [ $# -eq 0 ]; then
        echo "usage: _agent_ssh_sudo <command...>" >&2
        return 1
    fi
    $AGENT_SSH_CMD -- sudo "$@"
}

# _agent_scp <local_path> <remote_path>
# Copies a file to the agent VM.
_agent_scp() {
    local local_path="${1:?usage: _agent_scp <local_path> <remote_path>}"
    local remote_path="${2:?usage: _agent_scp <local_path> <remote_path>}"

    scp -i "${AGENT_SSH_KEY}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$local_path" "vagrant@${AGENT_VM_IP}:${remote_path}"
}

# ── Skip guards (overrides) ──────────────────────────────────────

# require_root — no-op in 2VM mode; root operations happen on agent VM via SSH
require_root() {
    :
}

# require_ebpf_env — verify SSH connectivity to agent VM instead of
# checking for local binary/Docker image
require_ebpf_env() {
    if ! _agent_ssh true 2>/dev/null; then
        skip "cannot SSH to agent VM at ${AGENT_VM_IP} (EBPF_2VM_MODE)"
    fi
    # Verify the agent binary exists on the remote host
    if ! _agent_ssh test -x /usr/local/bin/ebpfsentinel-agent 2>/dev/null; then
        skip "ebpfsentinel-agent not found on agent VM ${AGENT_VM_IP}"
    fi
}

# require_tool — in 2VM mode, check tool availability on the agent VM
# for privileged tools (bpftool, ip, tc), check on attacker for others
require_tool() {
    local tool="${1:?usage: require_tool <command>}"
    case "$tool" in
        bpftool|tc)
            if ! _agent_ssh_sudo which "$tool" &>/dev/null; then
                skip "${tool} not installed on agent VM"
            fi
            ;;
        *)
            if ! command -v "$tool" &>/dev/null; then
                skip "${tool} not installed"
            fi
            ;;
    esac
}

# ── Remote command wrappers ──────────────────────────────────────

# bpftool — wrapper that runs bpftool on the agent VM via SSH
bpftool() {
    _agent_ssh_sudo bpftool "$@"
}

# Override EBPF_VETH_HOST to match the agent VM's private network interface
EBPF_VETH_HOST="${EBPF_AGENT_INTERFACE}"

# ── Network namespace (overrides — no-ops) ────────────────────────

# create_test_netns — no-op in 2VM mode.
# The private network (192.168.56.0/24) IS the test network.
create_test_netns() {
    :
}

# destroy_test_netns — no-op in 2VM mode.
destroy_test_netns() {
    :
}

# ── Config preparation (override) ────────────────────────────────

# prepare_ebpf_config <fixture_file> [output_file]
# Same as original but substitutes __INTERFACE__ with eth1 (the agent VM's
# private network interface). The prepared config stays local; it will be
# scp'd to the agent VM by start_ebpf_agent.
prepare_ebpf_config() {
    local fixture="${1:?usage: prepare_ebpf_config <fixture_file>}"
    local output="${2:-/tmp/ebpfsentinel-test-ebpf-$$.yaml}"

    local data_dir="${_REMOTE_DATA_DIR}"
    local ebpf_dir="${EBPF_PROGRAM_DIR:-/usr/local/lib/ebpfsentinel/ebpf}"

    local whitelist_subnet="${WHITELIST_SUBNET:-192.168.56.0/24}"

    sed -e "s|__INTERFACE__|${EBPF_AGENT_INTERFACE}|g" \
        -e "s|__DATA_DIR__|${data_dir}|g" \
        -e "s|__EBPF_DIR__|${ebpf_dir}|g" \
        -e "s|__WHITELIST_SUBNET__|${whitelist_subnet}|g" \
        "$fixture" > "$output"

    echo "$output"
}

# ── Agent lifecycle (overrides) ──────────────────────────────────

# start_agent <config_file> [extra_args...]
# Overrides helpers.bash start_agent to run the agent on the agent VM via SSH.
start_agent() {
    local config_file="${1:?usage: start_agent <config_file> [extra_args...]}"
    shift

    # Reuse start_ebpf_agent — in 2VM mode both do the same thing
    start_ebpf_agent "$config_file" "$@"
}

# stop_agent — overrides helpers.bash stop_agent
stop_agent() {
    stop_ebpf_agent "$@"
}

# signal_agent <signal>
# Sends a signal to the remote agent process.
signal_agent() {
    local sig="${1:?usage: signal_agent <signal>}"
    local remote_pid
    remote_pid="$(_agent_ssh cat "${_REMOTE_PID_FILE}" 2>/dev/null)" || true
    if [ -z "$remote_pid" ] && [ -f "$AGENT_PID_FILE" ]; then
        remote_pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)"
    fi
    if [ -n "$remote_pid" ]; then
        _agent_ssh_sudo kill "-${sig}" "$remote_pid" 2>/dev/null || true
    fi
}

# wait_for_agent_exit [max_secs]
# Waits for the remote agent process to exit.
wait_for_agent_exit() {
    local max="${1:-10}"
    local remote_pid
    remote_pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
    [ -z "$remote_pid" ] && return 0

    local waited=0
    while _agent_ssh_sudo kill -0 "$remote_pid" 2>/dev/null && [ "$waited" -lt "$max" ]; do
        sleep 0.2
        waited=$((waited + 1))
    done
    ! _agent_ssh_sudo kill -0 "$remote_pid" 2>/dev/null
}

# start_agent_expect_fail <config_file> [extra_args...]
# Overrides helpers.bash — runs the agent on the agent VM, expects non-zero exit.
start_agent_expect_fail() {
    local config_file="${1:?usage: start_agent_expect_fail <config_file>}"
    shift

    # Copy config to agent VM
    _agent_ssh_sudo mkdir -p "${_REMOTE_CONFIG_DIR}" 2>/dev/null || true
    _agent_ssh_sudo chown vagrant:vagrant "${_REMOTE_CONFIG_DIR}" 2>/dev/null || true
    local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "$config_file")"
    _agent_scp "$config_file" "$remote_config" 2>/dev/null || {
        # If config doesn't exist locally (e.g. nonexistent file test), pass the path through
        remote_config="$config_file"
    }

    local extra_args=""
    for arg in "$@"; do
        extra_args="${extra_args} $(printf '%q' "$arg")"
    done

    _agent_ssh_sudo /usr/local/bin/ebpfsentinel-agent --config "$remote_config" $extra_args 2>/dev/null
    local exit_code=$?
    return $exit_code
}

# start_ebpf_agent <config_file> [extra_args...]
# Copies config to agent VM, starts the agent via SSH, waits for healthz.
start_ebpf_agent() {
    local config_file="${1:?usage: start_ebpf_agent <config_file> [extra_args...]}"
    shift

    # Kill stale agent on remote
    stop_ebpf_agent 2>/dev/null || true

    # Ensure remote directories exist
    _agent_ssh_sudo mkdir -p "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true
    _agent_ssh_sudo chown vagrant:vagrant "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true

    # Rewrite local data paths to remote data paths in the config before SCP
    local rewritten_config="/tmp/ebpfsentinel-2vm-rewritten-$$.yaml"
    sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
        "$config_file" > "$rewritten_config"

    # Copy rewritten config file to agent VM
    local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "$config_file")"
    _agent_scp "$rewritten_config" "$remote_config" || {
        rm -f "$rewritten_config"
        echo "Failed to scp config to agent VM" >&2
        return 1
    }
    rm -f "$rewritten_config"

    # Build the extra args string (properly quoted)
    local extra_args=""
    for arg in "$@"; do
        extra_args="${extra_args} $(printf '%q' "$arg")"
    done

    # Start agent on remote host via SSH
    # We use nohup + redirect so the process survives SSH disconnect.
    _agent_ssh_sudo bash -c \
        "'nohup /usr/local/bin/ebpfsentinel-agent --config ${remote_config}${extra_args} >${_REMOTE_LOG_FILE} 2>&1 & echo \$! > ${_REMOTE_PID_FILE}'" || {
        echo "Failed to start agent on agent VM" >&2
        return 1
    }

    # Brief pause to let the agent fork
    sleep 0.5

    # Retrieve the remote PID for local tracking
    local remote_pid
    remote_pid="$(_agent_ssh cat "${_REMOTE_PID_FILE}" 2>/dev/null)" || true
    if [ -z "$remote_pid" ]; then
        echo "Failed to read agent PID from agent VM" >&2
        _agent_ssh cat "${_REMOTE_LOG_FILE}" 2>&1 | tail -20 >&2
        return 1
    fi

    # Verify the process is still alive on the remote
    if ! _agent_ssh_sudo kill -0 "$remote_pid" 2>/dev/null; then
        echo "Agent process exited immediately on agent VM. Remote log:" >&2
        _agent_ssh cat "${_REMOTE_LOG_FILE}" 2>&1 | tail -20 >&2
        return 1
    fi

    # Write PID locally for tracking
    AGENT_PID="$remote_pid"
    echo "$AGENT_PID" > "$AGENT_PID_FILE"
    EBPF_AGENT_VIA_DOCKER="false"

    echo "  [strategy] 2VM: agent started on ${AGENT_VM_IP} (PID ${remote_pid})" >&2

    # Wait for agent to be healthy at the agent VM's HTTP endpoint
    wait_for_agent "http://${AGENT_VM_IP}:${AGENT_HTTP_PORT}/healthz" >/dev/null || {
        echo "Agent failed health check on ${AGENT_VM_IP}. Remote log:" >&2
        _agent_ssh cat "${_REMOTE_LOG_FILE}" 2>&1 | tail -20 >&2
        return 1
    }
}

# stop_ebpf_agent — stop agent running on the agent VM via SSH
stop_ebpf_agent() {
    local remote_pid
    remote_pid="$(_agent_ssh cat "${_REMOTE_PID_FILE}" 2>/dev/null)" || true

    if [ -z "$remote_pid" ]; then
        # No PID file on remote; try the local tracking file
        if [ -f "$AGENT_PID_FILE" ]; then
            remote_pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)"
        fi
    fi

    if [ -n "$remote_pid" ]; then
        # Graceful SIGTERM
        _agent_ssh_sudo kill -TERM "$remote_pid" 2>/dev/null || true

        # Wait for shutdown
        local waited=0
        while _agent_ssh_sudo kill -0 "$remote_pid" 2>/dev/null && [ "$waited" -lt "${AGENT_STOP_TIMEOUT:-5}" ]; do
            sleep 0.5
            waited=$((waited + 1))
        done

        # Fallback SIGKILL
        if _agent_ssh_sudo kill -0 "$remote_pid" 2>/dev/null; then
            _agent_ssh_sudo kill -KILL "$remote_pid" 2>/dev/null || true
            sleep 0.5
        fi
    fi

    # Clean up remote PID file
    _agent_ssh_sudo rm -f "${_REMOTE_PID_FILE}" 2>/dev/null || true

    # Clean up local PID file
    rm -f "$AGENT_PID_FILE"
    unset AGENT_PID
}

# ── Packet generation helpers (overrides — no netns, run locally) ─

# send_tcp_from_ns <dst_ip> <dst_port> [data] [timeout_secs]
send_tcp_from_ns() {
    local dst="${1:?usage: send_tcp_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: send_tcp_from_ns <dst_ip> <dst_port>}"
    local data="${3:-TESTDATA}"
    local timeout="${4:-2}"

    echo "$data" | timeout "$timeout" ncat -w "$timeout" "$dst" "$port" 2>/dev/null || true
}

# send_udp_from_ns <dst_ip> <dst_port> [data] [timeout_secs]
send_udp_from_ns() {
    local dst="${1:?usage: send_udp_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: send_udp_from_ns <dst_ip> <dst_port>}"
    local data="${3:-TESTDATA}"
    local timeout="${4:-2}"

    echo "$data" | timeout "$timeout" ncat -u -w "$timeout" "$dst" "$port" 2>/dev/null || true
}

# send_icmp_from_ns <dst_ip> [count] [timeout_secs]
send_icmp_from_ns() {
    local dst="${1:?usage: send_icmp_from_ns <dst_ip>}"
    local count="${2:-3}"
    local timeout="${3:-5}"

    ping -c "$count" -W 1 -i 0.2 "$dst" 2>/dev/null || true
}

# hping3_flood_from_ns <dst_ip> <dst_port> [count] [interval]
hping3_flood_from_ns() {
    local dst="${1:?usage: hping3_flood_from_ns <dst_ip> <dst_port>}"
    local port="${2:?usage: hping3_flood_from_ns <dst_ip> <dst_port>}"
    local count="${3:-100}"
    local interval="${4:-u1000}"   # microseconds between packets

    sudo hping3 -S -p "$port" -c "$count" -i "$interval" "$dst" 2>/dev/null || true
}

# iperf3_from_ns <dst_ip> [duration_secs] [protocol_flag] [extra_args...]
iperf3_from_ns() {
    local dst="${1:?usage: iperf3_from_ns <dst_ip> [duration] [proto_flag]}"
    local duration="${2:-5}"
    local proto="${3:-}"
    shift 3 2>/dev/null || true

    iperf3 -c "$dst" -t "$duration" $proto --json "$@" 2>/dev/null
}

# ── Polling helpers (overrides) ──────────────────────────────────

# wait_for_ebpf_loaded [max_attempts]
# Polls /readyz on the agent VM until ebpf_loaded is true.
wait_for_ebpf_loaded() {
    local max="${1:-30}"
    local attempt=0
    local readyz_url="http://${AGENT_VM_IP}:${AGENT_HTTP_PORT}/readyz"

    while [ "$attempt" -lt "$max" ]; do
        local body
        body="$(curl -sf --max-time "${HTTP_TIMEOUT}" "$readyz_url" 2>/dev/null)" || true
        local loaded
        loaded="$(echo "$body" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
        if [ "$loaded" = "true" ]; then
            return 0
        fi
        # Early exit: agent is healthy but eBPF not loaded (degraded mode)
        if [ -n "$body" ] && [ "$loaded" = "false" ]; then
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

# ── Cleanup (override) ───────────────────────────────────────────

cleanup_test_env() {
    stop_ebpf_agent 2>/dev/null || true
    # Clean up remote data directory
    _agent_ssh_sudo rm -rf "${_REMOTE_DATA_DIR}" 2>/dev/null || true
    _agent_ssh_sudo rm -rf "${_REMOTE_CONFIG_DIR}" 2>/dev/null || true
    _agent_ssh_sudo rm -f "${_REMOTE_LOG_FILE}" 2>/dev/null || true
    # Clean up local tracking
    rm -rf "$DATA_DIR"
}
