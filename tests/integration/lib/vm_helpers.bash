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

    # A freshly booted agent VM has a clean /tmp, so a per-suite scratch dir
    # created locally on the test runner does not exist on the agent. Create
    # the remote parent directory before the copy, otherwise scp fails with
    # "failed to upload file ... to ...". The agent-local test mode (sudo bats
    # on the agent) can also leave root-owned files at the same fixed /tmp
    # paths, which the unprivileged scp cannot overwrite — so prepare the
    # directory with sudo, hand it back to the vagrant user, and clear any
    # stale destination file first.
    local remote_dir
    remote_dir="$(dirname "$remote_path")"
    _agent_ssh_sudo "mkdir -p '$remote_dir' && chown vagrant: '$remote_dir' && rm -f '$remote_path'" 2>/dev/null || true

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
        -e "s|__HOST_IP__|${AGENT_VM_IP}|g" \
        -e "s|__NS_IP__|${ATTACKER_VM_IP}|g" \
        "$fixture" > "$output"

    # In 2VM mode the agent must be reachable from the attacker VM (HTTP health
    # check + REST traffic), so it has to bind all interfaces, not loopback.
    # Many fixtures default to 127.0.0.1; rewrite it. Binding non-loopback with
    # auth disabled requires allow_unauthenticated_api, so add it when absent
    # (avoid a duplicate key, which serde_yaml rejects).
    sed -i -E 's|^([[:space:]]*)bind_address:.*|\1bind_address: "0.0.0.0"|' "$output"
    if ! grep -qE '^[[:space:]]*allow_unauthenticated_api:' "$output"; then
        sed -i -E 's|^([[:space:]]*)bind_address: "0.0.0.0"|\1bind_address: "0.0.0.0"\n\1allow_unauthenticated_api: true|' "$output"
    fi

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
    # The agent runs in a child user namespace (via the launcher); files owned by
    # an unmapped uid (the vagrant user that scp'd them) are unreadable there.
    # Give the config + data dir to root (uid 0 is the only mapped id) so the
    # userns agent can read its config and write its audit/alert stores.
    _agent_ssh_sudo chown -R root:root "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true
    _agent_ssh_sudo chmod 755 "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true
    _agent_ssh_sudo chmod 640 "$remote_config" 2>/dev/null || true

    # Build the extra args string (properly quoted)
    local extra_args=""
    for arg in "$@"; do
        extra_args="${extra_args} $(printf '%q' "$arg")"
    done

    # Start agent on remote host via SSH. eBPF loads EXCLUSIVELY through a BPF
    # token (a user-namespace feature), so the agent must run via the shipped
    # launcher (delegates a bpffs + execs the agent in a child userns, as
    # production does). Run directly and it starts in API-only mode (no eBPF).
    # Binaries + objects live under /usr/local (world-traversable), so the userns
    # agent needs no staging. nohup so the process survives SSH disconnect.
    _agent_ssh_sudo bash -c \
        "'sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 || true; \
          LAUNCH=/usr/local/bin/ebpfsentinel-token-launch; \
          if [ -x \"\$LAUNCH\" ]; then \
            nohup env EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel \"\$LAUNCH\" --bpffs /sys/fs/bpf/ebpfsentinel /usr/local/bin/ebpfsentinel-agent --config ${remote_config}${extra_args} >${_REMOTE_LOG_FILE} 2>&1 & echo \$! > ${_REMOTE_PID_FILE}; \
          else \
            nohup /usr/local/bin/ebpfsentinel-agent --config ${remote_config}${extra_args} >${_REMOTE_LOG_FILE} 2>&1 & echo \$! > ${_REMOTE_PID_FILE}; \
          fi'" || {
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

    # Reap any launcher-spawned agent left over (the userns child is not the
    # tracked launcher pid) and WAIT for it to actually die. The agent attaches
    # XDP via a BPF_LINK held by its process fd; that link only auto-detaches
    # once the process is gone. If a lingering userns child stays attached, it
    # keeps throttling eth1 — contaminating the next suite's "no agent" baseline
    # — and its XDP hook makes the next attach fail with EBUSY (errno 16).
    #
    # Match by process name (comm), NOT `pkill -f "… --config"`: `_agent_ssh_sudo`
    # sends the command through ssh, which re-joins argv with spaces and drops
    # the quotes, so a multi-word `-f` pattern arrives as `pkill -f name --config`
    # — pkill then treats `--config` as a flag and silently kills nothing. The
    # binary's comm is truncated to 15 chars (`ebpfsentinel-ag` / `…-to`); a bare
    # single-token pattern survives ssh and never matches the pkill command line.
    local _reap=0
    _agent_ssh_sudo pkill ebpfsentinel-ag 2>/dev/null || true
    _agent_ssh_sudo pkill ebpfsentinel-to 2>/dev/null || true
    while _agent_ssh_sudo pgrep ebpfsentinel-ag >/dev/null 2>&1 && [ "$_reap" -lt 20 ]; do
        _agent_ssh_sudo pkill -9 ebpfsentinel-ag 2>/dev/null || true
        _agent_ssh_sudo pkill -9 ebpfsentinel-to 2>/dev/null || true
        sleep 0.3
        _reap=$((_reap + 1))
    done

    # Belt-and-suspenders: strip any XDP/TC the dead agent left on the data
    # interface so the next attach sees a clean hook (covers legacy/pinned
    # attaches that don't auto-detach on process exit).
    local _iface="${EBPF_AGENT_INTERFACE:-eth1}"
    _agent_ssh_sudo ip link set dev "$_iface" xdpgeneric off 2>/dev/null || true
    _agent_ssh_sudo ip link set dev "$_iface" xdp off 2>/dev/null || true
    _agent_ssh_sudo tc qdisc del dev "$_iface" clsact 2>/dev/null || true

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

# ── 3-VM transit topology helpers ────────────────────────────────
#
# Active only when EBPF_3VM_MODE=true (set by run-in-3vm.sh).
# Topology:
#   Client VM  (192.168.56.20) ── 56.0/24 ──┐
#                                          [Agent dual-NIC router]
#   Backend VM (192.168.57.30) ── 57.0/24 ──┘
#
# The agent's `eth1` lives on 56.0/24 (client side), `eth2` on 57.0/24
# (backend side). Static routes push all cross-subnet traffic through
# the agent so eBPF datapath (NAT, conntrack, QoS, DSR, TLS DLP) sees
# every packet.

BACKEND_VM_IP="${BACKEND_VM_IP:-192.168.57.30}"
AGENT_BACKEND_IP="${AGENT_BACKEND_IP:-192.168.57.10}"
BACKEND_SSH_KEY="${BACKEND_SSH_KEY:-${HOME}/.ssh/backend_key}"
BACKEND_SSH_CMD="ssh -i ${BACKEND_SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 vagrant@${BACKEND_VM_IP}"
EBPF_AGENT_BACKEND_IFACE="${EBPF_AGENT_BACKEND_IFACE:-eth2}"
EBPF_BACKEND_IFACE="${EBPF_BACKEND_IFACE:-eth1}"

# _backend_ssh <command...>
# Run a command on the backend VM via SSH. Returns the remote exit code.
_backend_ssh() {
    if [ $# -eq 0 ]; then
        echo "usage: _backend_ssh <command...>" >&2
        return 1
    fi
    $BACKEND_SSH_CMD -- "$@"
}

# _backend_ssh_sudo <command...>
# Run a command on the backend VM as root via SSH.
_backend_ssh_sudo() {
    if [ $# -eq 0 ]; then
        echo "usage: _backend_ssh_sudo <command...>" >&2
        return 1
    fi
    $BACKEND_SSH_CMD -- sudo "$@"
}

# skip_if_not_3vm is defined in ebpf_helpers.bash (always sourced) so it is
# available to guard setup before this file is loaded.

# route_via_agent <side>
# Install a route on `side` so traffic to the opposite subnet flows
# through the agent router. <side> is "client" or "backend".
# Returns 0 on success, non-zero on SSH/route failure.
route_via_agent() {
    local side="$1"
    case "$side" in
        client)
            # Client (attacker) reaches 192.168.57.0/24 via agent's 56.10
            $AGENT_SSH_CMD -- true >/dev/null 2>&1 || true
            ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
                -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                "vagrant@${ATTACKER_VM_IP}" -- \
                sudo ip route replace 192.168.57.0/24 via "${AGENT_VM_IP}" dev eth1
            ;;
        backend)
            # Backend reaches 192.168.56.0/24 via agent's 57.10
            _backend_ssh_sudo ip route replace 192.168.56.0/24 \
                via "${AGENT_BACKEND_IP}" dev "${EBPF_BACKEND_IFACE}"
            ;;
        *)
            echo "route_via_agent: side must be 'client' or 'backend' (got '${side}')" >&2
            return 2
            ;;
    esac
}

# set_backend_arp [iface]
# Discover the backend's MAC on its backend-side NIC, then populate the
# agent's BACKEND_MAC eBPF map so L2 DSR programs can rewrite dst MAC
# without an ARP round-trip on the data path.
#
# Echoes "<ip> <mac>" on stdout. Returns 0 on success.
set_backend_arp() {
    local iface="${1:-${EBPF_BACKEND_IFACE}}"
    local line ip mac
    line="$(_backend_ssh /usr/local/bin/backend-arp "${iface}")" || return 1
    ip="${line%% *}"
    mac="${line##* }"
    if [ -z "${ip}" ] || [ -z "${mac}" ]; then
        echo "set_backend_arp: empty ip/mac from backend (line='${line}')" >&2
        return 1
    fi
    # Prime agent ARP cache so the kernel resolver agrees with the eBPF map.
    _agent_ssh_sudo ip neigh replace "${ip}" lladdr "${mac}" \
        dev "${EBPF_AGENT_BACKEND_IFACE}" nud permanent >/dev/null 2>&1 || true
    # Push the entry through the LB control API (idempotent).
    curl -sf --max-time "${HTTP_TIMEOUT}" -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_TOKEN:-test-token}" \
        "${BASE_URL}/api/v1/lb/backends/mac" \
        -d "{\"ip\":\"${ip}\",\"mac\":\"${mac}\"}" >/dev/null 2>&1 || true
    echo "${ip} ${mac}"
}

# start_backend_service <svc> [port]
# Start a backend service via systemd and wait for its port to accept
# connections. Supported svc names: iperf3, nginx, sshd, s-server.
start_backend_service() {
    local svc="$1"
    local port="${2:-}"
    local unit
    case "$svc" in
        iperf3)    unit="iperf3-backend.service";  port="${port:-5201}" ;;
        nginx)     unit="nginx.service";           port="${port:-80}"   ;;
        sshd)      unit="ssh.service";             port="${port:-22}"   ;;
        s-server)  unit="s-server-backend.service"; port="${port:-8443}" ;;
        *)
            echo "start_backend_service: unknown svc '${svc}'" >&2
            return 2
            ;;
    esac
    _backend_ssh_sudo systemctl start "${unit}" || return 1
    # Wait for port (up to 10s)
    local attempt=0
    while [ "$attempt" -lt 10 ]; do
        if _backend_ssh "nc -z -w1 127.0.0.1 ${port}" 2>/dev/null; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "start_backend_service: ${svc} did not open :${port} on backend" >&2
    return 1
}

# capture_on <vm> <iface> <bpf-filter>
# Start a background tcpdump on the named VM (agent|client|backend) and
# echo the remote pcap path on stdout. Pair with stop_capture <vm> <path>.
capture_on() {
    local vm="$1"
    local iface="$2"
    local bpf="$3"
    local pcap="/tmp/cap-$$-$(date +%s).pcap"
    local unit="ebpf-cap-$(basename "${pcap}" .pcap)"
    local sshrun
    case "$vm" in
        agent)   sshrun=("_agent_ssh_sudo") ;;
        backend) sshrun=("_backend_ssh_sudo") ;;
        client)
            sshrun=(ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key"
                    -o StrictHostKeyChecking=no -o ConnectTimeout=5
                    "vagrant@${ATTACKER_VM_IP}" -- sudo)
            ;;
        *)
            echo "capture_on: vm must be 'agent', 'client', or 'backend' (got '${vm}')" >&2
            return 2
            ;;
    esac
    # Run tcpdump as a transient systemd unit. A plain backgrounded tcpdump
    # (nohup/setsid) is reaped when its launching SSH session ends over the
    # attacker->backend hop and never creates the capture file; the transient
    # unit is owned by systemd, survives the SSH close, and is stopped (clean
    # SIGTERM → pcap flush) by stop_capture via the same derived unit name.
    "${sshrun[@]}" systemd-run --unit="${unit}" --collect \
        tcpdump -n -U -w "${pcap}" -i "${iface}" ${bpf} >/dev/null 2>&1 || return 1
    # Wait until tcpdump has actually opened its capture file before returning,
    # so traffic that flows right after capture_on isn't missed. systemd-run
    # starts the unit asynchronously, so a fixed short sleep races the BPF
    # socket open; poll for the pcap to appear (tcpdump writes the 24-byte
    # global header immediately) and fall back to a generous settle.
    local _i
    for _i in 1 2 3 4 5 6 7 8 9 10; do
        "${sshrun[@]}" test -s "${pcap}" >/dev/null 2>&1 && break
        sleep 0.5
    done
    echo "${pcap}"
}

# stop_capture <vm> <pcap-path>
# Stop the tcpdump started by capture_on and fetch the pcap locally.
# Echoes the local path on stdout.
stop_capture() {
    local vm="$1"
    local pcap="$2"
    local unit="ebpf-cap-$(basename "${pcap}" .pcap)"
    local local_pcap="${DATA_DIR:-/tmp}/$(basename "${pcap}")"
    local sshrun scpsrc scpkey
    case "$vm" in
        agent)
            sshrun=("_agent_ssh_sudo")
            scpsrc="vagrant@${AGENT_VM_IP}:${pcap}"
            scpkey="${AGENT_SSH_KEY}"
            ;;
        backend)
            sshrun=("_backend_ssh_sudo")
            scpsrc="vagrant@${BACKEND_VM_IP}:${pcap}"
            scpkey="${BACKEND_SSH_KEY:-${AGENT_SSH_KEY%agent_key}backend_key}"
            ;;
        client)
            sshrun=(ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key"
                    -o StrictHostKeyChecking=no -o ConnectTimeout=5
                    "vagrant@${ATTACKER_VM_IP}" -- sudo)
            scpsrc="vagrant@${ATTACKER_VM_IP}:${pcap}"
            scpkey="${AGENT_SSH_KEY%agent_key}attacker_key"
            ;;
        *)
            echo "stop_capture: vm must be 'agent', 'client', or 'backend' (got '${vm}')" >&2
            return 2
            ;;
    esac
    # Stop the transient capture unit. systemctl stop is synchronous: it returns
    # only after tcpdump has received SIGTERM and exited (flushing its pcap), so
    # the file is complete before the scp below. Call systemctl directly through
    # sshrun (which already prepends sudo) — wrapping it in `sh -c` dropped the
    # unit argument through the quoting layers and left captures running.
    "${sshrun[@]}" systemctl stop "${unit}" >/dev/null 2>&1 || true
    # Pull pcap locally with the key that authenticates to THIS vm (the backend
    # rejects the agent key, which silently emptied the pcap and skipped tests).
    scp -i "${scpkey}" -o StrictHostKeyChecking=no \
        "${scpsrc}" "${local_pcap}" >/dev/null 2>&1 || true
    echo "${local_pcap}"
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
