#!/usr/bin/env bash
# ct_helpers.bash — Kernel netfilter conntrack helpers for 3-VM suites.
#
# These wrap two needs:
#   - establish a long-lived iperf3 flow from the attacker through the
#     agent's transit datapath so the kernel CT table on the agent
#     carries a tracked entry for the 4-tuple
#   - assert (or wait for) that CT entry to disappear after the agent
#     fires kill_flow_via_xdp_ct / kill_flow_via_skb_ct
#
# Requires: vm_helpers.bash already sourced. The `conntrack` userspace
# tool must be installed on the agent VM; if missing, the helpers print
# a hint to apt-install `conntrack` and return non-zero.

# _attacker_ssh <cmd...>
# Run a command on the attacker VM. Lightweight wrapper used by the iperf3
# launcher below.
_attacker_ssh() {
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" -- "$@"
}

# ensure_conntrack_tool
#
# Verify the `conntrack` CLI is available on the agent VM (provided by
# the conntrack-tools package). Returns 0 when present; 1 + a hint
# otherwise. Suites should `skip` on non-zero return rather than fail —
# kernel CT itself is always on, only the userspace inspector is gated.
ensure_conntrack_tool() {
    if _agent_ssh_sudo command -v conntrack >/dev/null 2>&1; then
        return 0
    fi
    echo "agent VM missing 'conntrack' tool (apt install conntrack)" >&2
    return 1
}

# establish_iperf_flow <dst_ip> <dst_port> [duration_secs]
#
# Launch a background iperf3 client on the attacker VM targeting the
# backend through the agent's transit path. Echoes the remote PID on
# stdout so the caller can stop it via stop_iperf_flow. Default duration
# is 60s (long enough for the test sequence + the mid-flow block).
establish_iperf_flow() {
    local dst_ip="${1:?usage: establish_iperf_flow <dst_ip> <dst_port> [duration]}"
    local dst_port="${2:?usage: establish_iperf_flow <dst_ip> <dst_port> [duration]}"
    local duration="${3:-60}"
    local out_log="/tmp/iperf3-ctkill-$$.log"
    local pid
    pid="$(_attacker_ssh sh -c "nohup iperf3 -c '${dst_ip}' -p '${dst_port}' -t ${duration} -b 1M --json >'${out_log}' 2>&1 & echo \$!")" || return 1
    [ -n "$pid" ] || return 1
    # Brief settle so the SYN/ACK round-trip clears and CT picks up the
    # flow on the agent.
    sleep 2
    echo "$pid"
}

# stop_iperf_flow <remote_pid>
#
# Best-effort kill of the iperf3 client started by establish_iperf_flow.
stop_iperf_flow() {
    local pid="${1:?usage: stop_iperf_flow <remote_pid>}"
    _attacker_ssh sh -c "kill ${pid} 2>/dev/null; true" >/dev/null 2>&1 || true
}

# ct_entry_count <dst_ip> <dst_port> [protocol]
#
# Echo the number of conntrack entries on the agent matching the given
# destination tuple. Protocol defaults to tcp. Returns 0 with the
# count, even when no rows match (echoes "0"). Returns non-zero only
# when the conntrack tool itself is missing.
ct_entry_count() {
    local dst_ip="${1:?usage: ct_entry_count <dst_ip> <dst_port> [proto]}"
    local dst_port="${2:?usage: ct_entry_count <dst_ip> <dst_port> [proto]}"
    local proto="${3:-tcp}"
    ensure_conntrack_tool || return 1
    local rows
    rows="$(_agent_ssh_sudo conntrack -L -p "${proto}" --dst "${dst_ip}" --dport "${dst_port}" 2>/dev/null \
            | grep -c "dport=${dst_port}")" || rows=0
    echo "${rows:-0}"
}

# assert_ct_entry_absent <dst_ip> <dst_port> [protocol] [retries] [sleep_s]
#
# Poll the agent's conntrack table for up to retries * sleep_s seconds,
# returning 0 as soon as no rows remain for the tuple. Echoes the final
# row count on stdout. Default retries=10, sleep_s=1.
assert_ct_entry_absent() {
    local dst_ip="${1:?usage: assert_ct_entry_absent <dst_ip> <dst_port>}"
    local dst_port="${2:?usage: assert_ct_entry_absent <dst_ip> <dst_port>}"
    local proto="${3:-tcp}"
    local retries="${4:-10}"
    local sleep_s="${5:-1}"
    local i count
    for ((i = 0; i < retries; i++)); do
        count="$(ct_entry_count "${dst_ip}" "${dst_port}" "${proto}")" || return 1
        if [ "${count:-0}" -eq 0 ]; then
            echo "0"
            return 0
        fi
        sleep "${sleep_s}"
    done
    echo "${count}"
    return 1
}

# wait_for_ct_entry <dst_ip> <dst_port> [protocol] [retries] [sleep_s]
#
# Inverse poll — wait for at least one CT row to appear. Useful right
# after establish_iperf_flow before the block-rule injection.
wait_for_ct_entry() {
    local dst_ip="${1:?usage: wait_for_ct_entry <dst_ip> <dst_port>}"
    local dst_port="${2:?usage: wait_for_ct_entry <dst_ip> <dst_port>}"
    local proto="${3:-tcp}"
    local retries="${4:-15}"
    local sleep_s="${5:-1}"
    local i count
    for ((i = 0; i < retries; i++)); do
        count="$(ct_entry_count "${dst_ip}" "${dst_port}" "${proto}")" || return 1
        if [ "${count:-0}" -gt 0 ]; then
            echo "${count}"
            return 0
        fi
        sleep "${sleep_s}"
    done
    echo "0"
    return 1
}
