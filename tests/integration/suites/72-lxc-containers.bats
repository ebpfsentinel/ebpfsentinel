#!/usr/bin/env bats
# 72-lxc-containers.bats - an LXC container is a container like the others.
#
# A Proxmox CT and an Incus instance are LXC containers, and an LXC
# container is a cgroup, so the agent names it from its cgroup path and
# every workload rule applies to it unchanged. The containers here are
# started with `lxc-execute` on the node's own root filesystem and network,
# which is the smallest LXC container there is: what is under test is the
# cgroup LXC places it in, and nothing else about it.
#
# The suite asserts:
#
#   * A rule naming a container by the hostname a Proxmox configuration
#     file gives it refuses a connect from the CT whose number names that
#     file, and the same client on the host connects.
#   * A rule naming a plain LXC container refuses a connect from it, and
#     not on the port the other rule names.
#   * The process table files a process of the CT under runtime `lxc`, with
#     the name and the OS type the configuration file gives.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool lxc-execute
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 72 runs its containers beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lxc-$$"
    mkdir -p "${DATA_DIR}/pve/lxc"
    # The file Proxmox keeps for CT 4101, snapshot section included, so the
    # name read is the current one.
    printf '%s\n' 'arch: amd64' 'hostname: ct-web' 'ostype: debian' 'tags: prod;web' \
        '[before-upgrade]' 'hostname: ct-old' >"${DATA_DIR}/pve/lxc/4101.conf"

    # The smallest container LXC starts: the node's root filesystem and
    # network, no console, no AppArmor profile of its own.
    export CT_CONF="${DATA_DIR}/ct.conf"
    printf '%s\n' 'lxc.net.0.type = none' 'lxc.apparmor.profile = unconfined' \
        'lxc.console.path = none' 'lxc.tty.max = 0' 'lxc.pty.max = 0' >"${CT_CONF}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-lxc.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "cgroup-workload-firewall" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "cgroup-workload-firewall did not load" >&2; return 1; }
    }

    LISTENER_PID_A="$(_listen 7201)"
    LISTENER_PID_B="$(_listen 7202)"
    export LISTENER_PID_A LISTENER_PID_B
}

teardown_file() {
    kill "${LISTENER_PID_A:-}" "${LISTENER_PID_B:-}" 2>/dev/null || true
    lxc-stop -k -n 4101 2>/dev/null || true
    lxc-stop -k -n ct-plain 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lxc-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_listen() {
    local port="${1:?usage: _listen <port>}"
    ip netns exec "$EBPF_TEST_NS" ncat -l "$EBPF_NS_IP" "$port" -k >/dev/null 2>&1 &
    local pid=$!
    local attempt=0
    while [ "$attempt" -lt 25 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -tlnH "sport = :${port}" 2>/dev/null | grep -q . && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "$pid"
}

# _in_ct <name> <shell line> - runs the line in a new LXC container. The
# pause lets the agent see the container's first exec and write its rules
# before the line connects, which is the order a long-lived CT has anyway.
_in_ct() {
    local name="${1:?usage: _in_ct <name> <line>}"
    local line="${2:?usage: _in_ct <name> <line>}"
    timeout 30 lxc-execute -n "${name}" -f "${CT_CONF}" -- \
        sh -c "sleep 2; ${line}" </dev/null 2>&1 | grep -v '^lxc-execute: '
    return "${PIPESTATUS[0]}"
}

_client() {
    echo "echo x | ncat -w 2 ${EBPF_NS_IP} ${1:?usage: _client <port>}"
}

_denials() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/firewall/workload/rules" \
        | jq -r --arg rule "${1:?usage: _denials <rule>}" '.rules[] | select(.rule == $rule) | .denials'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a client on the host reaches both ports" {
    run bash -c "$(_client 7201)"
    [ "$status" -eq 0 ]
    run bash -c "$(_client 7202)"
    [ "$status" -eq 0 ]
}

@test "the CT a Proxmox file names is refused by the rule naming its hostname" {
    local before
    before="$(_denials fw-ct-web)"
    run _in_ct 4101 "$(_client 7201)"
    [ "$status" -ne 0 ]
    [[ "$output" == *"not permitted"* ]]
    local after
    after="$(_denials fw-ct-web)"
    [ "${after}" -gt "${before}" ]
}

@test "a plain LXC container is refused by the rule naming it and not by the other" {
    local before
    before="$(_denials fw-ct-plain)"
    run _in_ct ct-plain "$(_client 7202)"
    [ "$status" -ne 0 ]
    [[ "$output" == *"not permitted"* ]]
    local after
    after="$(_denials fw-ct-plain)"
    [ "${after}" -gt "${before}" ]

    run _in_ct ct-plain "$(_client 7201)"
    [ "$status" -eq 0 ]
}

@test "a process of the CT is filed under lxc with the name and OS its file gives" {
    timeout 30 lxc-execute -n 4101 -f "${CT_CONF}" -- sleep 15 </dev/null >/dev/null 2>&1 &
    local procs="/sys/fs/cgroup/lxc.payload.4101/cgroup.procs"
    local pid="" attempt=0
    while [ -z "${pid}" ] && [ "${attempt}" -lt 50 ]; do
        local candidate
        for candidate in $(cat "${procs}" 2>/dev/null); do
            [ "$(cat "/proc/${candidate}/comm" 2>/dev/null)" = "sleep" ] && pid="${candidate}"
        done
        [ -n "${pid}" ] || sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -n "${pid}" ] || { echo "no sleep in ${procs}" >&2; return 1; }

    local container=""
    attempt=0
    while [ "${attempt}" -lt 30 ]; do
        container="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/processes/${pid}" \
            | jq -c '.container // empty')"
        [ -n "${container}" ] && [ "$(jq -r '.name // ""' <<<"${container}")" = "ct-web" ] && break
        sleep 0.2
        attempt=$((attempt + 1))
    done
    lxc-stop -k -n 4101 2>/dev/null || true
    echo "container: ${container}" >&2
    [ "$(jq -r '.runtime' <<<"${container}")" = "lxc" ]
    [ "$(jq -r '.id' <<<"${container}")" = "4101" ]
    [ "$(jq -r '.name' <<<"${container}")" = "ct-web" ]
    [ "$(jq -r '.image' <<<"${container}")" = "debian" ]
}
