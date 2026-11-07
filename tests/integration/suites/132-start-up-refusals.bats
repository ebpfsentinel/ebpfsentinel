#!/usr/bin/env bats
# 132-start-up-refusals.bats - the agent refuses to start where running would
# promise what the node does not do, and says why; where it can run with less,
# it runs and says what it lacks.
#
# The suite asserts:
#
#   * `firewall.network_executables` in enforce on a host whose security
#     modules leave the BPF LSM out: the agent exits non-zero, and its last
#     word names the setting, the missing module and the `lsm=` boot
#     parameter that would bring it.
#   * The same list in observe on the same host: the agent starts and says
#     that nothing is observed, so the refusal above is the enforce mode's
#     and not the host's.
#   * No warden to delegate a bpffs, so no BPF token: the agent stays up
#     serving its API, `/readyz` answers 503 with `ebpf_loaded` false, and the
#     log names the token and the warden socket it needs.
#   * The same missing token with an enforcing list configured: the agent
#     refuses to start rather than serve an API while enforcing nothing.
#
# The kernel floor's refusal is suite 77's. The security modules are shown to
# the agent through a bind mount over /sys/kernel/security/lsm inside a mount
# namespace of its own, so the host keeps its modules.
#
# Lane: ../vagrant-runtimes or ../vagrant. Requires: root, kernel >= 6.12,
# jq, unshare, and the BPF LSM active on the host for the enforce pair.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool curl
    require_tool unshare

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-refusals-$$"
    mkdir -p "${DATA_DIR}"
    create_test_netns

    export CURL_BIN
    CURL_BIN="$(readlink -f "$(command -v curl)")"
}

teardown() {
    stop_ebpf_agent 2>/dev/null || true
    unset EBPF_AGENT_LSM_FILE
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR}"
}

# _config <observe|enforce> - the network executables fixture in that mode.
_config() {
    local fixture="${DATA_DIR}/config-${1}.yaml"
    sed -e "s|__EXEC_MODE__|$1|" -e "s|__CURL__|${CURL_BIN}|" \
        "${FIXTURE_DIR}/config-ebpf-network-executables.yaml" >"${fixture}"
    prepare_ebpf_config "${fixture}"
}

# The host's security modules with bpf left out, as a file to bind over the
# real list.
_lsm_without_bpf() {
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null ||
        env_skip "the BPF LSM is not among this host's security modules"
    local fake="${DATA_DIR}/lsm"
    tr ',' '\n' </sys/kernel/security/lsm | grep -vx bpf | paste -sd, - | tr -d '\n' >"${fake}"
    echo "${fake}"
}

# _exit_status <pid> [max] - wait for a child of this shell to end, print its
# status; fails if it is still running after max seconds.
_exit_status() {
    local pid="$1" max="${2:-60}" i
    for ((i = 0; i < max * 2; i++)); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            local rc=0
            wait "${pid}" 2>/dev/null || rc=$?
            echo "${rc}"
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# _start_without_warden <config> - the agent alone, as a host with no warden
# running starts it.
_start_without_warden() {
    : >"${AGENT_LOG_FILE}"
    chmod 640 "$1"
    setsid env EBPF_PROGRAM_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release" \
        "${PROJECT_ROOT}/target/release/ebpfsentinel-agent" --config "$1" \
        </dev/null >"${AGENT_LOG_FILE}" 2>&1 &
    AGENT_PID=$!
    echo "${AGENT_PID}" >"${AGENT_PID_FILE}"
}

@test "an enforcing executables list on a host without the BPF LSM refuses to start and names the boot parameter" {
    EBPF_AGENT_LSM_FILE="$(_lsm_without_bpf)"
    export EBPF_AGENT_LSM_FILE
    local config
    config="$(_config enforce)"

    start_ebpf_agent "${config}" >/dev/null 2>&1 || true
    local rc
    rc="$(_exit_status "${AGENT_PID}")" || {
        echo "# the agent is still running" >&3
        tail -20 "${AGENT_LOG_FILE}" >&3
        false
    }
    [ "${rc}" -ne 0 ]
    grep -q 'firewall.network_executables is set to enforce and cannot be applied here' "${AGENT_LOG_FILE}" || {
        tail -20 "${AGENT_LOG_FILE}" >&3
        false
    }
    grep 'cannot be applied here' "${AGENT_LOG_FILE}" | grep -q 'lsm=.*bpf'
    [ "$(api_status /healthz)" != "200" ]
}

@test "the same list in observe on that host starts and says nothing is observed" {
    EBPF_AGENT_LSM_FILE="$(_lsm_without_bpf)"
    export EBPF_AGENT_LSM_FILE
    local config
    config="$(_config observe)"

    start_ebpf_agent "${config}"
    local i
    for i in $(seq 1 30); do
        grep -q 'network executables unavailable, nothing is observed' "${AGENT_LOG_FILE}" && break
        sleep 0.5
    done
    grep -q 'network executables unavailable, nothing is observed' "${AGENT_LOG_FILE}"
    [ "$(api_status /healthz)" = "200" ]
}

@test "without a warden the agent serves its API, is not ready, and names the token it lacks" {
    local config
    config="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-runtimes.yaml")"
    _start_without_warden "${config}"
    wait_for_agent >/dev/null || {
        tail -20 "${AGENT_LOG_FILE}" >&3
        false
    }

    [ "$(api_status /readyz)" = "503" ]
    [ "$(curl -s --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/readyz" | jq -r .ebpf_loaded)" = "false" ]
    grep -q 'BPF token unavailable - running in API-only mode' "${AGENT_LOG_FILE}"
    grep 'BPF token unavailable' "${AGENT_LOG_FILE}" | grep -q 'EBPFSENTINEL_WARDEN_SOCK'
}

@test "without a warden an enforcing executables list refuses to start rather than enforce nothing" {
    local config
    config="$(_config enforce)"
    _start_without_warden "${config}"
    local rc
    rc="$(_exit_status "${AGENT_PID}")" || {
        echo "# the agent is still running while enforcing nothing" >&3
        tail -20 "${AGENT_LOG_FILE}" >&3
        false
    }
    [ "${rc}" -ne 0 ]
    grep -q 'firewall.network_executables is set to enforce' "${AGENT_LOG_FILE}"
    grep 'firewall.network_executables is set to enforce' "${AGENT_LOG_FILE}" | grep -q 'BPF token'
}
