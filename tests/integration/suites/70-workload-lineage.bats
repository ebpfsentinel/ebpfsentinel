#!/usr/bin/env bats
# 70-workload-lineage.bats - workload rules decided on the chain of parents.
#
# A rule naming a parent or an ancestor is decided in the kernel at the
# call, by walking the calling task's parents and reading the executable
# each one runs. Nothing is recorded per task beforehand, so the assertions
# are about the chain a connect is made under and nothing else.
#
# The suite asserts:
#
#   * A connect whose direct parent runs `timeout` is refused with EPERM on
#     the port the parent rule names, while the same client started from
#     the shell connects.
#   * A connect two levels below `python3` is refused on the port the
#     ancestor rule names, which a parent rule would not see, and the same
#     chain reaches the other port because its parent is a shell.
#   * Each refusal is counted against the rule that made it.
#   * The reach endpoint, asked about a task below `python3`, lists the
#     ancestor rule, read from the chain the process table holds.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool ncat
    require_tool python3
    require_tool timeout
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 70 runs its clients beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lineage-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-workload-lineage.yaml")"
    export PREPARED_CONFIG
    sed -i -e "s|__TIMEOUT__|$(readlink -f "$(command -v timeout)")|" \
        -e "s|__PYTHON__|$(readlink -f "$(command -v python3)")|" "${PREPARED_CONFIG}"

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "cgroup-workload-firewall" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "cgroup-workload-firewall did not load" >&2; return 1; }
    }

    LISTENER_PID_A="$(_listen 7101)"
    LISTENER_PID_B="$(_listen 7102)"
    export LISTENER_PID_A LISTENER_PID_B
}

teardown_file() {
    kill "${LISTENER_PID_A:-}" "${LISTENER_PID_B:-}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lineage-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _listen <port> - a listener whose parent is this shell. The shared helper
# starts ncat under `timeout`, and a rule naming `timeout` as the parent of
# whatever binds the port would refuse the listener itself.
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

# The client, as a shell line: connects, sends a byte and closes. Exit 0 is
# a connection made; the refusal is ncat's own error on stderr.
_client() {
    local port="${1:?usage: _client <port>}"
    echo "echo x | ncat -w 2 ${EBPF_NS_IP} ${port}"
}

# _from_shell <port> - the client's parent is a shell.
_from_shell() {
    bash -c "$(_client "$1"); exit \$?"
}

# _under_timeout <port> - the client's parent is `timeout`.
_under_timeout() {
    echo x | timeout 5 ncat -w 2 "${EBPF_NS_IP}" "$1"
}

# _under_python <port> - python3 starts a shell that starts the client, so
# python3 is the grandparent and the shell the parent.
_under_python() {
    python3 -c 'import subprocess, sys; sys.exit(subprocess.call(["bash", "-c", sys.argv[1] + "; exit $?"]))' \
        "$(_client "$1")"
}

_denials() {
    local rule="${1:?usage: _denials <rule>}"
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/firewall/workload/rules" \
        | jq -r --arg rule "${rule}" '.rules[] | select(.rule == $rule) | .denials'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a client started from the shell reaches both ports" {
    run _from_shell 7101
    [ "$status" -eq 0 ]
    run _from_shell 7102
    [ "$status" -eq 0 ]
}

@test "a client whose parent runs timeout is refused on the port the parent rule names" {
    local before
    before="$(_denials fw-under-timeout)"
    run _under_timeout 7101
    [ "$status" -ne 0 ]
    [[ "$output" == *"not permitted"* ]]
    local after
    after="$(_denials fw-under-timeout)"
    [ "${after}" -gt "${before}" ]
}

@test "a client two levels below python3 is refused by the ancestor rule and not by the parent rule" {
    local before
    before="$(_denials fw-under-python)"
    run _under_python 7102
    [ "$status" -ne 0 ]
    [[ "$output" == *"not permitted"* ]]
    local after
    after="$(_denials fw-under-python)"
    [ "${after}" -gt "${before}" ]

    # Its parent is the shell, so the parent rule on the other port does
    # not reach it.
    run _under_python 7101
    [ "$status" -eq 0 ]
}

@test "the reach of a task below python3 lists the ancestor rule" {
    python3 -c 'import subprocess; subprocess.call(["sleep", "20"])' &
    local python_pid=$!
    local child=""
    local attempt=0
    while [ -z "${child}" ] && [ "${attempt}" -lt 50 ]; do
        child="$(pgrep -P "${python_pid}" -x sleep || true)"
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -n "${child}" ]

    # The process table learns of the exec from its own tracepoint, so give
    # it the moment it takes to record both processes.
    local rules=""
    attempt=0
    while [ "${attempt}" -lt 30 ]; do
        rules="$(curl -sf --max-time "${HTTP_TIMEOUT}" \
            "${BASE_URL}/api/v1/firewall/workload/reach?pid=${child}" \
            | jq -r '[.rules[].rule] | join(",")')"
        [[ "${rules}" == *"fw-under-python"* ]] && break
        sleep 0.2
        attempt=$((attempt + 1))
    done
    kill "${python_pid}" "${child}" 2>/dev/null || true
    [[ "${rules}" == *"fw-under-python"* ]]
    [[ "${rules}" != *"fw-under-timeout"* ]]
}
