#!/usr/bin/env bats
# 151-command-line-at-exec.bats - the arguments of a started process are
# copied by the kernel at exec, bounded and redacted as the /proc read is,
# and read from /proc where the kernel cannot copy them.
#
# The suite asserts:
#
#   * With the BPF LSM active, the process routes say the kernel reads the
#     command line at exec, and a process that rewrites its own arguments
#     straight after the exec is shown with the arguments it was started
#     with, which only a read made during the exec can still see.
#   * That line went through the redaction: the flag's value is removed, the
#     flag and the rest of the line stay.
#   * The process counters count the copy as `command_line_read`.
#   * With `bpf` left out of the active security modules, presented through
#     a bind mount over /sys/kernel/security/lsm in the agent's own mount
#     namespace, the routes say the kernel does not read it and why, and a
#     live process still carries its line, read from /proc.
#
# Requires: root, kernel >= 6.18, jq, perl.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 18
    require_tool jq
    require_tool perl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 151 starts its processes on the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-argv-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-command-line-at-exec.yaml")"
    export PREPARED_CONFIG
}

teardown() {
    local pid
    for pid in $(cat "${DATA_DIR}/children" 2>/dev/null); do
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -f "${DATA_DIR}/children"
    stop_ebpf_agent 2>/dev/null || true
    unset EBPF_AGENT_LSM_FILE
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-argv-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_require_bpf_lsm() {
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
        || lane_skip bpf-lsm "the BPF LSM is not among this host's security modules"
}

_start_agent() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    local attempt=0
    while ! grep -q "eBPF process tracing active" "$AGENT_LOG_FILE" && [ "$attempt" -lt 60 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    grep -q "eBPF process tracing active" "$AGENT_LOG_FILE" || {
        echo "# process tracing did not attach" >&3
        tail -30 "$AGENT_LOG_FILE" >&3
        return 1
    }
}

# _rewriting_process - a perl that overwrites its own arguments as soon as it
# runs and then waits, so /proc/<pid>/cmdline shows the rewrite and only a
# read made during the exec has the arguments it was started with. The new
# title is upper-cased at run time, so the script text the kernel copies
# never contains it.
_rewriting_process() {
    perl -e '$0 = uc "rewritten-after-exec"; sleep 60' \
        ebpf-argv-marker --password=hunter2 -h db >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" >> "${DATA_DIR}/children"
    echo "$pid"
}

# _plain_process - a process that keeps its arguments as started.
_plain_process() {
    perl -e 'sleep 60' ebpf-argv-plain --token=s.abc >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" >> "${DATA_DIR}/children"
    echo "$pid"
}

# _line_of <pid> - the command line the table holds for pid, waiting for it.
_line_of() {
    local pid="$1" attempt=0 out line
    while [ "$attempt" -lt 20 ]; do
        out="$("$AGENT_BIN" --output json processes --port "$AGENT_HTTP_PORT" show "$pid" 2>/dev/null)" || out=""
        line="$(echo "$out" | jq -r '.command_line // empty' 2>/dev/null)"
        if [ -n "$line" ]; then
            echo "$line"
            return 0
        fi
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the kernel reads the arguments at exec, before the process can rewrite them" {
    _require_bpf_lsm
    _start_agent

    local tracing
    tracing="$(api_get /api/v1/processes | jq -c '.tracing')"
    [ "$(echo "$tracing" | jq -r '.command_line')" = "true" ]
    [ "$(echo "$tracing" | jq -r '.command_line_kernel')" = "true" ] || {
        echo "# tracing: ${tracing}" >&3
        false
    }
    [ "$(echo "$tracing" | jq -r '.command_line_reason // "none"')" = "none" ]

    local pid line
    pid="$(_rewriting_process)"
    line="$(_line_of "$pid")" || {
        echo "# no command line for ${pid}" >&3
        false
    }
    assert_contains "$line" "ebpf-argv-marker"
    [[ "$line" != *"REWRITTEN-AFTER-EXEC"* ]]
}

@test "the line the kernel read is redacted like the /proc read" {
    _require_bpf_lsm
    _start_agent

    local pid line
    pid="$(_rewriting_process)"
    line="$(_line_of "$pid")"
    assert_contains "$line" "--password=[redacted] -h db"
    [[ "$line" != *"hunter2"* ]]
}

@test "a copy made at exec is counted" {
    _require_bpf_lsm
    _start_agent
    wait_for_ebpf_counters PROCESS_METRICS

    local before after
    before="$(ebpf_counter PROCESS_METRICS command_line_read)"
    _rewriting_process >/dev/null
    after="$(ebpf_counter_above PROCESS_METRICS command_line_read "${before:-0}")"
    [ "${after:-0}" -gt "${before:-0}" ] || {
        dump_ebpf_counters PROCESS_METRICS >&3
        false
    }
}

@test "without bpf among the security modules, the line is read from /proc and the routes say why" {
    [ -r /sys/kernel/security/lsm ] || env_skip "securityfs is not mounted on this host"
    local fake="${DATA_DIR}/lsm"
    tr ',' '\n' </sys/kernel/security/lsm | grep -vx 'bpf' | paste -sd, - | tr -d '\n' >"$fake"
    export EBPF_AGENT_LSM_FILE="$fake"
    _start_agent

    local tracing
    tracing="$(api_get /api/v1/processes | jq -c '.tracing')"
    [ "$(echo "$tracing" | jq -r '.command_line')" = "true" ]
    [ "$(echo "$tracing" | jq -r '.command_line_kernel')" = "false" ]
    [[ "$(echo "$tracing" | jq -r '.command_line_reason // ""')" == *"BPF LSM is not active"* ]] || {
        echo "# tracing: ${tracing}" >&3
        false
    }

    local pid line
    pid="$(_plain_process)"
    line="$(_line_of "$pid")"
    assert_contains "$line" "ebpf-argv-plain --token=[redacted]"
    [[ "$line" != *"s.abc"* ]]
}
