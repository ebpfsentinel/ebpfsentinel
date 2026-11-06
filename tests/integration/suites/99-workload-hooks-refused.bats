#!/usr/bin/env bats
# 99-workload-hooks-refused.bats - a workload rule the kernel cannot carry
# out is never left in the file looking enforced.
#
# The hooks are pointed at a plain directory, which no cgroup attach accepts.
# The suite asserts:
#
#   * A rule that refuses, over hooks that did not attach, stops the agent
#     at startup, naming the rule it could not enforce and the attach.
#   * Container labels read for policy stop it the same way, since a label
#     may say enforce on any container started later.
#   * A rule that only observes lets the agent start, and the hooks are
#     reported off with the reason, none of them half attached.
#   * A reload turning that rule to enforce is rejected, and the rule in
#     force still observes.
#   * The same refusing rule over the real cgroup root starts, so what stops
#     the agent above is the attach and nothing else in the file.
#
# Requires: root, kernel >= 6.12, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 99 starts the agent over a cgroup root of its own (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-wlrefused-$$"
    mkdir -p "${DATA_DIR}/not-a-cgroup"
    chmod 755 "$DATA_DIR" "${DATA_DIR}/not-a-cgroup"
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-wlrefused-$$}"
}

teardown() {
    stop_ebpf_agent 2>/dev/null || true
}

# _config <cgroup root> <rule mode or none> <labels true|false> - a prepared
# configuration, at a path of its own so a reload can rewrite it.
_config() {
    local rules="[]"
    if [ "$2" != "none" ]; then
        rules="[{id: wl-refused, priority: 10, action: deny, protocol: tcp, dst_port: 7401, workload: {unit: ssh.service, mode: $2}}]"
    fi
    local out="${DATA_DIR}/config-$2-$3-$(basename "$1").yaml"
    prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-workload-refused.yaml" "$out" >/dev/null
    sed -i -e "s|__CGROUP_ROOT__|$1|" -e "s|__RULES__|${rules}|" -e "s|__LABELS__|$3|g" "$out"
    echo "$out"
}

# _refused - the agent started from the last configuration is gone. The API
# answers before the programs load, so the start itself may well succeed.
_refused() {
    local pid
    pid="$(cat "$AGENT_PID_FILE" 2>/dev/null || true)"
    local i
    for i in $(seq 1 60); do
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.5
    done
    return 1
}

# _workload_status - the workload firewall block of the kernel features, once
# the agent has decided it: attached, or refused with a reason. Before the
# programs load the block is neither.
_workload_status() {
    local i block
    for i in $(seq 1 60); do
        block="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null | jq -c '.workload_firewall' 2>/dev/null)" || true
        if [ "$(jq -r '.attached' <<<"$block" 2>/dev/null)" = "true" ] \
            || [ -n "$(jq -r '.reason // empty' <<<"$block" 2>/dev/null)" ]; then
            echo "$block"
            return 0
        fi
        sleep 0.5
    done
    echo "$block"
    return 1
}

@test "a refusing rule over hooks that did not attach stops the agent and says why" {
    local cfg
    cfg="$(_config "${DATA_DIR}/not-a-cgroup" enforce false)"
    run start_ebpf_agent "$cfg"
    _refused
    grep -q "nothing enforcing it" "$AGENT_LOG_FILE" \
        || { tail -5 "$AGENT_LOG_FILE" >&3; false; }
    grep -q "the cgroup attach was refused" "$AGENT_LOG_FILE"
}

@test "container labels read for policy over hooks that did not attach stop the agent too" {
    local cfg
    cfg="$(_config "${DATA_DIR}/not-a-cgroup" none true)"
    run start_ebpf_agent "$cfg"
    _refused
    grep -q "label_policy is on" "$AGENT_LOG_FILE" \
        || { tail -5 "$AGENT_LOG_FILE" >&3; false; }
}

@test "an observing rule starts with the hooks reported off, none half attached" {
    local cfg
    cfg="$(_config "${DATA_DIR}/not-a-cgroup" observe false)"
    start_ebpf_agent "$cfg"

    local block
    block="$(_workload_status)" || true
    [ "$(jq -r '.attached' <<<"$block")" = "false" ] || { echo "# $block" >&3; false; }
    [ "$(jq -r '.hooks | length' <<<"$block")" = "0" ]
    [ -n "$(jq -r '.reason // empty' <<<"$block")" ]
    [ "$(jq -r '.cgroup' <<<"$block")" = "${DATA_DIR}/not-a-cgroup" ]
}

@test "a reload turning the observing rule to enforce is rejected and the rule still observes" {
    local cfg
    cfg="$(_config "${DATA_DIR}/not-a-cgroup" observe false)"
    start_ebpf_agent "$cfg"
    _workload_status >/dev/null

    sed -i 's|mode: observe|mode: enforce|' "$cfg"
    api_post /api/v1/config/reload '{}' --max-time 30 >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 20); do
        grep -q "config reload rejected" "$AGENT_LOG_FILE" && break
        sleep 0.5
    done
    grep -q "config reload rejected" "$AGENT_LOG_FILE" \
        || { tail -5 "$AGENT_LOG_FILE" >&3; false; }
    grep "config reload rejected" "$AGENT_LOG_FILE" | grep -q "nothing enforcing it"

    run api_get /healthz
    [ "$status" -eq 0 ]
    run api_get /api/v1/ebpf/kernel-features
    [ "$(jq -r '.workload_firewall.attached' <<<"$output")" = "false" ]
}

@test "the same refusing rule over the real cgroup root starts with every hook attached" {
    local root
    root="$(findmnt -n -o TARGET -t cgroup2 | head -1)"
    [ -n "$root" ] || env_skip "cgroup v2 unified hierarchy not mounted"
    local cfg
    cfg="$(_config "$root" enforce false)"
    start_ebpf_agent "$cfg"

    local block
    block="$(_workload_status)" || true
    [ "$(jq -r '.attached' <<<"$block")" = "true" ] || { echo "# $block" >&3; false; }
    [ "$(jq -r '.hooks | length' <<<"$block")" -gt 0 ]
}
