#!/usr/bin/env bats
# 77-kernel-floor-and-module-preflight.bats - the agent answers for its own
# kernel, refuses one below its floor, and names a missing module before a
# program fails on it.
#
# Three questions a host asks before anything else, each answered on the lane's
# real kernel rather than from a table:
#
#   - the kernel-features route reports the facts probed at startup, including
#     the file kfuncs and the newer kernel facts, each with a verdict rather
#     than a version inferred from the release string;
#   - an agent shown a release below 6.12 stops at startup and says what to
#     upgrade, with no degraded mode. The release is shown through a bind mount
#     over /proc/sys/kernel/osrelease inside a private mount namespace, so the
#     host is untouched and the agent reads exactly what it reads in production;
#   - with a module unloaded, the programs that call its kfuncs are refused by
#     name, with the module and the command that loads it, instead of the
#     resolver's error that names neither. The module is `fou`: the same check
#     covers nf_conntrack and xfrm_interface, but nf_conntrack is held by the
#     iptables rules of any host running Docker and cannot be unloaded there,
#     while nothing but fou6 holds fou.
#
# Requires: root, kernel >= 6.12, jq, unshare, modprobe. The module test skips
# when fou is built in or held by something other than fou6.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool unshare
    require_tool modprobe

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-floor-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-conntrack.yaml")"
    export PREPARED_CONFIG
    ALL_PROGRAMS_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-all-programs.yaml")"
    export ALL_PROGRAMS_CONFIG
}

teardown() {
    stop_ebpf_agent 2>/dev/null || true
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    modprobe fou 2>/dev/null || true
    modprobe fou6 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
}

@test "kernel-features reports the file kfuncs and the newer kernel facts with a verdict each" {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }

    local body
    body="$(api_get /api/v1/ebpf/kernel-features)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    # The helper sweep either ran or says why it did not; silence is the failure.
    echo "$body" | jq -e '.probed == true or ((.reason // "") != "")' >/dev/null
    [ "$(echo "$body" | jq -r '.file_kfuncs.probed')" = "true" ]
    echo "$body" | jq -e '.kfunc_features.features | length == 3' >/dev/null

    # Every fact carries its own verdict: confirmed, refused, or explicitly
    # unprobed with a reason, never a bare version comparison.
    local unexplained
    unexplained="$(echo "$body" | jq '[.kfunc_features.features[]
        | select(.usable == null and (.reason // "") == "")] | length')"
    [ "$unexplained" = "0" ]
}

@test "an agent shown a release below 6.12 refuses to start and names the upgrade" {
    local agent="${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
    [ -x "$agent" ] || soft_skip "no local agent build at $agent"

    local fake="${DATA_DIR}/osrelease"
    printf '6.11.0-29-generic\n' >"$fake"

    run timeout 30 unshare --mount --propagation private sh -c \
        'mount --bind "$1" /proc/sys/kernel/osrelease && exec "$2" --config "$3"' \
        sh "$fake" "$agent" "$PREPARED_CONFIG"

    [ "$status" -ne 0 ]
    [ "$status" -ne 124 ]
    [[ "$output" == *"refuses to start"* ]]
    [[ "$output" == *"6.11"* ]]
    [[ "$output" == *"6.12"* ]]
    # An Ubuntu release string earns the Ubuntu way up, not a generic line.
    [[ "$output" == *"linux-generic-hwe-24.04"* ]]
}

@test "with fou unloaded, the programs calling its kfuncs are refused naming the module" {
    if [ ! -d /sys/module/fou ]; then
        modprobe fou 2>/dev/null || env_skip "fou is not available on this kernel"
    fi
    [ -r /sys/module/fou/initstate ] || env_skip "fou is built into this kernel"
    modprobe -r fou6 fou 2>/dev/null || env_skip "fou is held by another user"
    [ ! -e /sys/kernel/btf/fou ]

    start_ebpf_agent "$ALL_PROGRAMS_CONFIG"

    local waited=0
    until grep -q 'registered by kernel module `fou`' "$AGENT_LOG_FILE" 2>/dev/null \
        || [ "$waited" -ge 30 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    stop_ebpf_agent
    modprobe fou
    modprobe fou6

    grep -q 'registered by kernel module `fou`' "$AGENT_LOG_FILE"
    grep -q 'modprobe fou' "$AGENT_LOG_FILE"
    grep -q '`tc_ids`' "$AGENT_LOG_FILE"
    ! grep -q 'not found in vmlinux or any loaded module BTF' "$AGENT_LOG_FILE"
}
