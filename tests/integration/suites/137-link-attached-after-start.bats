#!/usr/bin/env bats
# A link a workload brings after the agent started gets the TC chain.
#
# A container's veth appears long after start-up, so the chain the agent put
# on its configured interface says nothing about it. The suite starts the
# agent, then creates a namespace and a veth pair whose peer it moves there,
# the way a runtime does. The host end must carry the agent's TC programs
# within seconds, the window between the announcement and the attach must be
# counted under the link's kind, and a link taken down again must leave
# nothing the agent still reports as held.

load '../lib/helpers'
load '../lib/ebpf_helpers'

HOT_NS="ebpfsentinel-hot"
HOT_HOST="es-hot-h"
HOT_PEER="es-hot-p"

setup_file() {
    require_root
    require_kernel 6 18
    require_tool jq
    require_tool bpftool
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 137 creates its links on the agent's host (local lane only)"
    fi

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ids.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    local waited=0
    until grep -q "link hot-plug watcher started" "$AGENT_LOG_FILE"; do
        waited=$((waited + 1))
        [ "$waited" -lt 20 ] || {
            stop_ebpf_agent 2>/dev/null || true
            echo "the link watcher did not start: $(grep -m1 'hot-plug watcher skipped' "$AGENT_LOG_FILE")" >&2
            return 1
        }
        sleep 1
    done
}

teardown_file() {
    ip link del "$HOT_HOST" 2>/dev/null || true
    ip netns del "$HOT_NS" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -f "${PREPARED_CONFIG:-}"
}

# _tc_programs <dev> - the TC programs attached on that device, one per line.
_tc_programs() {
    bpftool -j net show dev "$1" 2>/dev/null | jq -r '.[0].tc[]? | "\(.kind) \(.name)"'
}

@test "a veth created after start carries the agent's TC programs within seconds" {
    ip netns add "$HOT_NS"
    ip link add "$HOT_HOST" type veth peer name "$HOT_PEER"
    ip link set "$HOT_PEER" netns "$HOT_NS"
    ip link set "$HOT_HOST" up
    ip -n "$HOT_NS" link set "$HOT_PEER" up
    # A process in the namespace, so the watcher has an owner to look for.
    ip netns exec "$HOT_NS" sleep 60 </dev/null >/dev/null 2>&1 3>&- &

    local deadline=$((SECONDS + 15)) progs=""
    while [ "$SECONDS" -lt "$deadline" ]; do
        progs="$(_tc_programs "$HOT_HOST")"
        [ -n "$progs" ] && break
        sleep 0.5
    done
    echo "$progs"
    [ -n "$progs" ] || {
        grep -i "hot-plug" "$AGENT_LOG_FILE" | tail -5 >&3
        false
    }
    # Each of them is one the agent runs on its configured interface too.
    local configured name
    configured="$(_tc_programs "$EBPF_VETH_HOST" | awk '{print $2}' | sort -u)"
    for name in $(echo "$progs" | awk '{print $2}' | sort -u); do
        echo "$configured" | grep -qx "$name" || {
            echo "# ${name} is not among the agent's: ${configured}" >&3
            false
        }
    done
}

@test "the window before the attach is counted under the link's kind" {
    wait_for_metric ebpfsentinel_link_attach_gap_seconds_count 1 15 '{kind="veth"}'
    [ "$(get_metrics_value ebpfsentinel_link_attach_gap_seconds_count '{kind="veth"}')" -ge 1 ]
    # The packets it carried before the chain went on are a figure, zero or more.
    [ -n "$(get_metrics_value ebpfsentinel_link_attach_unguarded_packets_total '{kind="veth"}')" ]
}

@test "a link deleted again leaves the agent running and its configured interface attached" {
    ip link del "$HOT_HOST"
    sleep 2
    [ -z "$(ip -o link show "$HOT_HOST" 2>/dev/null)" ]
    [ -n "$(_tc_programs "$EBPF_VETH_HOST")" ]
    api_get /healthz >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}
