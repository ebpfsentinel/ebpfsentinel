#!/usr/bin/env bats
# 140-enforcement-survives-the-agent.bats - the datapath keeps enforcing when
# the agent dies, and a restarted agent adopts it instead of attaching again.
#
# The suite asserts:
#
#   * A flow the firewall denies stays denied after the agent is killed with
#     SIGKILL, and a flow it lets through still passes: the hooks are attached
#     and running the last rules, not an interface left dead.
#   * The link pins are on the host bpffs while no agent runs.
#   * A restarted agent adopts the pinned links: one XDP program on the
#     interface and each TC program once, the adoption is logged, and the
#     deny still holds.
#   * An interface deleted and created again while no agent ran is attached
#     anew by the next agent: the pinned link on the old device is dead and
#     is not adopted.
#   * `ebpfsentinel-agent uninstall` after a graceful stop removes the pins
#     and leaves nothing attached, so the denied flow passes.
#
# Runs on all three lanes: the local lane drives the flow from the test
# namespace, the 2-VM and 3-VM lanes from the client VM toward the agent VM.
#
# Requires: root, kernel >= 6.18, bpftool, ncat, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

DENIED_PORT=7777
ALLOWED_PORT=9989
PIN_DIR=/sys/fs/bpf/ebpfsentinel-links

setup_file() {
    require_root
    require_kernel 6 18
    require_tool bpftool
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-survive-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-firewall.yaml")"
    export PREPARED_CONFIG
    _start
}

teardown_file() {
    _on_agent "pkill -f 'ncat -l -p ${DENIED_PORT}'; pkill -f 'ncat -l -p ${ALLOWED_PORT}'" \
        2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    _uninstall >/dev/null 2>&1 || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-survive-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

_vm_lane() {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || [ "${EBPF_3VM_MODE:-false}" = "true" ]
}

# _on_agent <shell> - run a command where the agent runs.
_on_agent() {
    if _vm_lane; then
        _agent_ssh_sudo sh -c "$1"
    else
        sh -c "$1"
    fi
}

# _agent_binary - the agent binary on the agent's host.
_agent_binary() {
    if _vm_lane; then
        echo /usr/local/bin/ebpfsentinel-agent
    else
        echo "${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
    fi
}

_start() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

# _listen <port> - a listener on the agent's host that answers each
# connection, for the length of one test.
_listen() {
    _on_agent "nohup timeout 20 ncat -l -p $1 -k -e /bin/cat >/dev/null 2>&1 &"
    sleep 0.5
}

# _reaches <port> - whether a connection from the client side to the agent's
# host completes and gets an answer. `--no-shutdown` keeps the connection
# open once HELLO is sent: without it ncat closes on the end of its input
# before the echo comes back, and an open port reads as refused.
_reaches() {
    local out
    if _vm_lane; then
        out="$(echo HELLO | timeout 4 ncat -w 2 --no-shutdown "$EBPF_HOST_IP" "$1" 2>/dev/null)" || true
    else
        out="$(echo HELLO | ip netns exec "$EBPF_TEST_NS" \
            timeout 4 ncat -w 2 --no-shutdown "$EBPF_HOST_IP" "$1" 2>/dev/null)" || true
    fi
    [ -n "$out" ]
}

# _refused <port> - the opposite, written out: bats does not fail a test on a
# negated command that is not its last.
_refused() {
    if _reaches "$1"; then
        echo "# port $1 was reached" >&3
        return 1
    fi
}

# _kill_hard - end the agent the way a crash or an OOM kill does. The warden
# is left running: it holds nothing the datapath needs, and a node whose agent
# died keeps its warden too.
_kill_hard() {
    _on_agent "pkill -9 -f 'ebpfsentinel-agent(-staged)? .*--config'" 2>/dev/null || true
    local waited=0
    while _on_agent "pgrep -f 'ebpfsentinel-agent(-staged)? .*--config'" >/dev/null 2>&1; do
        waited=$((waited + 1))
        [ "$waited" -lt 20 ] || return 1
        sleep 0.2
    done
}

_uninstall() {
    _on_agent "env -u EBPFSENTINEL_WARDEN_SOCK $(_agent_binary) uninstall"
}

# _xdp_programs <dev> / _tc_programs <dev> - what is attached there, one per line.
_xdp_programs() {
    bpftool -j net show dev "$1" 2>/dev/null | jq -r '.[0].xdp[]? | .name'
}

_tc_programs() {
    bpftool -j net show dev "$1" 2>/dev/null | jq -r '.[0].tc[]? | "\(.kind) \(.name)"'
}

@test "the denied flow is refused and the allowed one passes while the agent runs" {
    _listen "$DENIED_PORT"
    _listen "$ALLOWED_PORT"
    _refused "$DENIED_PORT"
    _reaches "$ALLOWED_PORT"
}

@test "after SIGKILL the denied flow stays refused and the allowed one still passes" {
    _kill_hard
    _listen "$DENIED_PORT"
    _listen "$ALLOWED_PORT"
    _refused "$DENIED_PORT"
    _reaches "$ALLOWED_PORT"
}

@test "the links are pinned on the host bpffs and attached while no agent runs" {
    local pins
    pins="$(_on_agent "ls ${PIN_DIR}")"
    echo "$pins"
    echo "$pins" | grep -q '^xdp-'
    [ "$(_xdp_programs "$EBPF_VETH_HOST" | wc -l)" -eq 1 ]
}

@test "a restarted agent adopts the pinned links and attaches nothing twice" {
    _start
    local waited=0
    until grep -q "pinned links adopted" "$AGENT_LOG_FILE" 2>/dev/null \
        || _on_agent "grep -q 'pinned links adopted' ${_REMOTE_LOG_FILE:-/nonexistent}" 2>/dev/null; do
        waited=$((waited + 1))
        [ "$waited" -lt 30 ] || {
            echo "# no adoption logged" >&3
            false
        }
        sleep 1
    done

    [ "$(_xdp_programs "$EBPF_VETH_HOST" | wc -l)" -eq 1 ]
    local tc dupes
    tc="$(_tc_programs "$EBPF_VETH_HOST")"
    echo "$tc"
    dupes="$(echo "$tc" | sort | uniq -d)"
    [ -z "$dupes" ] || {
        echo "# attached twice: ${dupes}" >&3
        false
    }

    _listen "$DENIED_PORT"
    _listen "$ALLOWED_PORT"
    _refused "$DENIED_PORT"
    _reaches "$ALLOWED_PORT"
}

@test "an interface created again while no agent ran is attached anew, not adopted dead" {
    _vm_lane && env_skip "suite 140 deletes and creates its test interface again (local lane only)"

    _kill_hard
    destroy_test_netns
    create_test_netns
    [ "$(_xdp_programs "$EBPF_VETH_HOST" | wc -l)" -eq 0 ]

    _start
    local waited=0
    until grep -q "pinned links adopted" "$AGENT_LOG_FILE" 2>/dev/null; do
        waited=$((waited + 1))
        [ "$waited" -lt 30 ] || {
            echo "# no adoption logged" >&3
            false
        }
        sleep 1
    done

    [ "$(_xdp_programs "$EBPF_VETH_HOST" | wc -l)" -eq 1 ] || {
        grep -E "pinned link|not swapped" "$AGENT_LOG_FILE" | tail -5 >&3
        false
    }
    _listen "$DENIED_PORT"
    _listen "$ALLOWED_PORT"
    _refused "$DENIED_PORT"
    _reaches "$ALLOWED_PORT"
}

@test "uninstall after a stop removes the pins and the hooks with them" {
    stop_ebpf_agent
    _uninstall
    [ -z "$(_on_agent "ls ${PIN_DIR} 2>/dev/null")" ]
    [ "$(_xdp_programs "$EBPF_VETH_HOST" | wc -l)" -eq 0 ]
    _listen "$DENIED_PORT"
    _reaches "$DENIED_PORT"
}
