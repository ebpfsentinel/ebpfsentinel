#!/usr/bin/env bats
# 98-container-label-policy.bats - a container's egress policy written in
# its own labels is put in force on that container and on no other.
#
# The suite asserts:
#
#   * A container labelled to enforce a deny list is refused the listed
#     destination, reaches the one not listed, and the refusal is an alert
#     carrying the rule its label produced.
#   * A container labelled with an allow list and a default deny reaches
#     the listed destination only.
#   * A container whose labels say no mode observes: the connect goes
#     through and the alert is raised.
#   * A container with a label that cannot be read gets no rule at all,
#     and the label reading names the label and the reason.
#   * A container with no policy label is not listed and reaches every
#     destination the others are refused.
#   * A container started after the agent is policed without a reload,
#     and its rules go when it is removed.
#
# Requires: root, kernel >= 6.12, jq, docker, python3, a static busybox.

load '../lib/helpers'
load '../lib/ebpf_helpers'

IMAGE="ebpfsentinel-test-labels:busybox"
PREFIX="ebpfsentinel-test-labels"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool docker
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 98 runs its containers beside the agent (local lane only)"
    fi
    docker info >/dev/null 2>&1 || env_skip "docker daemon not reachable"
    local busybox
    busybox="$(command -v busybox || true)"
    [ -n "$busybox" ] && file -L "$busybox" 2>/dev/null | grep -q "statically linked" \
        || env_skip "no statically linked busybox to build the test image from"

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-labels-$$"
    mkdir -p "${DATA_DIR}/rootfs/bin"
    cp "$busybox" "${DATA_DIR}/rootfs/bin/busybox"
    ln -s busybox "${DATA_DIR}/rootfs/bin/sh"
    ln -s busybox "${DATA_DIR}/rootfs/bin/nc"
    ln -s busybox "${DATA_DIR}/rootfs/bin/sleep"
    tar -C "${DATA_DIR}/rootfs" -c . | docker import - "$IMAGE" >/dev/null

    export GATEWAY
    GATEWAY="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
    [ -n "$GATEWAY" ] || { echo "no gateway on the default bridge" >&2; return 1; }

    # One listener per port on the bridge's gateway, each accepting and
    # closing at once, so a connect that is let through ends cleanly.
    python3 - "$GATEWAY" 7301 7302 7303 >/dev/null 2>&1 <<'PY' &
import socket, sys, threading
def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.close()
for p in sys.argv[2:]:
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()
threading.Event().wait()
PY
    echo $! > "${DATA_DIR}/listener.pid"

    _start deny \
        --label io.ebpfsentinel.policy.mode=enforce \
        --label "io.ebpfsentinel.policy.egress.deny=tcp/7301@${GATEWAY}/32"
    _start allowlist \
        --label io.ebpfsentinel.policy.mode=enforce \
        --label "io.ebpfsentinel.policy.egress.allow=tcp/7302@${GATEWAY}/32" \
        --label io.ebpfsentinel.policy.egress.default=deny
    _start observe \
        --label "io.ebpfsentinel.policy.egress.deny=tcp/7303@${GATEWAY}/32"
    _start broken \
        --label io.ebpfsentinel.policy.mode=enforce \
        --label "io.ebpfsentinel.policy.egress.deny=tcp/7301@${GATEWAY}/32, ftp/21"
    _start plain

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-label-policy.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_listed deny 30 || {
        api_get /api/v1/firewall/workload/labels >&2
        tail -30 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

teardown_file() {
    local name
    for name in deny allowlist observe broken plain late; do
        docker rm -f "${PREFIX}-${name}" >/dev/null 2>&1 || true
    done
    docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
    [ -f "${DATA_DIR:-}/listener.pid" ] && kill "$(cat "${DATA_DIR}/listener.pid")" 2>/dev/null
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-labels-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _start <name> [docker run options...] - one container that stays up.
_start() {
    local name="$1"
    shift
    docker run -d --name "${PREFIX}-${name}" "$@" "$IMAGE" /bin/sleep 3600 >/dev/null
}

_id() {
    docker inspect -f '{{.Id}}' "${PREFIX}-$1"
}

# _entry <name> - the label reading's entry for the container, or nothing.
_entry() {
    api_get /api/v1/firewall/workload/labels \
        | jq -c --arg id "$(_id "$1")" '.containers[] | select(.container_id == $id)'
}

_wait_listed() {
    local name="$1" tries="${2:-30}" i
    for i in $(seq 1 "$tries"); do
        [ -n "$(_entry "$name")" ] && return 0
        sleep 1
    done
    return 1
}

# _reach <name> <port> - whether the container's connect to the gateway
# on that port goes through.
_reach() {
    docker exec "${PREFIX}-$1" nc -w 2 "$GATEWAY" "$2" </dev/null >/dev/null 2>&1
}

# _label_rules <short id> - how many workload rules in force came from the
# labels of the container whose id starts so.
_label_rules() {
    api_get /api/v1/firewall/workload/rules \
        | jq --arg s "label-$1-" '[.. | objects | select((.rule // "") | tostring | startswith($s))] | length'
}

_label_alert() {
    local short
    short="$(_id "$1" | cut -c1-12)"
    wait_for_alert ".[] | select(.rule_id | startswith(\"label-${short}-\"))" "${2:-15}" 1
}

@test "an enforced deny label refuses the listed destination only, and the alert names its rule" {
    local entry
    entry="$(_entry deny)"
    [ "$(jq -r '.mode' <<<"$entry")" = "enforce" ]
    [ "$(jq -r '.problems | length' <<<"$entry")" = "0" ]
    [ "$(jq -r '.rules | length' <<<"$entry")" -ge 1 ]

    # Every docker exec is a new task in the container's cgroup, so three
    # attempts in a row are three chances for a task to clear what the label
    # put on the cgroup.
    local k
    for k in 1 2 3; do
        run _reach deny 7301
        [ "$status" -ne 0 ]
    done
    run _reach deny 7302
    [ "$status" -eq 0 ]

    run _label_alert deny
    [ "$status" -eq 0 ] || { tail -5 "$AGENT_LOG_FILE" >&3; false; }
    [ "$(jq -r '.dst_port' <<<"$output")" = "7301" ] \
        || assert_contains "$(jq -r '.message' <<<"$output")" "7301"
}

@test "an allow list with a default deny reaches the listed destination only" {
    _wait_listed allowlist 10
    run _reach allowlist 7302
    [ "$status" -eq 0 ]
    run _reach allowlist 7301
    [ "$status" -ne 0 ]
    run _reach allowlist 7303
    [ "$status" -ne 0 ]
}

@test "a label policy with no mode observes: the connect goes through and the alert is raised" {
    _wait_listed observe 10
    [ "$(jq -r '.mode' <<<"$(_entry observe)")" = "observe" ]
    run _reach observe 7303
    [ "$status" -eq 0 ]
    run _label_alert observe
    [ "$status" -eq 0 ]
}

@test "a label that cannot be read leaves the container with no rule, and says why" {
    _wait_listed broken 10
    local entry
    entry="$(_entry broken)"
    [ "$(jq -r '.rules | length' <<<"$entry")" = "0" ]
    [ "$(jq -r '.problems[0].label' <<<"$entry")" = "io.ebpfsentinel.policy.egress.deny" ]
    assert_contains "$(jq -r '.problems[0].reason' <<<"$entry")" "ftp"
    # The entry that could be read is not put in force on its own.
    run _reach broken 7301
    [ "$status" -eq 0 ]
}

@test "a container with no policy label is not listed and reaches what the others are refused" {
    [ -z "$(_entry plain)" ]
    run _reach plain 7301
    [ "$status" -eq 0 ]
    run _reach plain 7303
    [ "$status" -eq 0 ]
}

@test "a container started after the agent is policed without a reload, and its rules go with it" {
    _start late \
        --label io.ebpfsentinel.policy.mode=enforce \
        --label "io.ebpfsentinel.policy.egress.deny=tcp/7302@${GATEWAY}/32"
    _wait_listed late 30
    run _reach late 7302
    [ "$status" -ne 0 ]

    local short i gone=false
    short="$(_id late | cut -c1-12)"
    [ "$(_label_rules "$short")" -ge 1 ]
    docker rm -f "${PREFIX}-late" >/dev/null
    for i in $(seq 1 30); do
        if [ "$(_label_rules "$short")" = "0" ]; then
            gone=true
            break
        fi
        sleep 1
    done
    [ "$gone" = true ]
}
