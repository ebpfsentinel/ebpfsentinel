#!/usr/bin/env bats
# 130-podman-attribution.bats - a container Podman runs is named in the alert
# it raises, rootful and rootless.
#
# The suite asserts:
#
#   * A rootful Podman container dialling the probe port raises an alert
#     carrying runtime `podman`, the container's full id, its name and its
#     image, and the agent reports the rootful runtime as reachable.
#   * A rootless container, run by a user whose `podman.socket` listens under
#     /run/user/<uid>, is named the same way, and the agent reports that
#     user's runtime as reachable.
#
# Both containers share the node's network, so the probe leaves through the
# inspected veth on egress where the sending socket's cgroup is readable.
#
# Lane: ../vagrant-runtimes. Requires: root, kernel >= 6.12, podman with its
# rootful socket listening, and for the rootless test a user with lingering
# and `podman.socket` enabled.

load '../lib/helpers'
load '../lib/ebpf_helpers'

PROBE_PORT=65501
PROBE_IMAGE="docker.io/library/busybox:1.36"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool curl
    # Only ../vagrant-runtimes carries the runtimes; elsewhere the skip says
    # where the suite runs rather than what this machine lacks.
    command -v podman >/dev/null 2>&1 ||
        env_skip "suite 130 runs its containers through Podman (runtimes lane only: ../vagrant-runtimes)"

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    ROOTLESS_USER="$(_rootless_user)"
    export ROOTLESS_USER

    export DATA_DIR="/tmp/ebpfsentinel-test-data-podman-$$"
    mkdir -p "${DATA_DIR}"
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-runtimes.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        tail -20 "${AGENT_LOG_FILE}" >&2
        return 1
    }

    ip netns exec "${EBPF_TEST_NS}" sh -c \
        "while true; do nc -l -p ${PROBE_PORT} -w 2 >/dev/null 2>&1 || sleep 0.2; done" &
    export PROBE_LISTENER_PID=$!
}

teardown_file() {
    podman rm -f "probe-rootful-$$" >/dev/null 2>&1 || true
    if [ -n "${ROOTLESS_USER:-}" ]; then
        _rootless podman rm -f "probe-rootless-$$" >/dev/null 2>&1 || true
    fi
    [ -n "${PROBE_LISTENER_PID:-}" ] && kill "${PROBE_LISTENER_PID}" 2>/dev/null
    ip netns exec "${EBPF_TEST_NS}" pkill -f "nc -l -p ${PROBE_PORT}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR}"
    rm -f "${PREPARED_CONFIG:-}"
}

_probe_script() {
    printf 'for i in 1 2 3 4 5; do (echo probe; sleep 0.1) | nc -w 1 %s %s >/dev/null 2>&1 || true; done' \
        "${EBPF_NS_IP}" "${PROBE_PORT}"
}

# The first user whose rootless socket exists, unless the lane names one.
_rootless_user() {
    if [ -n "${PODMAN_ROOTLESS_USER:-}" ]; then
        echo "${PODMAN_ROOTLESS_USER}"
        return
    fi
    local sock
    for sock in /run/user/*/podman/podman.sock; do
        [ -S "${sock}" ] && { stat -c %U "${sock}"; return; }
    done
}

# _rootless <cmd...> - run as the rootless user, inside their own session bus.
_rootless() {
    local uid
    uid="$(id -u "${ROOTLESS_USER}")"
    (cd / && runuser -u "${ROOTLESS_USER}" -- env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" "$@")
}

# _alert_for <container id> - the container block of an alert naming that id.
_alert_for() {
    wait_for_alert "first(.[] | select(.container != null and .container.id == \"$1\") | .container)" 20 1
}

_runtime_reach() {
    api_get /api/v1/agent/status | jq -r --arg uid "$1" \
        '.container_coverage.podman_runtimes[]?
         | select((.uid | tostring) == (if $uid == "" then "null" else $uid end)) | .reach'
}

@test "a rootful Podman container is named by id, name and image" {
    [ -S /run/podman/podman.sock ] || env_skip "the rootful podman.socket is not listening"
    local name="probe-rootful-$$" id
    id="$(podman run -d --name "${name}" --network host "${PROBE_IMAGE}" sh -c "$(_probe_script)")"
    podman wait "${name}" >/dev/null

    run _alert_for "${id}"
    [ "$status" -eq 0 ] || {
        echo "# no alert carried container ${id}" >&3
        api_get /api/v1/alerts | jq -c '[.alerts[] | .container] | .[0:5]' >&3
        false
    }
    local ctr="$output"
    [ "$(jq -r .runtime <<<"${ctr}")" = "podman" ]
    [ "$(jq -r .name <<<"${ctr}")" = "${name}" ]
    [[ "$(jq -r .image <<<"${ctr}")" == *busybox* ]]
    [[ "$(jq -r .cgroup_path <<<"${ctr}")" == *"libpod-${id}"* ]]
    [ "$(_runtime_reach "")" = "reachable" ]
}

@test "a rootless Podman container is named through its user's own socket" {
    [ -n "${ROOTLESS_USER}" ] || env_skip "no user runs a rootless podman.socket"
    local uid name="probe-rootless-$$" id
    uid="$(id -u "${ROOTLESS_USER}")"
    id="$(_rootless podman run -d --name "${name}" --network host "${PROBE_IMAGE}" sh -c "$(_probe_script)")"
    _rootless podman wait "${name}" >/dev/null

    run _alert_for "${id}"
    [ "$status" -eq 0 ] || {
        echo "# no alert carried container ${id}" >&3
        api_get /api/v1/alerts | jq -c '[.alerts[] | .container] | .[0:5]' >&3
        false
    }
    local ctr="$output"
    [ "$(jq -r .runtime <<<"${ctr}")" = "podman" ]
    [[ "$(jq -r .cgroup_path <<<"${ctr}")" == *"user@${uid}.service"*"libpod-${id}"* ]]
    [ "$(_runtime_reach "${uid}")" = "reachable" ] || {
        echo "# the runtime of uid ${uid}: $(_runtime_reach "${uid}")" >&3
        false
    }
    [ "$(jq -r .name <<<"${ctr}")" = "${name}" ]
    [[ "$(jq -r .image <<<"${ctr}")" == *busybox* ]]
}
