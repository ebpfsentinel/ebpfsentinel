#!/usr/bin/env bats
# 97-fim-inside-a-container.bats - a file written inside a container is
# reported at the path the container sees, by the process that wrote it.
#
# The suite asserts:
#
#   * A file dropped under /etc/cron.d inside a container raises the host
#     rule naming that path, which only the path rooted inside the
#     container matches: the host path under Docker's storage does not.
#   * The alert names the writing process inside the container.
#   * The same file written on the host under a directory ending in
#     etc/cron.d raises nothing: the host path does not match the rule.
#
# Requires: root, kernel >= 6.12, jq, docker, a static busybox.

load '../lib/helpers'
load '../lib/ebpf_helpers'

IMAGE="ebpfsentinel-test-fim:busybox"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool docker

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 97 runs its container beside the agent (local lane only)"
    fi
    docker info >/dev/null 2>&1 || env_skip "docker daemon not reachable"
    local busybox
    busybox="$(command -v busybox || true)"
    [ -n "$busybox" ] && file -L "$busybox" 2>/dev/null | grep -q "statically linked" \
        || env_skip "no statically linked busybox to build the test image from"

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-fim-container-$$"
    mkdir -p "${DATA_DIR}/rootfs/bin" "${DATA_DIR}/rootfs/etc/cron.d" "${DATA_DIR}/rootfs/tmp"
    cp "$busybox" "${DATA_DIR}/rootfs/bin/busybox"
    ln -s busybox "${DATA_DIR}/rootfs/bin/sh"
    # An image built from the host's own busybox, so the suite pulls nothing.
    tar -C "${DATA_DIR}/rootfs" -c . | docker import - "$IMAGE" >/dev/null

    export DOCKER_ROOT
    DOCKER_ROOT="$(docker info -f '{{.DockerRootDir}}')"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-fim-container.yaml")"
    export PREPARED_CONFIG
    sed -i -e "s|__DOCKER_ROOT__|${DOCKER_ROOT}|" "$PREPARED_CONFIG"
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    local attempt=0
    while ! grep -q "file watch running" "$AGENT_LOG_FILE" && [ "$attempt" -lt 30 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    grep -q "file watch running" "$AGENT_LOG_FILE" || {
        tail -30 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

teardown_file() {
    docker rm -f ebpfsentinel-test-fim >/dev/null 2>&1 || true
    docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-fim-container-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

_dump() {
    api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.rule_id == "fim-container-cron")]' >&3
}

@test "a file dropped under /etc/cron.d inside a container is reported at that path, with its writer" {
    docker run -d --name ebpfsentinel-test-fim "$IMAGE" /bin/sh -c \
        'sleep 2; echo "* * * * * root /tmp/x" > /etc/cron.d/backdoor; sleep 30' >/dev/null
    local host_pid
    host_pid="$(docker inspect -f '{{.State.Pid}}' ebpfsentinel-test-fim)"
    [ -n "$host_pid" ] && [ "$host_pid" != "0" ]

    run wait_for_alert '.[] | select(.rule_id == "fim-container-cron")' 30 1
    [ "$status" -eq 0 ] || { _dump; tail -5 "$AGENT_LOG_FILE" >&3; false; }
    local alert="$output"
    assert_contains "$(jq -r '.message' <<<"$alert")" "/etc/cron.d/backdoor"
    # The writer is the container's shell, a host pid whose root is the
    # container's: its parent is the process Docker started.
    local writer
    writer="$(jq -r '.workload.pid // empty' <<<"$alert")"
    [ -n "$writer" ] || { echo "# $alert" >&3; false; }
    [ "$writer" = "$host_pid" ] || [ "$(jq -r '.workload.ancestry.ancestors[0].pid // empty' <<<"$alert")" = "$host_pid" ]
}

@test "the same file written on the host under a directory ending in etc/cron.d raises nothing" {
    local before
    before="$(api_get /api/v1/alerts | jq '[.alerts // . | .[] | select(.rule_id == "fim-container-cron")] | length')"
    mkdir -p "${DATA_DIR}/host/etc/cron.d"
    echo "* * * * * root /tmp/x" > "${DATA_DIR}/host/etc/cron.d/backdoor"
    sleep 6
    [ "$(api_get /api/v1/alerts | jq '[.alerts // . | .[] | select(.rule_id == "fim-container-cron")] | length')" -eq "$before" ]
}
