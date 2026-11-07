#!/usr/bin/env bats
# 131-cri-runtimes-attribution.bats - a container containerd or CRI-O starts
# outside Kubernetes is attributed to its id and its runtime.
#
# The suite asserts, for each of the two CRI runtimes:
#
#   * A container started through the CRI with the systemd cgroup driver, the
#     way a kubelet on a systemd host starts one, raises an alert carrying the
#     runtime (`containerd` or `crio`), the container's full id and the
#     cgroup path the runtime gave it (`cri-containerd-<id>.scope` or
#     `crio-<id>.scope`). With no Kubernetes enricher there is no name or
#     image to add; the id and the runtime are what the documentation
#     promises outside a cluster.
#
# The pod shares the node's network, so no CNI is involved and the probe
# leaves through the inspected veth on egress.
#
# Lane: ../vagrant-runtimes. Requires: root, kernel >= 6.12, crictl, and the
# runtime's socket listening; each test skips when its runtime is absent.

load '../lib/helpers'
load '../lib/ebpf_helpers'

PROBE_PORT=65501
PROBE_IMAGE="docker.io/library/busybox:1.36"
CONTAINERD_SOCK="unix:///run/containerd/containerd.sock"
CRIO_SOCK="unix:///var/run/crio/crio.sock"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool curl
    require_tool crictl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-cri-$$"
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
    local endpoint pod
    for endpoint in "${CONTAINERD_SOCK}" "${CRIO_SOCK}"; do
        for pod in $(crictl --runtime-endpoint "${endpoint}" pods -q \
            --label ebpfsentinel-test=runtimes 2>/dev/null); do
            crictl --runtime-endpoint "${endpoint}" stopp "${pod}" >/dev/null 2>&1 || true
            crictl --runtime-endpoint "${endpoint}" rmp "${pod}" >/dev/null 2>&1 || true
        done
    done
    [ -n "${PROBE_LISTENER_PID:-}" ] && kill "${PROBE_LISTENER_PID}" 2>/dev/null
    ip netns exec "${EBPF_TEST_NS}" pkill -f "nc -l -p ${PROBE_PORT}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _run_probe <endpoint> <tag> - start a host-network pod and a probe
# container in it through the CRI; prints the container id.
_run_probe() {
    local endpoint="$1" tag="$2"
    local pod_cfg="${DATA_DIR}/pod-${tag}.json" ctr_cfg="${DATA_DIR}/ctr-${tag}.json"
    jq -n --arg name "probe-${tag}-$$" --arg uid "$(cat /proc/sys/kernel/random/uuid)" '{
        metadata: {name: $name, namespace: "ebpfsentinel-test", uid: $uid, attempt: 0},
        labels: {"ebpfsentinel-test": "runtimes"},
        log_directory: "/tmp",
        linux: {
            cgroup_parent: "ebpfsentineltest.slice",
            security_context: {namespace_options: {network: 2}}
        }
    }' >"${pod_cfg}"
    jq -n --arg image "${PROBE_IMAGE}" --arg ip "${EBPF_NS_IP}" --arg port "${PROBE_PORT}" '{
        metadata: {name: "probe"},
        image: {image: $image},
        command: ["sh", "-c",
            ("for i in 1 2 3 4 5; do (echo probe; sleep 0.1) | nc -w 1 " + $ip + " " + $port
             + " >/dev/null 2>&1 || true; done; sleep 2")],
        log_path: "probe.log",
        linux: {}
    }' >"${ctr_cfg}"

    local pod ctr
    pod="$(crictl --runtime-endpoint "${endpoint}" runp "${pod_cfg}")" || return 1
    ctr="$(crictl --runtime-endpoint "${endpoint}" create "${pod}" "${ctr_cfg}" "${pod_cfg}")" || return 1
    crictl --runtime-endpoint "${endpoint}" start "${ctr}" >/dev/null || return 1
    echo "${ctr}"
}

_endpoint_up() {
    crictl --runtime-endpoint "$1" version >/dev/null 2>&1
}

# _assert_attributed <container id> <runtime> <cgroup scope prefix>
_assert_attributed() {
    local id="$1" runtime="$2" scope="$3"
    run wait_for_alert "first(.[] | select(.container != null and .container.id == \"${id}\") | .container)" 20 1
    [ "$status" -eq 0 ] || {
        echo "# no alert carried container ${id}" >&3
        api_get /api/v1/alerts | jq -c '[.alerts[] | .container] | .[0:5]' >&3
        false
    }
    local ctr="$output"
    [ "$(jq -r .kind <<<"${ctr}")" = "container" ]
    [ "$(jq -r .runtime <<<"${ctr}")" = "${runtime}" ] || {
        echo "# runtime: $(jq -r .runtime <<<"${ctr}")" >&3
        false
    }
    [[ "$(jq -r .cgroup_path <<<"${ctr}")" == *"${scope}-${id}.scope"* ]] || {
        echo "# cgroup path: $(jq -r .cgroup_path <<<"${ctr}")" >&3
        false
    }
}

@test "a container containerd starts through the CRI is attributed to its id and runtime" {
    _endpoint_up "${CONTAINERD_SOCK}" || env_skip "containerd's CRI socket is not answering"
    local id
    id="$(_run_probe "${CONTAINERD_SOCK}" containerd)"
    [ -n "${id}" ]
    _assert_attributed "${id}" containerd cri-containerd
}

@test "a container CRI-O starts is attributed to its id and runtime" {
    _endpoint_up "${CRIO_SOCK}" || env_skip "CRI-O's socket is not answering"
    local id
    id="$(_run_probe "${CRIO_SOCK}" crio)"
    [ -n "${id}" ]
    _assert_attributed "${id}" crio crio
}
