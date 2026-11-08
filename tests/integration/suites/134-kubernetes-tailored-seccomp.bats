#!/usr/bin/env bats
# 134-kubernetes-tailored-seccomp.bats - the chart's tailored seccomp option on
# a real node: the warden image writes the agent's profile into the kubelet's
# directory, the kubelet confines the agent container with it, and the agent
# still creates its user namespace and loads through its token under it.
# Requires: minikube, kubectl, helm, docker. VM-only, like 10-kubernetes: the
# minikube node is a container on the VM's kernel, so the agent pod loads
# eBPF there, and never on a workstation.

load '../lib/helpers'

NAMESPACE="ebpfsentinel-seccomp"
RELEASE="seccomp"
PROFILE_ON_NODE="/var/lib/kubelet/seccomp/ebpfsentinel/ebpfsentinel-agent.json"
# Overridable, so a lane that already built the agent image under another tag
# does not build it again.
AGENT_IMAGE="${AGENT_IMAGE:-ebpfsentinel:latest}"
WARDEN_IMAGE="${WARDEN_IMAGE:-ebpfsentinel-warden:latest}"
# The chart's default memory limit is below what the agent's maps take on
# start with its default configuration, and an agent killed for memory says
# nothing about its seccomp profile.
AGENT_MEMORY_LIMIT="${AGENT_MEMORY_LIMIT:-1Gi}"

agent_pod() {
    kubectl -n "$NAMESPACE" get pod \
        -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# The pid of a container of the agent pod, in the minikube node's pid
# namespace, read through the node's own container runtime.
container_pid() {
    local name="$1" id
    id="$(kubectl -n "$NAMESPACE" get pod "$(agent_pod)" \
        -o jsonpath="{.status.containerStatuses[?(@.name==\"${name}\")].containerID}{.status.initContainerStatuses[?(@.name==\"${name}\")].containerID}")"
    case "$id" in
        docker://*)
            docker exec minikube docker inspect -f '{{.State.Pid}}' "${id#docker://}" ;;
        containerd://* | cri-o://*)
            docker exec minikube crictl inspect -o go-template \
                --template '{{.info.pid}}' "${id#*://}" ;;
        *) return 1 ;;
    esac
}

# The seccomp mode the kernel holds for a container's main process: 0 is
# none, 2 is a filter.
container_seccomp_mode() {
    local pid
    pid="$(container_pid "$1")" || return 1
    docker exec minikube awk '/^Seccomp:/ {print $2}' "/proc/${pid}/status"
}

setup_file() {
    for tool in minikube kubectl helm docker; do
        command -v "$tool" &>/dev/null || env_skip "$tool not installed"
    done

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"

    # Same lock directory as 10-kubernetes, for the same reason: minikube
    # names its locks after the operation, and a root run collides with a
    # login user's stale lock in a sticky /tmp.
    TMPDIR="/var/tmp/ebpfsentinel-minikube-$(id -u)"
    export TMPDIR
    mkdir -p "$TMPDIR"
    chmod 700 "$TMPDIR"

    local mk_force=()
    if [ "$(id -u)" -eq 0 ]; then
        mk_force=(--force)
    fi
    if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
        reclaim_docker_residue
        if ! minikube start --driver=docker --cpus=2 --memory=2048 "${mk_force[@]}"; then
            echo "# minikube start failed - deleting the profile and retrying" >&3
            minikube delete --all &>/dev/null || true
            minikube start --driver=docker --cpus=2 --memory=2048 "${mk_force[@]}" \
                || env_skip "minikube cluster could not start on this host"
        fi
    fi

    if ! docker image inspect "$AGENT_IMAGE" &>/dev/null; then
        echo "# Staging eBPF programs for the agent image..." >&3
        stage_ebpf_objects "$PROJECT_ROOT" \
            || env_skip "no eBPF objects available to build the agent image"
        echo "# Building ${AGENT_IMAGE}..." >&3
        docker build -f "${PROJECT_ROOT}/Dockerfile.agent" -t "$AGENT_IMAGE" "$PROJECT_ROOT"
    fi
    # The warden image is what writes the profile, so one that predates the
    # subcommand is rebuilt rather than trusted.
    if ! docker run --rm --entrypoint /usr/local/bin/warden "$WARDEN_IMAGE" help 2>&1 \
        | grep -q install-seccomp-profile; then
        echo "# Building ${WARDEN_IMAGE}..." >&3
        docker build -f "${PROJECT_ROOT}/Dockerfile.warden" -t "$WARDEN_IMAGE" "$PROJECT_ROOT"
    fi
    minikube image load "$AGENT_IMAGE"
    minikube image load "$WARDEN_IMAGE"

    # A profile left by an earlier run would prove nothing about this one.
    docker exec minikube rm -f "$PROFILE_ON_NODE"

    kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=true &>/dev/null || true
    helm install "$RELEASE" "${PROJECT_ROOT}/charts/ebpfsentinel" \
        --namespace "$NAMESPACE" --create-namespace \
        --set "image.repository=${AGENT_IMAGE%:*},image.tag=${AGENT_IMAGE##*:},image.pullPolicy=IfNotPresent" \
        --set "wardenImage.repository=${WARDEN_IMAGE%:*},wardenImage.tag=${WARDEN_IMAGE##*:}" \
        --set daemonset.bpfToken.bpffsEmptyDir=true \
        --set daemonset.state.ephemeral=true \
        --set "daemonset.resources.limits.memory=${AGENT_MEMORY_LIMIT}" \
        --set daemonset.tailoredSeccomp.enabled=true

    # Running is what every test needs; Ready is asserted on its own below,
    # since a nested node may refuse an XDP attach the profile has no part in.
    local waited=0
    while [ "$waited" -lt 90 ]; do
        [ "$(kubectl -n "$NAMESPACE" get pod -l "app.kubernetes.io/instance=${RELEASE}" \
               -o jsonpath='{.items[0].status.phase}' 2>/dev/null)" = "Running" ] && break
        sleep 2
        waited=$((waited + 1))
    done
}

teardown_file() {
    if [ -n "${BATS_SUITE_TEST_NUMBER:-}" ] && command -v kubectl &>/dev/null; then
        kubectl -n "$NAMESPACE" get pods -o wide >&3 2>&1 || true
    fi
    helm uninstall "$RELEASE" --namespace "$NAMESPACE" &>/dev/null || true
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true &>/dev/null || true
}

# ── Tests ──────────────────────────────────────────────────────────

@test "the agent container is declared Localhost on the tailored profile" {
    local pod type profile
    pod="$(agent_pod)"
    [ -n "$pod" ]
    type="$(kubectl -n "$NAMESPACE" get pod "$pod" \
        -o jsonpath='{.spec.containers[?(@.name=="agent")].securityContext.seccompProfile.type}')"
    profile="$(kubectl -n "$NAMESPACE" get pod "$pod" \
        -o jsonpath='{.spec.containers[?(@.name=="agent")].securityContext.seccompProfile.localhostProfile}')"
    echo "seccompProfile.type=${type} localhostProfile=${profile}" >&3
    [ "$type" = "Localhost" ]
    [ "$profile" = "ebpfsentinel/ebpfsentinel-agent.json" ]
}

@test "the init container wrote the profile the repository ships, byte for byte" {
    local want got
    want="$(sha256sum "${PROJECT_ROOT}/dist/seccomp/ebpfsentinel-agent.json" | cut -d' ' -f1)"
    got="$(docker exec minikube sha256sum "$PROFILE_ON_NODE" | cut -d' ' -f1)"
    echo "dist ${want} node ${got}" >&3
    [ "$want" = "$got" ]
    run kubectl -n "$NAMESPACE" logs "$(agent_pod)" -c seccomp-profile
    assert_contains "$output" "seccomp profile written to /seccomp/ebpfsentinel/ebpfsentinel-agent.json"
}

@test "the agent pod runs with no restart" {
    local pod phase restarts
    pod="$(agent_pod)"
    sleep 10
    phase="$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}')"
    restarts="$(kubectl -n "$NAMESPACE" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
    echo "phase=${phase} agent restarts=${restarts}" >&3
    [ "$phase" = "Running" ]
    [ "$restarts" = "0" ]
}

@test "the kernel holds a seccomp filter on the agent and none on the warden" {
    local agent warden
    agent="$(container_seccomp_mode agent)"
    warden="$(container_seccomp_mode warden)"
    echo "agent Seccomp: ${agent}, warden Seccomp: ${warden}" >&3
    [ "$agent" = "2" ]
    [ "$warden" = "0" ]
}

@test "the agent creates its token and loads its programs under the profile" {
    # The profile exists so that the user namespace, the mount family and
    # bpf pass with no capability held; a token the agent could not create
    # is what too tight a profile looks like.
    local gate
    gate="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
    [ "$gate" = "0" ] || env_skip "kernel.apparmor_restrict_unprivileged_userns=1 on this host refuses the user namespace before seccomp is consulted"

    local pod log waited=0
    pod="$(agent_pod)"
    while [ "$waited" -lt 30 ]; do
        log="$(kubectl -n "$NAMESPACE" logs "$pod" -c agent 2>&1)"
        grep -q -e "eBPF loading via BPF token" -e "BPF token unavailable" <<<"$log" && break
        sleep 2
        waited=$((waited + 1))
    done
    grep "BPF token" <<<"$log" | head -3 >&3 || true
    run grep -c "BPF token unavailable" <<<"$log"
    [ "$output" = "0" ]
    run grep -c "eBPF loading via BPF token" <<<"$log"
    [ "$output" -ge 1 ]
}

@test "the agent is Ready under the profile" {
    run kubectl -n "$NAMESPACE" wait --for=condition=Ready pod \
        -l "app.kubernetes.io/instance=${RELEASE}" --timeout=120s
    echo "$output" >&3
    [ "$status" -eq 0 ]
}

@test "an API server agrees with the chart's own admission list with the option on" {
    run env HELM_ARGS="--set daemonset.tailoredSeccomp.enabled=true" \
        CHART="${PROJECT_ROOT}/charts/ebpfsentinel" \
        "${PROJECT_ROOT}/scripts/check-psa-claims.sh"
    echo "$output" | tail -5 >&3
    kubectl delete namespace ebpfsentinel-psa-baseline ebpfsentinel-psa-privileged \
        --ignore-not-found &>/dev/null || true
    [ "$status" -eq 0 ]
}
