#!/usr/bin/env bats
# 159-networkpolicy-from-the-chart.bats - Kubernetes NetworkPolicy carried
# out by the agent the OSS chart installs, with no operator and no custom
# resource: the chart alone, with `container.kubernetes.enabled` and
# `container.kubernetes.networkPolicy.mode`. In enforce mode a policy
# admitting nothing into a server pod refuses a client's connect, and the
# agent counts the refusal; lifted, the path reopens. In observe mode the
# same policy lets the client through and the agent counts what it would
# have refused. Observe raises no alert: a counter is all it writes.
#
# The cluster is a minikube node of its own profile on the bridge CNI, which
# implements no NetworkPolicy, so every refusal here is the agent's, and the
# observe half shows the CNI refusing nothing. kind is not used: its kindnet
# carries policies itself, and the agent VM provisions minikube.
# Requires: minikube, kubectl, helm, docker, jq. VM-only, like 10-kubernetes
# and 134-kubernetes-tailored-seccomp: the node is a container on the VM's
# kernel, so the agent pod loads eBPF there, and never on a workstation.

load '../lib/helpers'

PROFILE="ebpfsentinel-netpol"
NAMESPACE="ebpfsentinel-netpol"
APPS="netpol-apps"
RELEASE="netpol"
AGNHOST_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.53"
# Overridable, so a lane that already built the agent image under another tag
# does not build it again.
AGENT_IMAGE="${AGENT_IMAGE:-ebpfsentinel:latest}"
WARDEN_IMAGE="${WARDEN_IMAGE:-ebpfsentinel-warden:latest}"

# Every call names this suite's cluster, so a default profile another suite
# left running is never the one written to.
k() {
    kubectl --context "$PROFILE" "$@"
}

# The running agent pod of the current configuration: after an upgrade, the
# pod carrying the checksum of the configuration the DaemonSet now renders.
agent_pod() {
    local want
    want="$(k -n "$NAMESPACE" get daemonset -l "app.kubernetes.io/instance=${RELEASE}" -o json \
        | jq -r '.items[0].spec.template.metadata.annotations["checksum/config"] // empty')"
    k -n "$NAMESPACE" get pods -l "app.kubernetes.io/instance=${RELEASE}" -o json \
        | jq -r --arg want "$want" '[.items[]
            | select(.metadata.deletionTimestamp == null
                and .status.phase == "Running"
                and .metadata.annotations["checksum/config"] == $want)][0].metadata.name // empty'
}

# Wait for the agent of the current configuration to run and answer its
# metrics port. Running, not Ready: a nested node may refuse the XDP attach,
# which has no part in the cgroup hooks a NetworkPolicy rides on.
wait_for_agent() {
    local pod="" waited=0
    while [ "$waited" -lt 90 ]; do
        pod="$(agent_pod)"
        if [ -n "$pod" ] && k get --raw \
            "/api/v1/namespaces/${NAMESPACE}/pods/http:${pod}:9090/proxy/metrics" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        waited=$((waited + 1))
    done
    echo "no agent of the current configuration answered its metrics port" >&2
    k -n "$NAMESPACE" get pods -o wide >&2 || true
    k -n "$NAMESPACE" logs -l "app.kubernetes.io/instance=${RELEASE}" \
        --all-containers --tail=80 >&2 || true
    return 1
}

# One NETPOL_METRICS counter of the running agent, 0 until first counted.
netpol_count() {
    local body value
    body="$(k get --raw \
        "/api/v1/namespaces/${NAMESPACE}/pods/http:$(agent_pod):9090/proxy/metrics")" || return 1
    value="$(grep '^ebpfsentinel_packets_total{' <<<"$body" \
        | grep 'interface="NETPOL_METRICS"' | grep "action=\"$1\"" \
        | awk '{print $NF}' | head -1)"
    value="${value:-0}"
    echo "${value%.*}"
}

server_address() {
    echo "$(k -n "$APPS" get pod server -o jsonpath='{.status.podIP}'):8080"
}

client_reaches_server() {
    k -n "$APPS" exec client -- /agnhost connect "$(server_address)" --timeout=3s
}

# A policy selecting the server and admitting nothing into it.
apply_deny_policy() {
    k apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-server
  namespace: ${APPS}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
YAML
}

setup_file() {
    for tool in minikube kubectl helm docker jq; do
        command -v "$tool" &>/dev/null || soft_skip "${tool} not installed"
    done
    local gate
    gate="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
    [ "$gate" = "0" ] || lane_skip userns "kernel.apparmor_restrict_unprivileged_userns=1 on this host refuses the user namespace the agent loads its programs from"

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
    # A profile of its own, so the CNI is the one chosen here and not the one
    # a cluster left by another suite was started with. A profile left by an
    # earlier run of this suite is deleted rather than trusted.
    minikube delete -p "$PROFILE" &>/dev/null || true
    reclaim_docker_residue
    minikube start -p "$PROFILE" --driver=docker --cni=bridge \
        --cpus=2 --memory=2048 "${mk_force[@]}" \
        || env_skip "minikube cluster could not start on this host"

    if ! docker image inspect "$AGENT_IMAGE" &>/dev/null; then
        echo "# Staging eBPF programs for the agent image..." >&3
        stage_ebpf_objects "$PROJECT_ROOT" \
            || env_skip "no eBPF objects available to build the agent image"
        echo "# Building ${AGENT_IMAGE}..." >&3
        docker build -f "${PROJECT_ROOT}/Dockerfile.agent" -t "$AGENT_IMAGE" "$PROJECT_ROOT"
    fi
    if ! docker image inspect "$WARDEN_IMAGE" &>/dev/null; then
        echo "# Building ${WARDEN_IMAGE}..." >&3
        docker build -f "${PROJECT_ROOT}/Dockerfile.warden" -t "$WARDEN_IMAGE" "$PROJECT_ROOT"
    fi
    docker image inspect "$AGNHOST_IMAGE" &>/dev/null || docker pull "$AGNHOST_IMAGE"
    minikube -p "$PROFILE" image load "$AGENT_IMAGE"
    minikube -p "$PROFILE" image load "$WARDEN_IMAGE"
    minikube -p "$PROFILE" image load "$AGNHOST_IMAGE"

    helm install "$RELEASE" "${PROJECT_ROOT}/charts/ebpfsentinel" \
        --kube-context "$PROFILE" \
        --namespace "$NAMESPACE" --create-namespace \
        --set "image.repository=${AGENT_IMAGE%:*},image.tag=${AGENT_IMAGE##*:},image.pullPolicy=IfNotPresent" \
        --set "wardenImage.repository=${WARDEN_IMAGE%:*},wardenImage.tag=${WARDEN_IMAGE##*:}" \
        --set daemonset.bpfToken.pinLinksOnNode=false \
        --set daemonset.state.ephemeral=true \
        --set container.kubernetes.enabled=true \
        --set container.kubernetes.networkPolicy.mode=enforce
    wait_for_agent

    k create namespace "$APPS" --dry-run=client -o yaml | k apply -f - >/dev/null
    k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${APPS}
  labels: {app: server}
spec:
  containers:
    - name: server
      image: ${AGNHOST_IMAGE}
      imagePullPolicy: IfNotPresent
      args: [netexec, --http-port=8080]
      ports: [{containerPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: ${APPS}
  labels: {app: client}
spec:
  containers:
    - name: client
      image: ${AGNHOST_IMAGE}
      imagePullPolicy: IfNotPresent
      args: [pause]
YAML
    k -n "$APPS" wait --for=condition=Ready pod/server pod/client --timeout=180s
}

teardown_file() {
    if [ -n "${BATS_SUITE_TEST_NUMBER:-}" ] && command -v kubectl &>/dev/null; then
        k get pods -A -o wide >&3 2>&1 || true
        k -n "$NAMESPACE" logs -l "app.kubernetes.io/instance=${RELEASE}" \
            -c agent --tail=60 >&3 2>&1 || true
    fi
    helm uninstall "$RELEASE" --kube-context "$PROFILE" --namespace "$NAMESPACE" &>/dev/null || true
    minikube delete -p "$PROFILE" &>/dev/null || true
}

# ── Tests ──────────────────────────────────────────────────────────

@test "the chart alone renders enforce and grants the reads a policy needs" {
    run k -n "$NAMESPACE" get configmap -l "app.kubernetes.io/instance=${RELEASE}" -o yaml
    assert_contains "$output" 'mode: "enforce"'

    local account
    account="$(k -n "$NAMESPACE" get daemonset -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{.items[0].spec.template.spec.serviceAccountName}')"
    [ -n "$account" ]
    [ "$(k auth can-i watch networkpolicies.networking.k8s.io --all-namespaces \
        --as "system:serviceaccount:${NAMESPACE}:${account}")" = "yes" ]

    # No operator and no custom resource stand behind the agent.
    run k get crd -o name
    [[ "$output" != *ebpfsentinel* ]]
}

@test "the agent runs in enforce mode with no restart" {
    # Enforce refuses to start when the cgroup hooks do not attach, so a
    # running agent is one carrying the policy hooks.
    local pod restarts
    pod="$(agent_pod)"
    [ -n "$pod" ]
    sleep 10
    restarts="$(k -n "$NAMESPACE" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
    echo "agent ${pod} restarts=${restarts}" >&3
    [ "$restarts" = "0" ]
}

@test "with no policy the client reaches the server" {
    local streak=0
    for _ in $(seq 1 60); do
        if client_reaches_server >/dev/null 2>&1; then
            streak=$((streak + 1))
            [ "$streak" -ge 5 ] && break
        else
            streak=0
        fi
        sleep 1
    done
    [ "$streak" -ge 5 ]
}

@test "enforce: a policy admitting nothing refuses the client, and the agent counts it" {
    local before after refused=0
    before="$(netpol_count ingress_refused)"
    apply_deny_policy
    for _ in $(seq 1 30); do
        if ! client_reaches_server >/dev/null 2>&1; then
            refused=1
            break
        fi
        sleep 2
    done
    [ "$refused" -eq 1 ]

    # The refusal is the agent's: its own counter moved. Read until the
    # metrics loop has polled the kernel map.
    after="$before"
    for _ in $(seq 1 15); do
        after="$(netpol_count ingress_refused)"
        [ "$after" -gt "$before" ] && break
        sleep 2
    done
    echo "ingress_refused ${before} -> ${after}" >&3
    [ "$after" -gt "$before" ]
}

@test "enforce: lifting the policy reopens the path" {
    k -n "$APPS" delete networkpolicy deny-server --ignore-not-found >/dev/null
    for _ in $(seq 1 30); do
        client_reaches_server >/dev/null 2>&1 && return 0
        sleep 2
    done
    client_reaches_server
}

@test "observe: the same policy lets the client through and is counted as would refuse" {
    helm upgrade "$RELEASE" "${PROJECT_ROOT}/charts/ebpfsentinel" \
        --kube-context "$PROFILE" --namespace "$NAMESPACE" --reuse-values \
        --set container.kubernetes.networkPolicy.mode=observe
    wait_for_agent
    run k -n "$NAMESPACE" get configmap -l "app.kubernetes.io/instance=${RELEASE}" -o yaml
    assert_contains "$output" 'mode: "observe"'

    local would_before refused_before would_after refused_after
    would_before="$(netpol_count ingress_would_refuse)"
    refused_before="$(netpol_count ingress_refused)"
    apply_deny_policy
    # Long enough for the agent to have compiled the policy: in enforce it
    # refused within this window.
    sleep 10
    for _ in $(seq 1 5); do
        client_reaches_server
        sleep 1
    done

    would_after="$would_before"
    for _ in $(seq 1 15); do
        would_after="$(netpol_count ingress_would_refuse)"
        [ "$would_after" -gt "$would_before" ] && break
        sleep 2
    done
    refused_after="$(netpol_count ingress_refused)"
    echo "ingress_would_refuse ${would_before} -> ${would_after}, ingress_refused ${refused_before} -> ${refused_after}" >&3
    [ "$would_after" -gt "$would_before" ]
    [ "$refused_after" -eq "$refused_before" ]
    k -n "$APPS" delete networkpolicy deny-server --ignore-not-found >/dev/null
}
