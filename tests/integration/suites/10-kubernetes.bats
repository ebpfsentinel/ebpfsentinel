#!/usr/bin/env bats
# 10-kubernetes.bats — Kubernetes (Minikube) deployment tests
# Requires: minikube, kubectl
# NOTE: This suite is designed for VM-only execution (not CI).

load '../lib/helpers'

K8S_NAMESPACE="ebpfsentinel-test"
K8S_FIXTURES="${BATS_TEST_DIRNAME}/../fixtures/k8s"

setup_file() {
    # Skip if minikube is not available
    if ! command -v minikube &>/dev/null; then
        skip "minikube not installed"
    fi
    if ! command -v kubectl &>/dev/null; then
        skip "kubectl not installed"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"

    # Start minikube if not running
    if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
        minikube start --driver=docker --cpus=2 --memory=2048
    fi

    # Load local Docker image into minikube
    if docker image inspect ebpfsentinel:latest &>/dev/null 2>&1; then
        minikube image load ebpfsentinel:latest
    fi

    # Wait for namespace to be fully deleted if still terminating
    local ns_wait=0
    while kubectl get namespace "$K8S_NAMESPACE" 2>/dev/null | grep -q "Terminating" && [ "$ns_wait" -lt 30 ]; do
        sleep 2
        ns_wait=$((ns_wait + 1))
    done

    # Apply K8s manifests
    kubectl apply -f "${K8S_FIXTURES}/namespace.yaml"
    kubectl apply -f "${K8S_FIXTURES}/serviceaccount.yaml"
    kubectl apply -f "${K8S_FIXTURES}/rbac.yaml"
    kubectl apply -f "${K8S_FIXTURES}/configmap.yaml"
    kubectl apply -f "${K8S_FIXTURES}/daemonset.yaml"

    # Wait for pod to be ready (up to 120s)
    kubectl -n "$K8S_NAMESPACE" wait --for=condition=Ready pod \
        -l app.kubernetes.io/name=ebpfsentinel \
        --timeout=120s 2>/dev/null || true
}

teardown_file() {
    # Cleanup K8s resources
    kubectl delete namespace "$K8S_NAMESPACE" --ignore-not-found=true 2>/dev/null || true
    kubectl delete clusterrole ebpfsentinel --ignore-not-found=true 2>/dev/null || true
    kubectl delete clusterrolebinding ebpfsentinel --ignore-not-found=true 2>/dev/null || true
}

# ── Tests ──────────────────────────────────────────────────────────

@test "minikube is running" {
    command -v minikube &>/dev/null || skip "minikube not installed"

    local status
    status="$(minikube status --format='{{.Host}}' 2>/dev/null)" || true
    [ "$status" = "Running" ]
}

@test "DaemonSet pod reaches Running state" {
    command -v kubectl &>/dev/null || skip "kubectl not installed"

    local phase
    phase="$(kubectl -n "$K8S_NAMESPACE" get pod \
        -l app.kubernetes.io/name=ebpfsentinel \
        -o jsonpath='{.items[0].status.phase}' 2>/dev/null)" || true
    [ "$phase" = "Running" ]
}

@test "liveness probe passes (0 restarts)" {
    command -v kubectl &>/dev/null || skip "kubectl not installed"

    # Give the probes time to run
    sleep 15

    local restarts
    restarts="$(kubectl -n "$K8S_NAMESPACE" get pod \
        -l app.kubernetes.io/name=ebpfsentinel \
        -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null)" || restarts="unknown"
    [ "$restarts" = "0" ]
}

@test "ServiceAccount exists" {
    command -v kubectl &>/dev/null || skip "kubectl not installed"

    run kubectl -n "$K8S_NAMESPACE" get serviceaccount ebpfsentinel
    [ "$status" -eq 0 ]
}

@test "metrics endpoint accessible via port-forward" {
    command -v kubectl &>/dev/null || skip "kubectl not installed"

    local pod_name
    pod_name="$(kubectl -n "$K8S_NAMESPACE" get pod \
        -l app.kubernetes.io/name=ebpfsentinel \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)" || skip "No pod found"

    # Pick a random local port to avoid conflicts with other suites
    local local_port=$((28000 + RANDOM % 1000))

    # Start port-forward in background, capture stderr to detect readiness
    local pf_log="/tmp/ebpfsentinel-pf-$$.log"
    kubectl -n "$K8S_NAMESPACE" port-forward "$pod_name" "${local_port}:8080" >"$pf_log" 2>&1 &
    local pf_pid=$!

    # Wait for port-forward to be ready (kubectl prints "Forwarding from ...")
    local pf_wait=0
    while ! grep -q "Forwarding" "$pf_log" 2>/dev/null && [ "$pf_wait" -lt 15 ]; do
        sleep 1
        pf_wait=$((pf_wait + 1))
        # Bail early if the process died
        kill -0 "$pf_pid" 2>/dev/null || break
    done

    # Curl the forwarded port from the host
    local output=""
    local attempts=0
    while [ "$attempts" -lt 5 ]; do
        output="$(curl -sf --max-time 5 "http://127.0.0.1:${local_port}/metrics" 2>&1)" || true
        if [[ "$output" == *"# HELP"* ]]; then
            break
        fi
        sleep 2
        attempts=$((attempts + 1))
    done

    # Cleanup
    kill "$pf_pid" 2>/dev/null || true
    wait "$pf_pid" 2>/dev/null || true
    rm -f "$pf_log"

    assert_contains "$output" "# HELP"
}
