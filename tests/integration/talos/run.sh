#!/usr/bin/env bash
# End-to-end Kubernetes test for the eBPFsentinel agent on a local Talos cluster.
#
# Why Talos + qemu: minikube/kind run the node as a container, so the agent's
# BPF-token launcher (which unshare()s a child user namespace to create a
# delegated bpffs) hits a nested-userns wall. Talos qemu nodes are real VMs with
# a real kernel (>= 6.12 on Talos 1.13), so the launcher and real eBPF attach
# work exactly as on a production node.
#
# Usage:
#   tests/integration/talos/run.sh prep       # build/push image to local registry (NON-root)
#   sudo tests/integration/talos/run.sh up     # create cluster + deploy + verify  (ROOT: qemu net)
#   sudo tests/integration/talos/run.sh down   # destroy cluster + registry        (ROOT)
#
# `up`/`down` need root because the qemu provisioner builds a bridge + tap
# devices and NAT rules on the host. Plain `sudo` (no `-E`): the script resolves
# the invoking user via $SUDO_USER so talosctl/kubectl state lands in their home.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

CLUSTER_NAME="ebpfsentinel-e2e"
CIDR="10.5.0.0/24"
GATEWAY="10.5.0.1"
REGISTRY_PORT="5005"
REGISTRY_NAME="talos-e2e-registry"
IMAGE_LOCAL="localhost:${REGISTRY_PORT}/ebpfsentinel:latest"   # push (docker treats localhost as insecure)
NAMESPACE="ebpfsentinel-e2e"
RELEASE="ebpfsentinel"
CHART="${PROJECT_ROOT}/charts/ebpfsentinel"
VALUES="${SCRIPT_DIR}/values-talos.yaml"
PATCH="${SCRIPT_DIR}/patch-all.yaml"

# Resolve the invoking user even under sudo (sudoers here forbids `-E`, so HOME
# is reset to /root and PATH is sanitized). Point HOME/PATH at the real user so
# talosctl (in ~/.local/bin) is found and talosconfig/kubeconfig land in the
# user's home — then chown state back at the end of `up`.
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"
[ -n "${REAL_HOME}" ] || REAL_HOME="${HOME}"
export HOME="${REAL_HOME}"
export PATH="${REAL_HOME}/.local/bin:/usr/local/bin:/snap/bin:/usr/bin:/bin:${PATH}"

log() { printf '\033[1;36m[talos-e2e]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[talos-e2e] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── prep: image into local registry (non-root) ────────────────────────────────
prep() {
  command -v docker >/dev/null || die "docker not found"

  if ! docker image inspect ebpfsentinel:latest >/dev/null 2>&1; then
    log "Staging eBPF objects + building ebpfsentinel:latest"
    mkdir -p "${PROJECT_ROOT}/ebpf-out"
    find "${PROJECT_ROOT}/crates/ebpf-programs/"*/target/bpfel-unknown-none/release \
      -maxdepth 1 -type f ! -name '*.d' ! -name '*.fingerprint' ! -name '.cargo*' \
      -exec cp {} "${PROJECT_ROOT}/ebpf-out/" \; 2>/dev/null || true
    docker build -t ebpfsentinel:latest "${PROJECT_ROOT}"
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}"; then
    log "Starting local registry on :${REGISTRY_PORT}"
    docker rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
    docker run -d --restart=always -p "${REGISTRY_PORT}:5000" --name "${REGISTRY_NAME}" registry:2 >/dev/null
  fi

  log "Tag + push ${IMAGE_LOCAL}"
  docker tag ebpfsentinel:latest "${IMAGE_LOCAL}"
  docker push "${IMAGE_LOCAL}"
  log "prep done — image in registry as repo 'ebpfsentinel' (pulled in-cluster via ${GATEWAY}:${REGISTRY_PORT})"
}

# ── up: cluster + deploy + verify (root) ──────────────────────────────────────
cluster_up() {
  [ "$(id -u)" -eq 0 ] || die "run 'up' as root: sudo -E $0 up"
  command -v talosctl >/dev/null || die "talosctl not found in PATH (${PATH})"

  docker ps --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}" \
    || die "local registry not running — run (non-root): $0 prep"

  if [ -d "${HOME}/.talos/clusters/${CLUSTER_NAME}" ]; then
    log "Cluster '${CLUSTER_NAME}' already exists — skipping create, resuming deploy"
  else
    log "Creating Talos qemu cluster '${CLUSTER_NAME}' (1 control-plane + 2 workers)"
    # cluster create waits for full health and merges kubeconfig into ~/.kube/config.
    talosctl cluster create qemu \
      --name "${CLUSTER_NAME}" \
      --talos-version v1.13.4 \
      --controlplanes 1 --workers 2 \
      --cidr "${CIDR}" \
      --memory-controlplanes 2560 --memory-workers 2048 \
      --config-patch "@${PATCH}"
  fi

  # Hand state back to the invoking user so later non-root kubectl works.
  if [ -n "${SUDO_USER:-}" ]; then
    chown -R "${SUDO_USER}" "${HOME}/.talos" "${HOME}/.kube" 2>/dev/null || true
  fi

  deploy
  verify
}

# ── deploy: namespace + helm ──────────────────────────────────────────────────
deploy() {
  command -v kubectl >/dev/null || die "kubectl not found"
  command -v helm >/dev/null || die "helm not found"

  log "Namespace ${NAMESPACE} (PodSecurity: privileged — agent needs CAP_SYS_ADMIN)"
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=privileged --overwrite

  log "helm install ${RELEASE}"
  helm upgrade --install "${RELEASE}" "${CHART}" \
    -n "${NAMESPACE}" -f "${VALUES}" \
    --wait --timeout 5m || log "helm --wait timed out; verify will report pod state"
}

# ── verify: Ready + /healthz + /metrics + eBPF attach ─────────────────────────
verify() {
  log "Pods:"
  kubectl -n "${NAMESPACE}" get pods -o wide || true

  log "Waiting for DaemonSet pods Ready (real eBPF attach => /readyz 200 => Ready)"
  kubectl -n "${NAMESPACE}" rollout status ds/"${RELEASE}" --timeout=120s || true

  local pod
  pod="$(kubectl -n "${NAMESPACE}" get pod -l app.kubernetes.io/name=ebpfsentinel \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)" || true
  [ -n "${pod}" ] || die "no agent pod found"

  log "Recent agent log (attach evidence):"
  kubectl -n "${NAMESPACE}" logs "${pod}" --tail=40 2>/dev/null | \
    grep -iE 'attach|loaded|token|bpffs|ready|listening|error|warn' || true

  # Distroless image has no shell — curl the hostNetwork node IP from the host
  # instead (the qemu bridge gives the host a route into the cluster CIDR).
  local host_ip
  host_ip="$(kubectl -n "${NAMESPACE}" get pod "${pod}" \
            -o jsonpath='{.status.hostIP}' 2>/dev/null)" || true
  if [ -n "${host_ip}" ]; then
    log "Probe endpoints on node ${host_ip} (hostNetwork)"
    for ep in "8080/healthz" "8080/readyz" "9090/metrics"; do
      out="$(curl -s -m4 -o /dev/null -w '%{http_code}' \
             "http://${host_ip}:${ep%%/*}/${ep#*/}" 2>/dev/null)" || out="ERR"
      printf '  :%s/%s -> HTTP %s\n' "${ep%%/*}" "${ep#*/}" "${out}" >&2
    done
    log "metrics sample:"
    curl -s -m4 "http://${host_ip}:9090/metrics" 2>/dev/null | grep -E '^ebpfsentinel_' | head -8 || true
  else
    log "no hostIP yet; inspect manually: kubectl -n ${NAMESPACE} port-forward ${pod} 8080 9090"
  fi

  log "DaemonSet status:"
  kubectl -n "${NAMESPACE}" get ds "${RELEASE}"
}

# ── down: teardown ────────────────────────────────────────────────────────────
cluster_down() {
  [ "$(id -u)" -eq 0 ] || die "run 'down' as root: sudo -E $0 down"
  log "Destroying Talos cluster '${CLUSTER_NAME}'"
  talosctl cluster destroy qemu --name "${CLUSTER_NAME}" || true
  log "Removing local registry"
  docker rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
  log "down done"
}

case "${1:-}" in
  prep)   prep ;;
  up)     cluster_up ;;
  deploy) deploy ;;
  verify) verify ;;
  down)   cluster_down ;;
  *) die "usage: $0 {prep|up|deploy|verify|down}" ;;
esac
