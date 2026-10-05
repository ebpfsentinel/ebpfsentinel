#!/usr/bin/env bash
# End-to-end Kubernetes test for the eBPFsentinel agent on a local Talos cluster.
#
# Why Talos + qemu: minikube/kind run the node as a container, so the agent's
# self-unshare (a child user namespace owning the bpffs the warden delegates)
# hits a nested-userns wall. Talos qemu nodes are real VMs with a real kernel
# (>= 6.12 on Talos 1.13), so token loading and real eBPF attach work exactly as
# on a production node.
#
# `verify` is a gate, not a report: it exits non-zero unless the shipped split
# posture holds on every node - the agent container non-root with every
# capability dropped and none added, the warden the only container holding
# CAP_SYS_ADMIN/NET_ADMIN/NET_RAW - and that agent still loads and attaches its
# own eBPF through the token and reads the kernel conntrack table through the
# warden.
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
IMAGE_LOCAL="localhost:${REGISTRY_PORT}/ebpfsentinel:latest"           # push (docker treats localhost as insecure)
WARDEN_LOCAL="localhost:${REGISTRY_PORT}/ebpfsentinel-warden:latest"   # privileged broker sidecar image
NAMESPACE="ebpfsentinel-e2e"
RELEASE="ebpfsentinel"
CHART="${PROJECT_ROOT}/charts/ebpfsentinel"
VALUES="${SCRIPT_DIR}/values-talos.yaml"
PATCH="${SCRIPT_DIR}/patch-all.yaml"

# Resolve the invoking user even under sudo (sudoers here forbids `-E`, so HOME
# is reset to /root and PATH is sanitized). Point HOME/PATH at the real user so
# talosctl (in ~/.local/bin) is found and talosconfig/kubeconfig land in the
# user's home - then chown state back at the end of `up`.
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

  # Rebuild by default so each iteration deploys the CURRENT source - the
  # registry is re-pushed below and nodes pull :latest (pullPolicy: Always).
  # Set PREP_NO_REBUILD=1 to reuse existing local images (faster, but may be
  # stale - skips the build only when the image already exists).
  if [ "${PREP_NO_REBUILD:-0}" != "1" ] || ! docker image inspect ebpfsentinel:latest >/dev/null 2>&1; then
    # The image copies ebpf-out/ verbatim, so an empty one builds an agent that
    # loads nothing and every attach check below fails for a reason that is not
    # the datapath. Build the set and refuse to go on with fewer than all of it.
    log "Building the eBPF objects + staging them into ebpf-out/"
    (cd "${PROJECT_ROOT}" && cargo xtask ebpf-build)
    local built="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    mkdir -p "${PROJECT_ROOT}/ebpf-out"
    find "${built}" -maxdepth 1 -type f ! -name '*.d' \
      -exec cp {} "${PROJECT_ROOT}/ebpf-out/" \;
    local staged
    staged="$(find "${PROJECT_ROOT}/ebpf-out" -maxdepth 1 -type f | wc -l)"
    [ "${staged}" -ge 16 ] || die "only ${staged} eBPF objects staged from ${built}, expected 16"
    log "Building ebpfsentinel:latest"
    docker build -f "${PROJECT_ROOT}/Dockerfile.agent" -t ebpfsentinel:latest "${PROJECT_ROOT}"
  fi

  # Split deployment: the privileged warden broker ships as its own lean image.
  if [ "${PREP_NO_REBUILD:-0}" != "1" ] || ! docker image inspect ebpfsentinel-warden:latest >/dev/null 2>&1; then
    log "Building ebpfsentinel-warden:latest"
    docker build -f "${PROJECT_ROOT}/Dockerfile.warden" -t ebpfsentinel-warden:latest "${PROJECT_ROOT}"
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}"; then
    log "Starting local registry on :${REGISTRY_PORT}"
    docker rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
    docker run -d --restart=always -p "${REGISTRY_PORT}:5000" --name "${REGISTRY_NAME}" registry:2 >/dev/null
  fi

  log "Tag + push ${IMAGE_LOCAL}"
  docker tag ebpfsentinel:latest "${IMAGE_LOCAL}"
  docker push "${IMAGE_LOCAL}"

  log "Tag + push ${WARDEN_LOCAL}"
  docker tag ebpfsentinel-warden:latest "${WARDEN_LOCAL}"
  docker push "${WARDEN_LOCAL}"

  log "prep done - agent + warden images in registry (pulled in-cluster via ${GATEWAY}:${REGISTRY_PORT})"
}

# ── up: cluster + deploy + verify (root) ──────────────────────────────────────
cluster_up() {
  [ "$(id -u)" -eq 0 ] || die "run 'up' as root: sudo -E $0 up"
  command -v talosctl >/dev/null || die "talosctl not found in PATH (${PATH})"

  # Auto-provision the registry + images when the registry is not running. prep
  # runs here as root (root can reach the docker socket); HOME already points at
  # the real user's home (set above), so docker uses their config, not /root.
  if ! docker ps --format '{{.Names}}' | grep -qx "${REGISTRY_NAME}"; then
    log "local registry not running - auto-provisioning (build + registry + push)"
    prep
  fi

  create_cluster() {
    log "Creating Talos qemu cluster '${CLUSTER_NAME}' (1 control-plane + 2 workers)"
    # cluster create waits for full health and merges kubeconfig into ~/.kube/config.
    talosctl cluster create qemu \
      --name "${CLUSTER_NAME}" \
      --talos-version v1.13.4 \
      --controlplanes 1 --workers 2 \
      --cidr "${CIDR}" \
      --memory-controlplanes 2560 --memory-workers 2048 \
      --config-patch "@${PATCH}"
  }

  if [ -d "${HOME}/.talos/clusters/${CLUSTER_NAME}" ]; then
    # A state dir alone does not mean the cluster is alive: the qemu VMs are
    # processes that do not survive a host reboot, leaving stale state that makes
    # `cluster create` refuse and the deploy time out against a dead apiserver.
    # Probe the apiserver; if it is unreachable, the cluster is stale - tear just
    # the cluster down (leaving the local registry intact) and recreate it.
    if timeout 5 bash -c "exec 3<>/dev/tcp/${GATEWAY}/6443" 2>/dev/null; then
      log "Cluster '${CLUSTER_NAME}' is up (apiserver reachable) - resuming deploy"
    else
      log "Cluster '${CLUSTER_NAME}' state is stale (apiserver unreachable) - destroying and recreating"
      talosctl cluster destroy --name "${CLUSTER_NAME}" -f || true
      create_cluster
    fi
  else
    create_cluster
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

  log "Namespace ${NAMESPACE} (PodSecurity: privileged - warden holds CAP_SYS_ADMIN, agent runs unconfined)"
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=privileged --overwrite

  log "helm install ${RELEASE}"
  helm upgrade --install "${RELEASE}" "${CHART}" \
    -n "${NAMESPACE}" -f "${VALUES}" \
    --wait --timeout 5m || log "helm --wait timed out; verify will report pod state"
}

# ── verify: posture + token load + attach + conntrack through the warden ─────
FAILURES=0
check() { # check <description> <command...>
  local what="$1"; shift
  if "$@"; then
    printf '  \033[1;32mok\033[0m   %s\n' "${what}" >&2
  else
    printf '  \033[1;31mFAIL\033[0m %s\n' "${what}" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

container_json() { # container_json <pod-json> <init|main> <name>
  local field=containers
  [ "$2" = init ] && field=initContainers
  jq -c --arg n "$3" ".spec.${field}[] | select(.name == \$n)" <<<"$1"
}

verify() {
  command -v jq >/dev/null || die "jq not found"
  FAILURES=0

  log "Waiting for the DaemonSet rollout (Ready => /readyz 200 => eBPF attached)"
  check "daemonset rolled out" \
    kubectl -n "${NAMESPACE}" rollout status ds/"${RELEASE}" --timeout=180s

  local pods
  pods="$(kubectl -n "${NAMESPACE}" get pod -l app.kubernetes.io/name=ebpfsentinel \
          -o jsonpath='{.items[*].metadata.name}')"
  [ -n "${pods}" ] || die "no agent pod found"

  local pod pod_json agent warden host_ip api
  for pod in ${pods}; do
    log "Pod ${pod}"
    pod_json="$(kubectl -n "${NAMESPACE}" get pod "${pod}" -o json)"
    agent="$(container_json "${pod_json}" main agent)"
    warden="$(container_json "${pod_json}" init warden)"

    # Declared posture, read back from the API server rather than the chart.
    check "agent runs as uid 65534" \
      test "$(jq -r '.securityContext.runAsUser' <<<"${agent}")" = 65534
    check "agent drops ALL capabilities" \
      test "$(jq -r '.securityContext.capabilities.drop | index("ALL") != null' <<<"${agent}")" = true
    check "agent adds no capability" \
      test "$(jq -r '(.securityContext.capabilities.add // []) | length' <<<"${agent}")" = 0
    check "agent is not privileged" \
      test "$(jq -r '.securityContext.privileged // false' <<<"${agent}")" = false
    check "warden is a native sidecar" \
      test "$(jq -r '.restartPolicy' <<<"${warden}")" = Always
    check "warden holds SYS_ADMIN, NET_ADMIN, NET_RAW" \
      test "$(jq -r '[.securityContext.capabilities.add[]] | (index("SYS_ADMIN") != null and index("NET_ADMIN") != null and index("NET_RAW") != null)' <<<"${warden}")" = true
    check "agent never restarted" \
      test "$(jq -r '[.status.containerStatuses[] | select(.name == "agent") | .restartCount][0]' <<<"${pod_json}")" = 0

    # Observed behaviour: the rootless agent minted its own token and attached.
    local logs
    logs="$(kubectl -n "${NAMESPACE}" logs "${pod}" -c agent 2>/dev/null || true)"
    check "agent created its BPF token" grep -q 'BPF_TOKEN_CREATE succeeded' <<<"${logs}"
    check "agent loads eBPF via the token" grep -q 'eBPF loading via BPF token' <<<"${logs}"

    host_ip="$(jq -r '.status.hostIP // empty' <<<"${pod_json}")"
    if [ -z "${host_ip}" ]; then
      check "pod has a host IP" false
      continue
    fi
    # Distroless image has no shell - curl the hostNetwork node IP from the host
    # instead (the qemu bridge gives the host a route into the cluster CIDR).
    api="http://${host_ip}:8080"

    check "/healthz answers 200" \
      test "$(curl -s -m5 -o /dev/null -w '%{http_code}' "${api}/healthz")" = 200
    check "/readyz answers 200" \
      test "$(curl -s -m5 -o /dev/null -w '%{http_code}' "${api}/readyz")" = 200

    local status
    status="$(curl -s -m5 "${api}/api/v1/ebpf/status" || true)"
    check "xdp-firewall loaded" \
      test "$(jq -r '[.programs[] | select(.name == "xdp-firewall") | .loaded][0] // false' <<<"${status}" 2>/dev/null)" = true
    check "no attach blocked" \
      test "$(jq -r '.attach_blocked | length' <<<"${status}" 2>/dev/null)" = 0

    # Reading the kernel conntrack table needs CAP_NET_ADMIN in the host network
    # namespace, which the agent does not hold: a non-empty table on a live
    # node (kubelet, apiserver, CNI flows) proves the read went through the
    # warden.
    local conns
    conns="$(curl -s -m10 "${api}/api/v1/conntrack/connections?limit=50" || true)"
    check "kernel conntrack read through the warden" \
      test "$(jq -r 'if type == "array" then length else 0 end' <<<"${conns}" 2>/dev/null || echo 0)" -gt 0
  done

  if [ "${FAILURES}" -ne 0 ]; then
    kubectl -n "${NAMESPACE}" get pods -o wide >&2 || true
    die "${FAILURES} check(s) failed"
  fi
  log "all checks passed on: ${pods}"
}

# ── down: teardown ────────────────────────────────────────────────────────────
cluster_down() {
  [ "$(id -u)" -eq 0 ] || die "run 'down' as root: sudo -E $0 down"
  log "Destroying Talos cluster '${CLUSTER_NAME}'"
  talosctl cluster destroy --name "${CLUSTER_NAME}" -f || true
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
