#!/usr/bin/env bash
# eBPFsentinel demo - the agent fleet driven from a git repository.
#
#   ./gitops.sh up     # a kind cluster, Argo CD, and a git server holding the agent
#   ./gitops.sh down   # delete the cluster and everything under .run/
#   ./gitops.sh env    # print the two exports the tutorial's commands assume
#
# Every tool it needs beyond docker, git and curl is downloaded into .run/bin
# at a pinned version and checked against its published SHA-256 before it
# runs, so nothing is installed on the host.

set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
RUN="$HERE/.run"
BIN="$RUN/bin"
export KUBECONFIG="$RUN/kubeconfig"
export PATH="$BIN:$PATH"

KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.37.0
KUBECTL_SHA256=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f
HELM_VERSION=v4.3.0
HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
ARGOCD_VERSION=v3.5.3
ARGOCD_SHA256=1a87025d8eb2eae621653fd312fb9ca51df1b4b3b6992a030e3a9ef38e45c448

CLUSTER=ebpfsentinel-gitops
TAG="${EBPFSENTINEL_TAG:-latest}"
AGENT_IMAGE="ghcr.io/ebpfsentinel/ebpfsentinel:$TAG"
WARDEN_IMAGE="ghcr.io/ebpfsentinel/ebpfsentinel-warden:$TAG"
# The agent chart vendored into the repository. A checkout's charts/ebpfsentinel
# can stand in for the published one.
AGENT_CHART="${AGENT_CHART:-oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel}"

say() { printf 'gitops: %s\n' "$*"; }
fail() {
  printf 'gitops: %s\n' "$*" >&2
  exit 1
}

preflight() {
  local tool
  for tool in docker git curl sha256sum tar; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required."
  done
  docker info >/dev/null 2>&1 || fail "cannot reach the Docker daemon; run as a member of the docker group, or with sudo."

  local release major minor
  release="$(uname -r)"
  major="${release%%.*}"
  minor="${release#*.}"
  minor="${minor%%.*}"
  if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 9 ]; }; then
    fail "kernel ${release}: the agent needs 6.9 or later, and a kind node shares the host's kernel."
  fi
  [ -r /sys/kernel/btf/vmlinux ] || fail "this kernel exposes no BTF at /sys/kernel/btf/vmlinux."
}

# fetch <url> <sha256> <destination>
fetch() {
  local tmp
  tmp="$(mktemp)"
  curl -fsSL "$1" -o "$tmp"
  if ! echo "$2  $tmp" | sha256sum --check --status; then
    rm -f "$tmp"
    fail "checksum mismatch for $1"
  fi
  mv "$tmp" "$3"
}

tools() {
  mkdir -p "$BIN"
  if [ ! -x "$BIN/kind" ]; then
    say "fetching kind $KIND_VERSION"
    fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$KIND_SHA256" "$BIN/kind"
    chmod +x "$BIN/kind"
  fi
  if [ ! -x "$BIN/kubectl" ]; then
    say "fetching kubectl $KUBECTL_VERSION"
    fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" "$BIN/kubectl"
    chmod +x "$BIN/kubectl"
  fi
  if [ ! -x "$BIN/helm" ]; then
    say "fetching helm $HELM_VERSION"
    fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_SHA256" "$RUN/helm.tar.gz"
    tar -xzf "$RUN/helm.tar.gz" -C "$RUN" linux-amd64/helm
    mv "$RUN/linux-amd64/helm" "$BIN/helm"
    rm -rf "$RUN/helm.tar.gz" "$RUN/linux-amd64"
  fi
  if [ ! -f "$RUN/argocd-core.yaml" ]; then
    say "fetching Argo CD $ARGOCD_VERSION"
    fetch "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/core-install.yaml" "$ARGOCD_SHA256" "$RUN/argocd-core.yaml"
  fi
}

cluster() {
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null
    return 0
  fi
  say "creating the kind cluster"
  kind create cluster --config kind.yaml --kubeconfig "$KUBECONFIG" --wait 120s
}

# A locally built image is used as it is; anything else is pulled first.
images() {
  local image
  for image in "$AGENT_IMAGE" "$WARDEN_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
    say "loading $image into the node"
    kind load docker-image --name "$CLUSTER" "$image" >/dev/null
  done
}

argocd() {
  say "installing Argo CD (core: no UI, no API server)"
  kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply --server-side -n argocd -f "$RUN/argocd-core.yaml" >/dev/null
  # Three minutes between two looks at the repository is right for an estate
  # and long for a demo.
  kubectl -n argocd patch configmap argocd-cm --type merge \
    -p '{"data":{"timeout.reconciliation":"15s"}}' >/dev/null
  kubectl -n argocd rollout restart statefulset argocd-application-controller >/dev/null
  kubectl -n argocd rollout status statefulset argocd-application-controller --timeout 5m >/dev/null
  kubectl -n argocd rollout status deployment argocd-repo-server --timeout 5m >/dev/null
}

forward() {
  if [ -f "$RUN/port-forward.pid" ] && kill -0 "$(cat "$RUN/port-forward.pid")" 2>/dev/null; then
    return 0
  fi
  kubectl -n gitops port-forward service/git 9418:9418 >"$RUN/port-forward.log" 2>&1 &
  echo $! >"$RUN/port-forward.pid"
  for _ in $(seq 1 30); do
    git ls-remote git://localhost:9418/estate.git >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "the git server did not answer on localhost:9418; see $RUN/port-forward.log"
}

repository() {
  say "starting the git server and seeding it with estate/"
  kubectl apply -f git-server.yaml >/dev/null
  kubectl -n gitops rollout status deployment git --timeout 3m >/dev/null
  forward
  if [ -n "$(git ls-remote git://localhost:9418/estate.git 2>/dev/null)" ]; then
    return 0
  fi
  local seed="$RUN/seed"
  rm -rf "$seed"
  git init --quiet --initial-branch=main "$seed"
  cp estate/agent.yaml "$seed/"
  case "$AGENT_CHART" in
    oci://*) helm pull "$AGENT_CHART" --untar --untardir "$seed" >/dev/null ;;
    *) cp -r "$AGENT_CHART" "$seed/ebpfsentinel" ;;
  esac
  mv "$seed/ebpfsentinel" "$seed/chart"
  sed -i "s/^  tag: latest$/  tag: $TAG/" "$seed/agent.yaml"
  git -C "$seed" add .
  git -C "$seed" -c user.name=demo -c user.email=demo@ebpfsentinel.invalid \
    commit --quiet -m "Agent on every node, SYN flood mitigation on"
  git -C "$seed" push --quiet git://localhost:9418/estate.git main
  rm -rf "$seed"
}

sync() {
  say "handing the repository to Argo CD"
  kubectl apply -f application.yaml >/dev/null
  local status
  for _ in $(seq 1 90); do
    status="$(kubectl -n ebpfsentinel get daemonset ebpfsentinel -o jsonpath='{.status.numberReady}' 2>/dev/null || true)"
    if [ "${status:-0}" -ge 1 ]; then
      say "agent ready on the node. Next, in this shell:"
      say "  eval \"\$(./gitops.sh env)\""
      say "  git clone git://localhost:9418/estate.git"
      return 0
    fi
    sleep 2
  done
  kubectl -n argocd get application estate -o wide >&2 || true
  kubectl -n ebpfsentinel get pods >&2 || true
  fail "the agent did not become ready in three minutes; the state is above."
}

up() {
  preflight
  mkdir -p "$RUN"
  tools
  cluster
  images
  argocd
  repository
  sync
}

down() {
  if [ -f "$RUN/port-forward.pid" ]; then
    kill "$(cat "$RUN/port-forward.pid")" 2>/dev/null || true
  fi
  if [ -x "$BIN/kind" ]; then
    "$BIN/kind" delete cluster --name "$CLUSTER" || true
  fi
  rm -rf "$RUN"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  env)
    # shellcheck disable=SC2016 # $PATH expands in the shell that evaluates it
    printf 'export PATH=%q:"$PATH"\n' "$BIN"
    printf 'export KUBECONFIG=%q\n' "$KUBECONFIG"
    ;;
  *)
    fail "usage: ./gitops.sh up | down | env"
    ;;
esac
