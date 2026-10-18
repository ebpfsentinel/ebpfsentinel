#!/usr/bin/env bash
# Ask a live API server what it thinks of the chart's pod, and compare its
# answer with what the chart says about itself.
#
# The chart refuses to render at a Pod Security Admission level its values
# violate, and lists the violations. That list is a claim until a cluster
# answers: this script renders the pod, submits it to a namespace enforcing
# `baseline` and one enforcing `privileged`, and fails when
#
#   - the API server names a control the chart's own list does not name;
#   - the API server names hostPID, which these values no longer ask for;
#   - the privileged namespace refuses the pod.
#
# Needs kubectl, helm, python3 and a cluster. Nothing is created outside the
# two namespaces it makes, and every submission is a server dry run.
set -euo pipefail

CHART="${CHART:-charts/ebpfsentinel}"
RELEASE="${RELEASE:-ebpfsentinel}"
NS_BASELINE="${NS_BASELINE:-ebpfsentinel-psa-baseline}"
NS_PRIVILEGED="${NS_PRIVILEGED:-ebpfsentinel-psa-privileged}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for tool in kubectl helm python3; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
kubectl version >/dev/null 2>&1 || {
  echo "no reachable cluster: this check is a cluster run, not a manifest read" >&2
  exit 2
}

echo "== rendering $CHART"
helm template "$RELEASE" "$CHART" ${HELM_ARGS:-} > "$WORK/render.yaml"

python3 - "$WORK/render.yaml" "$WORK/pod.yaml" "$NS_BASELINE" <<'PY'
import sys, yaml
render, out, namespace = sys.argv[1], sys.argv[2], sys.argv[3]
sets = [d for d in yaml.safe_load_all(open(render)) if d and d.get("kind") == "DaemonSet"]
if len(sets) != 1:
    raise SystemExit(f"expected one DaemonSet in the render, found {len(sets)}")
spec = sets[0]["spec"]["template"]["spec"]
pod = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "psa-probe", "namespace": namespace},
    "spec": spec,
}
yaml.safe_dump(pod, open(out, "w"))
print(spec.get("serviceAccountName", "default"))
PY
SERVICE_ACCOUNT="$(python3 -c "
import yaml,sys
pod=yaml.safe_load(open('$WORK/pod.yaml'))
print(pod['spec'].get('serviceAccountName','default'))
")"

for pair in "$NS_BASELINE baseline" "$NS_PRIVILEGED privileged"; do
  set -- $pair
  kubectl get namespace "$1" >/dev/null 2>&1 || kubectl create namespace "$1" >/dev/null
  kubectl label namespace "$1" "pod-security.kubernetes.io/enforce=$2" --overwrite >/dev/null
  kubectl -n "$1" get serviceaccount "$SERVICE_ACCOUNT" >/dev/null 2>&1 ||
    kubectl -n "$1" create serviceaccount "$SERVICE_ACCOUNT" >/dev/null
done

echo "== submitting the pod to $NS_BASELINE (enforce=baseline)"
VERDICT="$(kubectl apply --dry-run=server -f "$WORK/pod.yaml" 2>&1 || true)"
echo "$VERDICT"

if grep -qi "hostPID" <<<"$VERDICT"; then
  echo "FAIL: the API server names hostPID, which these values no longer set" >&2
  exit 1
fi

echo "== the chart's own list, at the same level"
CLAIM="$(helm template "$RELEASE" "$CHART" ${HELM_ARGS:-} \
  --set daemonset.podSecurityAdmission=baseline 2>&1 || true)"
echo "$CLAIM"

status=0
check_control() {
  local needle="$1" claim_needle="$2" name="$3"
  if grep -qi -- "$needle" <<<"$VERDICT" && ! grep -qi -- "$claim_needle" <<<"$CLAIM"; then
    echo "FAIL: the cluster names $name and the chart's list does not" >&2
    status=1
  fi
}
check_control "host namespaces" "hostNetwork" "the host network namespace"
check_control "non-default capabilities" "capabilities.add" "added capabilities"
check_control "seccompProfile" "seccompProfile" "the seccomp profile"
check_control "AppArmor" "appArmorProfile" "the AppArmor profile"
check_control "hostPath volumes" "hostPath volumes" "hostPath volumes"
check_control "hostPort" "host ports" "host ports"

echo "== submitting the same pod to $NS_PRIVILEGED (enforce=privileged)"
sed "s/namespace: $NS_BASELINE/namespace: $NS_PRIVILEGED/" "$WORK/pod.yaml" > "$WORK/pod-privileged.yaml"
if ! kubectl apply --dry-run=server -f "$WORK/pod-privileged.yaml"; then
  echo "FAIL: the level the chart declares does not admit the pod it renders" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "OK: the chart's list and the API server agree, and hostPID is in neither"
fi
exit "$status"
