#!/usr/bin/env bash
# Render the chart and compare it byte for byte with the renders committed
# under tests/chart/, so a template change that moves the default manifests is
# a diff somebody reads rather than a pod that changed underneath a cluster.
#
#   tests/chart/default.yaml           the chart with its shipped values
#   tests/chart/tailored-seccomp.yaml  the same with the tailored seccomp
#                                      profile turned on
#
# It also asserts that turning the profile on takes the agent's Unconfined
# seccomp off the list of what a stricter Pod Security Admission level forbids.
#
# Run with --update to rewrite the renders after a deliberate change, and read
# the diff before committing it. Needs helm and nothing else.
set -euo pipefail

CHART="${CHART:-charts/ebpfsentinel}"
RELEASE="${RELEASE:-ebpfsentinel}"
NAMESPACE="${NAMESPACE:-ebpfsentinel}"
GOLDEN="${GOLDEN:-tests/chart}"
TAILORED=(--set daemonset.tailoredSeccomp.enabled=true)

command -v helm >/dev/null || { echo "missing helm" >&2; exit 2; }
cd "$(dirname "$0")/.."

render() {
  helm template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "$@"
}

if [ "${1:-}" = "--update" ]; then
  render > "$GOLDEN/default.yaml"
  render "${TAILORED[@]}" > "$GOLDEN/tailored-seccomp.yaml"
  echo "rewrote $GOLDEN/default.yaml and $GOLDEN/tailored-seccomp.yaml"
  exit 0
fi

status=0
compare() {
  local golden="$1"
  shift
  if render "$@" | diff -u "$GOLDEN/$golden" -; then
    echo "ok   $golden"
  else
    echo "FAIL $golden differs from the render above" >&2
    status=1
  fi
}

compare default.yaml
compare tailored-seccomp.yaml "${TAILORED[@]}"

# A level that forbids Unconfined must not name the agent's profile once the
# tailored one replaces it. The render still fails at that level, for the
# warden and the hostPath volumes, which is what the message is read for.
if refusal="$(render "${TAILORED[@]}" --set daemonset.podSecurityAdmission=baseline 2>&1)"; then
  echo "FAIL a baseline render was expected to be refused" >&2
  status=1
elif grep -q "daemonset.securityContext.seccompProfile" <<<"$refusal"; then
  echo "FAIL the baseline refusal still names the agent's seccomp profile:" >&2
  echo "$refusal" >&2
  status=1
else
  echo "ok   baseline refusal leaves the agent's profile out"
fi

exit "$status"
