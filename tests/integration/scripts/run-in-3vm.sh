#!/usr/bin/env bash
# run-in-3vm.sh — Run integration tests using the 3-VM transit topology
#
# Boots three Vagrant VMs (client/attacker + agent-router + backend),
# then runs BATS suites on the client VM. Traffic from the client is
# routed through the agent's eBPF datapath to reach the backend, so
# transit-only features (NAT, conntrack, QoS, L4/L2 LB, TLS DLP) can
# be exercised end-to-end.
#
# Subnets:
#   192.168.56.0/24 — client (.20) ↔ agent.eth1 (.10)
#   192.168.57.0/24 — agent.eth2 (.10) ↔ backend (.30)
#
# Usage:
#   ./run-in-3vm.sh                        # Run all 3-VM-tagged suites
#   ./run-in-3vm.sh --suite 28             # Run a single suite by number
#   ./run-in-3vm.sh --transit-only         # Only suites tagged topology=3vm
#   ./run-in-3vm.sh --profile nightly      # Only suites with suite_profiles==nightly
#   ./run-in-3vm.sh --skip-provision       # Skip vagrant up
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"
SUITE_DIR="${INTEGRATION_DIR}/suites"
COVERAGE_MATRIX="${INTEGRATION_DIR}/coverage-matrix.yaml"

# ── Parse arguments ────────────────────────────────────────────────
SUITE=""
TRANSIT_ONLY=false
SKIP_PROVISION=false
PROFILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --suite)          SUITE="$2"; shift 2 ;;
        --transit-only)   TRANSIT_ONLY=true; shift ;;
        --skip-provision) SKIP_PROVISION=true; shift ;;
        --profile)        PROFILE="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Ensure VMs are running ─────────────────────────────────────────
if [ "$SKIP_PROVISION" != "true" ]; then
    echo "=== Booting 3-VM transit environment ==="
    cd "$VAGRANT_DIR"
    VAGRANT_3VM=1 vagrant up agent attacker backend
    cd "$INTEGRATION_DIR"
fi

# ── Build suite list ───────────────────────────────────────────────
list_transit_suites() {
    # Read coverage-matrix.yaml and emit suites whose topology field is 3vm.
    # We rely on PyYAML being preinstalled on Ubuntu test runners; fall back
    # to a grep heuristic if python3 is unavailable.
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<PY
import os, sys
try:
    import yaml
except ImportError:
    sys.exit(2)
with open("${COVERAGE_MATRIX}") as f:
    doc = yaml.safe_load(f)
suites = set()
for section in ("ebpf_programs", "cli_subcommands", "domain_modules"):
    for row in doc.get(section, []) or []:
        if row.get("topology") == "3vm":
            for s in row.get("suites", []) or []:
                suites.add(s)
for s in sorted(suites):
    print(s)
PY
        local rc=$?
        if [ "$rc" -eq 2 ]; then
            # PyYAML missing — fall through to grep heuristic
            :
        else
            return $rc
        fi
    fi
    # grep fallback: rows with "topology: 3vm" — only correct when each row
    # lists exactly one suite (good enough for early Epic 34 work).
    awk '/topology: 3vm/{flag=1} flag && /- suites:/{getline; gsub(/[ \-]/,""); print; flag=0}' \
        "${COVERAGE_MATRIX}" 2>/dev/null || true
}

# Emit suite numbers whose suite_profiles entry matches $PROFILE.
list_profile_suites() {
    python3 - "$PROFILE" <<PY
import sys, yaml
profile = sys.argv[1]
with open("${COVERAGE_MATRIX}") as f:
    doc = yaml.safe_load(f)
for num, prof in (doc.get("suite_profiles") or {}).items():
    if prof == profile:
        print(num)
PY
}

build_suite_args() {
    if [ -n "$PROFILE" ]; then
        local names paths
        names="$(list_profile_suites | sort)"
        if [ -z "$names" ]; then
            echo "ERROR: No suites with profile='${PROFILE}' in coverage-matrix.yaml" >&2
            exit 1
        fi
        paths=""
        while IFS= read -r n; do
            [ -z "$n" ] && continue
            local p
            p="$(ls "${SUITE_DIR}/${n}"-* 2>/dev/null | head -1)" || true
            [ -n "$p" ] && paths="${paths} ${p}"
        done <<< "$names"
        echo "$paths"
        return
    fi

    if [ -n "$SUITE" ]; then
        local match
        match="$(ls "${SUITE_DIR}/${SUITE}"*.bats 2>/dev/null | head -1)" || true
        if [ -z "$match" ]; then
            echo "ERROR: No suite matching '${SUITE}' in ${SUITE_DIR}" >&2
            exit 1
        fi
        echo "$match"
        return
    fi

    if [ "$TRANSIT_ONLY" = "true" ]; then
        local names paths
        names="$(list_transit_suites)"
        if [ -z "$names" ]; then
            echo "ERROR: No suites tagged topology=3vm in coverage-matrix.yaml" >&2
            exit 1
        fi
        paths=""
        while IFS= read -r n; do
            [ -z "$n" ] && continue
            local p
            p="$(ls "${SUITE_DIR}/${n}"* 2>/dev/null | head -1)" || true
            [ -n "$p" ] && paths="${paths} ${p}"
        done <<< "$names"
        echo "$paths"
        return
    fi

    # Default: every suite that exists. Tests gate themselves via
    # skip_if_not_3vm so non-3VM suites no-op cleanly.
    ls "${SUITE_DIR}"/*.bats 2>/dev/null
}

SUITES="$(build_suite_args)"
if [ -z "$SUITES" ]; then
    echo "ERROR: No test suites found" >&2
    exit 1
fi

REMOTE_SUITES=""
for s in $SUITES; do
    bn="$(basename "$s")"
    REMOTE_SUITES="${REMOTE_SUITES} suites/${bn}"
done

# ── Heal attacker → backend SSH trust ──────────────────────────────
# Vagrant provisions VMs in definition order, so a combined `up` runs the
# attacker's backend-key copy before the backend VM exists — leaving the
# transit suites (50/51 capture + iperf3) unable to reach the backend.
# Re-copy the key here (idempotent) now that all three VMs are up.
cd "$VAGRANT_DIR"
VAGRANT_3VM=1 vagrant ssh attacker -c '
  if ! ssh -i ~/.ssh/backend_key -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o BatchMode=yes vagrant@192.168.57.30 true 2>/dev/null; then
    if command -v sshpass >/dev/null 2>&1; then
      sshpass -p vagrant ssh-copy-id -i ~/.ssh/backend_key.pub \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        vagrant@192.168.57.30 2>/dev/null \
        && echo "backend SSH trust established" \
        || echo "WARN: could not establish backend SSH trust"
    fi
  fi
' || true
cd "$INTEGRATION_DIR"

# ── Run BATS suites on client VM ───────────────────────────────────
echo "=== Running tests on client VM (192.168.56.20) → agent (.10/.57.10) → backend (192.168.57.30) ==="
echo "  Suites: $(echo "$REMOTE_SUITES" | wc -w | tr -d ' ')"
echo ""

cd "$VAGRANT_DIR"
VAGRANT_3VM=1 vagrant ssh attacker -c \
    "cd /home/vagrant/ebpfsentinel/tests/integration && \
     export EBPF_3VM_MODE=true && \
     export EBPF_2VM_MODE=true && \
     export AGENT_VM_IP=192.168.56.10 && \
     export AGENT_BACKEND_IP=192.168.57.10 && \
     export ATTACKER_VM_IP=192.168.56.20 && \
     export BACKEND_VM_IP=192.168.57.30 && \
     export AGENT_SSH_KEY=~/.ssh/agent_key && \
     export BACKEND_SSH_KEY=~/.ssh/backend_key && \
     bats --timing ${REMOTE_SUITES}"

echo ""
echo "=== 3-VM test run complete ==="
