#!/usr/bin/env bash
# run-in-2vm.sh — Run integration tests using the 2-VM topology
#
# Boots both Vagrant VMs (agent + attacker), then runs BATS suites
# on the attacker VM which sends traffic to the agent VM over the
# private network (192.168.56.0/24).
#
# Usage:
#   ./run-in-2vm.sh                        # Run all suites
#   ./run-in-2vm.sh --suite 11             # Run a single suite by number
#   ./run-in-2vm.sh --ebpf                 # eBPF scenario suites only
#   ./run-in-2vm.sh --performance          # Performance suites only
#   ./run-in-2vm.sh --perf-comparison      # Binary vs Docker perf comparison
#   ./run-in-2vm.sh --skip-provision       # Skip vagrant up (VMs already running)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"
SUITE_DIR="${INTEGRATION_DIR}/suites"

# ── Parse arguments ────────────────────────────────────────────────
SUITE=""
EBPF_ONLY=false
PERF_ONLY=false
PERF_COMPARISON=false
SKIP_PROVISION=false
QUICK=false

while [ $# -gt 0 ]; do
    case "$1" in
        --suite)       SUITE="$2"; shift 2 ;;
        --ebpf)        EBPF_ONLY=true; shift ;;
        --performance) PERF_ONLY=true; shift ;;
        --perf-comparison) PERF_COMPARISON=true; shift ;;
        --skip-provision)  SKIP_PROVISION=true; shift ;;
        --quick)       QUICK=true; shift ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Ensure VMs are running ─────────────────────────────────────────
if [ "$SKIP_PROVISION" != "true" ]; then
    echo "=== Booting 2-VM environment ==="
    cd "$VAGRANT_DIR"
    vagrant up
    cd "$INTEGRATION_DIR"
fi

# ── Build suite list ───────────────────────────────────────────────
build_suite_args() {
    if [ -n "$SUITE" ]; then
        # Single suite by number prefix
        local match
        match="$(ls "${SUITE_DIR}/${SUITE}"*.bats 2>/dev/null | head -1)" || true
        if [ -z "$match" ]; then
            echo "ERROR: No suite matching '${SUITE}' in ${SUITE_DIR}" >&2
            exit 1
        fi
        echo "$match"
        return
    fi

    if [ "$EBPF_ONLY" = "true" ]; then
        ls "${SUITE_DIR}"/11-*.bats \
           "${SUITE_DIR}"/12-*.bats \
           "${SUITE_DIR}"/13-*.bats \
           "${SUITE_DIR}"/14-*.bats \
           "${SUITE_DIR}"/18-*.bats \
           "${SUITE_DIR}"/19-*.bats \
           "${SUITE_DIR}"/20-*.bats \
           "${SUITE_DIR}"/21-*.bats \
           "${SUITE_DIR}"/22-*.bats \
           "${SUITE_DIR}"/23-*.bats \
           2>/dev/null || true
        return
    fi

    if [ "$PERF_ONLY" = "true" ]; then
        ls "${SUITE_DIR}"/15-*.bats \
           "${SUITE_DIR}"/29-*.bats \
           "${SUITE_DIR}"/30-*.bats \
           2>/dev/null || true
        return
    fi

    # All suites
    ls "${SUITE_DIR}"/*.bats 2>/dev/null
}

# ── Performance comparison mode ────────────────────────────────────
if [ "$PERF_COMPARISON" = "true" ]; then
    echo "=== Binary vs Docker performance comparison ==="
    echo ""

    QUICK_FLAG=""
    [ "$QUICK" = "true" ] && QUICK_FLAG="--quick"

    # Run binary mode perf test on agent VM
    echo "── Phase 1: Binary mode ──"
    cd "$VAGRANT_DIR"
    vagrant ssh agent -c \
        "cd /home/vagrant/ebpfsentinel/tests/integration && \
         sudo bash scripts/perf-test-docker.sh --mode binary --skip-build ${QUICK_FLAG}" \
        2>&1 | tee /tmp/ebpfsentinel-2vm-perf-binary.txt

    # Run Docker mode perf test on agent VM
    echo ""
    echo "── Phase 2: Docker mode ──"
    vagrant ssh agent -c \
        "cd /home/vagrant/ebpfsentinel/tests/integration && \
         sudo bash scripts/perf-test-docker.sh --mode docker --skip-build ${QUICK_FLAG}" \
        2>&1 | tee /tmp/ebpfsentinel-2vm-perf-docker.txt

    # Print comparison
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  Binary vs Docker Performance Comparison (2-VM)"
    echo "══════════════════════════════════════════════════════"
    echo ""
    echo "Full output saved to:"
    echo "  Binary: /tmp/ebpfsentinel-2vm-perf-binary.txt"
    echo "  Docker: /tmp/ebpfsentinel-2vm-perf-docker.txt"

    exit 0
fi

# ── Run BATS suites on attacker VM ─────────────────────────────────
SUITES="$(build_suite_args)"

if [ -z "$SUITES" ]; then
    echo "ERROR: No test suites found" >&2
    exit 1
fi

# Convert absolute paths to relative paths inside the VM
REMOTE_SUITES=""
for s in $SUITES; do
    basename="$(basename "$s")"
    REMOTE_SUITES="${REMOTE_SUITES} suites/${basename}"
done

echo "=== Running tests on attacker VM (192.168.56.20) ==="
echo "  Suites: $(echo "$REMOTE_SUITES" | wc -w | tr -d ' ')"
echo ""

cd "$VAGRANT_DIR"
vagrant ssh attacker -c \
    "cd /home/vagrant/ebpfsentinel/tests/integration && \
     export EBPF_2VM_MODE=true && \
     export AGENT_VM_IP=192.168.56.10 && \
     export ATTACKER_VM_IP=192.168.56.20 && \
     export AGENT_SSH_KEY=~/.ssh/agent_key && \
     bats --timing ${REMOTE_SUITES}"

echo ""
echo "=== 2-VM test run complete ==="
