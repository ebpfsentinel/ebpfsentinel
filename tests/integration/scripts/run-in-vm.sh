#!/usr/bin/env bash
# run-in-vm.sh — Main integration test runner
#
# Usage: run-in-vm.sh [--suite <name>] [--k8s-only] [--ebpf-scenarios] [--performance] [--skip-build]
#
# Discovers BATS suites in tests/integration/suites/, runs them,
# and produces a summary report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/../.." && pwd)"
SUITE_DIR="${INTEGRATION_DIR}/suites"

SUITE_FILTER=""
K8S_ONLY=false
EBPF_SCENARIOS=false
PERFORMANCE=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite)           SUITE_FILTER="$2"; shift 2 ;;
        --k8s-only)        K8S_ONLY=true; shift ;;
        --ebpf-scenarios)  EBPF_SCENARIOS=true; shift ;;
        --performance)     PERFORMANCE=true; shift ;;
        --skip-build)      SKIP_BUILD=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────

echo "=== eBPFsentinel Integration Test Runner ==="
echo "Project root: ${PROJECT_ROOT}"
echo "Suite dir:    ${SUITE_DIR}"
echo ""

# Check for bats
if ! command -v bats &>/dev/null; then
    echo "ERROR: bats not found. Install: https://github.com/bats-core/bats-core" >&2
    exit 1
fi

# Check for required tools
for tool in curl jq; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: ${tool} not found." >&2
        exit 1
    fi
done

# ── Build agent ────────────────────────────────────────────────────

if [ "$SKIP_BUILD" = "false" ]; then
    echo "Building agent (release)..."
    (cd "$PROJECT_ROOT" && cargo build --release --bin ebpfsentinel-agent)
    echo ""
fi

# ── Generate certs and JWT keys ────────────────────────────────────

echo "Generating test certificates..."
bash "${SCRIPT_DIR}/generate-certs.sh"
echo ""

echo "Generating JWT keys and tokens..."
bash "${SCRIPT_DIR}/generate-jwt-keys.sh"
echo ""

# ── Discover and run suites ────────────────────────────────────────

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
FAILED_NAMES=()

run_suite() {
    local suite_file="$1"
    local suite_name
    suite_name="$(basename "$suite_file" .bats)"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Running: ${suite_name}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    if bats --timing "$suite_file"; then
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        FAILED_SUITES=$((FAILED_SUITES + 1))
        FAILED_NAMES+=("$suite_name")
    fi

    echo ""
}

if [ -n "$SUITE_FILTER" ]; then
    # Run specific suite
    MATCHED_FILE="$(find "$SUITE_DIR" -name "*${SUITE_FILTER}*.bats" | head -1)"
    if [ -z "$MATCHED_FILE" ]; then
        echo "ERROR: No suite matching '${SUITE_FILTER}' found in ${SUITE_DIR}" >&2
        exit 1
    fi
    run_suite "$MATCHED_FILE"
elif [ "$K8S_ONLY" = "true" ]; then
    # K8s suite only
    K8S_SUITE="${SUITE_DIR}/10-kubernetes.bats"
    if [ -f "$K8S_SUITE" ]; then
        run_suite "$K8S_SUITE"
    else
        echo "ERROR: K8s suite not found: ${K8S_SUITE}" >&2
        exit 1
    fi
elif [ "$EBPF_SCENARIOS" = "true" ]; then
    # eBPF scenario suites (11-14)
    for suite_file in "${SUITE_DIR}"/1[1-4]-*.bats; do
        [ -f "$suite_file" ] || continue
        run_suite "$suite_file"
    done
elif [ "$PERFORMANCE" = "true" ]; then
    # Performance benchmark suite (15)
    PERF_SUITE="${SUITE_DIR}/15-performance-benchmark.bats"
    if [ -f "$PERF_SUITE" ]; then
        run_suite "$PERF_SUITE"
    else
        echo "ERROR: Performance suite not found: ${PERF_SUITE}" >&2
        exit 1
    fi
else
    # All suites, sorted by filename
    for suite_file in "$SUITE_DIR"/*.bats; do
        [ -f "$suite_file" ] || continue
        run_suite "$suite_file"
    done
fi

# ── Summary ────────────────────────────────────────────────────────

echo "================================================================"
echo "  INTEGRATION TEST SUMMARY"
echo "================================================================"
echo "  Total suites: ${TOTAL_SUITES}"
echo "  Passed:       ${PASSED_SUITES}"
echo "  Failed:       ${FAILED_SUITES}"

if [ ${#FAILED_NAMES[@]} -gt 0 ]; then
    echo ""
    echo "  Failed suites:"
    for name in "${FAILED_NAMES[@]}"; do
        echo "    - ${name}"
    done
fi

echo "================================================================"

if [ "$FAILED_SUITES" -gt 0 ]; then
    exit 1
fi
