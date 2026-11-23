#!/usr/bin/env bash
# kernel-matrix-guest.sh - one kernel of the matrix, on the machine running it.
#
# Usage (as root, on the agent VM, after the kernel-mainline provisioner booted
# the version):
#   kernel-matrix-guest.sh <build> <tier> <out-dir>
#
# <build> is what check-kernel-matrix.py --resolve answered: 6.18.5, 6.19 (a
# .0 release) or 7.4-rc4.
#
# 1. Refuses to go on when the running kernel is not the mainline build of
#    <version>: a matrix line reporting a kernel it did not run is worse than
#    no line.
# 2. Runs the in-kernel harness the eBPF workflow runs on a hosted runner, on
#    this kernel: every object through the verifier and BPF_PROG_TEST_RUN, a
#    denied packet through each step of a firewall reload, a trace touching no
#    map, a signal to a process making no syscall.
# 3. Runs the local lane: every suite of the datapath profile for the load and
#    preview tiers, every local suite for the full tier, strict, with the lane
#    claims of the agent VM plus `mainline-kernel`.
#
# Writes <out-dir>/summary.txt (one line per step, then the lane's per-suite
# lines), the harness logs, the suite TAP files and the kernel-features answer
# suite 86 saves. Exits 1 when any step failed.
set -u

VERSION="${1:?usage: kernel-matrix-guest.sh <version> <tier> <out-dir>}"
TIER="${2:?usage: kernel-matrix-guest.sh <version> <tier> <out-dir>}"
OUT="${3:?usage: kernel-matrix-guest.sh <version> <tier> <out-dir>}"
PROJECT_ROOT="${PROJECT_ROOT:-/home/vagrant/ebpfsentinel}"
BUILD_USER="${BUILD_USER:-vagrant}"
INTEG="${PROJECT_ROOT}/tests/integration"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
rm -rf "$OUT"
mkdir -p "$OUT"
SUMMARY="${OUT}/summary.txt"
failed=0

step() {
    # step <name> <ok|FAIL> [detail]
    printf '%-34s %s%s\n' "$1" "$2" "${3:+ ($3)}" | tee -a "$SUMMARY"
    [ "$2" = ok ] || failed=1
}

# ── 1. the kernel is the one asked for ───────────────────────────────
running="$(uname -r)"
case "$VERSION" in
    *-rc*) want_prefix="${VERSION%%-rc*}.0-"; want_rc="rc${VERSION##*-rc}" ;;
    *.*.*) want_prefix="${VERSION}-"; want_rc="" ;;
    *)     want_prefix="${VERSION}.0-"; want_rc="" ;;
esac
{
    echo "kernel ${VERSION} tier ${TIER}"
    echo "running ${running}"
    echo "lsm $(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
    echo "date $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee "$SUMMARY"
if [[ "$running" != "${want_prefix}"* ]] || [[ -n "$want_rc" && "$running" != *"${want_rc}-generic" ]]; then
    step "kernel" FAIL "running ${running}, asked ${VERSION}"
    exit 1
fi
step "kernel" ok

# ── 2. the in-kernel harness ─────────────────────────────────────────
# The kfuncs of five programs live in modules a minimal host does not load
# until asked, as the prerequisites page tells an operator.
if modprobe -a nf_conntrack fou fou6 xfrm_interface 2>"${OUT}/modprobe.log"; then
    step "modules" ok
else
    step "modules" FAIL "see modprobe.log"
fi

EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
[ -d "$EBPF_DIR" ] || EBPF_DIR=/usr/local/lib/ebpfsentinel

# Built unprivileged, once: the binaries do not depend on the kernel, so the
# first kernel of a run pays for them and the others find them fresh.
build() {
    # build <cargo test args...>: prints the test executable cargo built
    sudo -u "$BUILD_USER" -H bash -lc "cd '${PROJECT_ROOT}' && cargo test $* --no-run --message-format=json" 2>>"${OUT}/harness-build.log" |
        jq -r 'select(.executable != null and .profile.test) | .executable' | tail -1
}

harness() {
    # harness <name> <cargo test args> [test filter]
    local name="$1" args="$2" filter="${3:-}" bin log
    log="${OUT}/harness-${name}.log"
    bin="$(build "$args")"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        step "harness ${name}" FAIL "cargo built no binary for ${args}, see harness-build.log"
        return
    fi
    # shellcheck disable=SC2086
    if env EBPFSENTINEL_EBPF_DIR="$EBPF_DIR" "$bin" $filter --nocapture --test-threads=1 >"$log" 2>&1; then
        step "harness ${name}" ok "$(grep -E '^test result:' "$log" | tail -1 | sed 's/^test result: //')"
    else
        step "harness ${name}" FAIL "see harness-${name}.log"
    fi
}

harness prog-test-run "-p adapters --test ebpf_prog_test_run"
harness reload-keeps-deny "-p adapters --lib" "map_manager::tests::in_kernel"
harness trace-side-effects "-p adapters --test ebpf_trace_side_effects"
harness signal-task "-p adapters --test signal_task"

# ── 3. the local lane ────────────────────────────────────────────────
case "$TIER" in
    full) suites="" ;;
    load|preview) suites="$(bash "${INTEG}/scripts/list-suites-by-profile.sh" --list datapath)" ;;
    *) step "tier" FAIL "unknown tier ${TIER}"; exit 1 ;;
esac

# shellcheck disable=SC2086
EBPFSENTINEL_STRICT_SKIPS=1 \
EBPFSENTINEL_LANE_CLAIMS='bpf-lsm openssl-mlkem userns root mainline-kernel' \
EBPFSENTINEL_KERNEL_MATRIX_OUT="$OUT" \
PROJECT_ROOT="$PROJECT_ROOT" \
    bash "${INTEG}/scripts/run-local-lane.sh" $suites >"${OUT}/local-lane.log" 2>&1
cp /tmp/local-lane-result.txt "${OUT}/local-lane-result.txt" 2>/dev/null || true
mkdir -p "${OUT}/tap"
cp /tmp/ll-*.tap "${OUT}/tap/" 2>/dev/null || true
rm -f /tmp/ll-*.tap

if ! grep -q '^=== DONE ===' "${OUT}/local-lane-result.txt" 2>/dev/null; then
    step "local lane" FAIL "the lane stopped before its end, see local-lane.log"
else
    bad="$(grep -E '^SUITE ' "${OUT}/local-lane-result.txt" | grep -vE 'fail=0 rc=0' | grep -cv 'NOT RUN (written for the runtimes lane')"
    total="$(grep -cE '^SUITE ' "${OUT}/local-lane-result.txt")"
    if [ "$bad" -eq 0 ]; then
        step "local lane" ok "${total} suites"
    else
        step "local lane" FAIL "${bad} of ${total} suites"
    fi
    grep -E '^SUITE ' "${OUT}/local-lane-result.txt" >>"$SUMMARY"
fi
[ -s "${OUT}/kernel-features.json" ] || echo "note: no kernel-features.json (suite 86 not run or skipped)" >>"$SUMMARY"
chown -R "$BUILD_USER" "$OUT" 2>/dev/null || true
exit "$failed"
