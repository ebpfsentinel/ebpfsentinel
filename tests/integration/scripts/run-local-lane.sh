#!/usr/bin/env bash
# run-local-lane.sh — run a set of agent-local (netns) bats suites on the agent
# VM, one at a time with a clean eBPF/netns slate between each, and write a
# compact pass/skip/fail summary to /tmp/local-lane-result.txt.
#
# Usage (on the agent VM):
#   sudo PROJECT_ROOT=/home/vagrant/ebpfsentinel bash scripts/run-local-lane.sh 33 52 57 58
set -u

PROJECT_ROOT="${PROJECT_ROOT:-/home/vagrant/ebpfsentinel}"
cd "${PROJECT_ROOT}/tests/integration" || exit 1
OUT=/tmp/local-lane-result.txt
: >"$OUT"

clean_slate() {
    pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
    sleep 1
    ip netns del ebpf-test-ns 2>/dev/null || true
    ip link del veth-ebpf0 2>/dev/null || true
    ip link del veth-ebpf1 2>/dev/null || true
    rm -rf /sys/fs/bpf/ebpfsentinel 2>/dev/null || true
    # Free agent ports left by a wedged process.
    for p in 8080 50051 9090 18080 18099; do
        fuser -k "${p}/tcp" 2>/dev/null || true
    done
    sleep 1
}

for s in "$@"; do
    suite="$(ls suites/${s}-*.bats 2>/dev/null | head -1)"
    if [ -z "$suite" ]; then
        echo "SUITE ${s}: NOT FOUND" >>"$OUT"
        continue
    fi
    clean_slate
    log="/tmp/ll-${s}.tap"
    PROJECT_ROOT="$PROJECT_ROOT" timeout 400 bats "$suite" >"$log" 2>&1
    rc=$?
    pass=$(grep -cE '^ok ' "$log" 2>/dev/null)
    skip=$(grep -cE '# skip' "$log" 2>/dev/null)
    fail=$(grep -cE '^not ok ' "$log" 2>/dev/null)
    real_pass=$((pass - skip))
    echo "SUITE ${s}: pass=${real_pass} skip=${skip} fail=${fail} rc=${rc} (log /tmp/ll-${s}.tap)" >>"$OUT"
done

echo "=== DONE ===" >>"$OUT"
