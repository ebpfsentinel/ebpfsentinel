#!/usr/bin/env bash
# run-local-lane.sh — run a set of agent-local (netns) bats suites on the agent
# VM, one at a time with a clean eBPF/netns slate between each, and write a
# compact pass/skip/fail summary to /tmp/local-lane-result.txt.
#
# Usage (on the agent VM):
#   sudo PROJECT_ROOT=/home/vagrant/ebpfsentinel bash scripts/run-local-lane.sh 33 52 57 58
set -u

PROJECT_ROOT="${PROJECT_ROOT:-/home/vagrant/ebpfsentinel}"
# The canonical lane provisions every prerequisite a suite owns, so a
# `soft_skip` here means a regression rather than a missing capability.
# Export EBPFSENTINEL_STRICT_SKIPS=1 before calling this script to turn those
# skips into failures (env_skip is unaffected — see lib/skip_policy.bash).
export EBPFSENTINEL_STRICT_SKIPS="${EBPFSENTINEL_STRICT_SKIPS:-0}"
cd "${PROJECT_ROOT}/tests/integration" || exit 1
OUT=/tmp/local-lane-result.txt
: >"$OUT"

# Suites that must NOT run as root. minikube refuses its docker driver under
# root (`DRV_AS_ROOT`), so driving a cluster from this script - which is invoked
# with sudo because every other suite needs netns and eBPF - silently skips the
# whole suite with "cluster could not start on this host". Drop back to the
# invoking user for these, and give them a longer budget: creating a cluster
# takes minutes, not the seconds a netns suite needs.
UNPRIVILEGED_SUITES=" 10 "
UNPRIVILEGED_TIMEOUT=1200
DEFAULT_TIMEOUT=400

clean_slate() {
    pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
    sleep 1
    ip netns del ebpf-test-ns 2>/dev/null || true
    ip link del veth-ebpf0 2>/dev/null || true
    ip link del veth-ebpf1 2>/dev/null || true
    ip link del ebpfsent-sink0 2>/dev/null || true
    rm -rf /sys/fs/bpf/ebpfsentinel 2>/dev/null || true
    # Free agent ports left by a wedged process.
    for p in 8080 50051 9090 18080 18085 18086 18087 18088 18099; do
        fuser -k "${p}/tcp" 2>/dev/null || true
    done
    sleep 1
}

# A bare `skip` in a suite always reports success, whatever the lane asked
# for: it is invisible to EBPFSENTINEL_STRICT_SKIPS. Refuse to start the lane
# while one is left, rather than reporting a green run that measured nothing.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
    if ! bash scripts/audit-skips.sh >/tmp/skip-audit.txt 2>&1; then
        cat /tmp/skip-audit.txt
        echo "skip audit failed - fix the suites before running the lane" >&2
        exit 1
    fi
else
    echo "WARNING: python3 + PyYAML absent, skip audit not run" | tee -a "$OUT"
fi

for s in "$@"; do
    suite="$(ls suites/${s}-*.bats 2>/dev/null | head -1)"
    if [ -z "$suite" ]; then
        echo "SUITE ${s}: NOT FOUND" >>"$OUT"
        continue
    fi
    clean_slate
    log="/tmp/ll-${s}.tap"

    case "$UNPRIVILEGED_SUITES" in
        *" ${s} "*) unpriv=true ;;
        *)          unpriv=false ;;
    esac

    if [ "$unpriv" = true ] && [ "$(id -u)" -eq 0 ]; then
        if [ -z "${SUDO_USER:-}" ]; then
            echo "SUITE ${s}: NOT RUN (needs an unprivileged user; no SUDO_USER to drop to)" >>"$OUT"
            continue
        fi
        # `env` rather than `sudo -E`: the point is to reset HOME so minikube
        # and kubectl find the invoking user's ~/.minikube and ~/.kube, while
        # still carrying the two variables the suites actually read.
        sudo -u "$SUDO_USER" env \
            PROJECT_ROOT="$PROJECT_ROOT" \
            EBPFSENTINEL_STRICT_SKIPS="$EBPFSENTINEL_STRICT_SKIPS" \
            timeout "$UNPRIVILEGED_TIMEOUT" bats "$suite" >"$log" 2>&1
    else
        PROJECT_ROOT="$PROJECT_ROOT" timeout "$DEFAULT_TIMEOUT" bats "$suite" >"$log" 2>&1
    fi
    rc=$?
    pass=$(grep -cE '^ok ' "$log" 2>/dev/null)
    skip=$(grep -cE '# skip' "$log" 2>/dev/null)
    fail=$(grep -cE '^not ok ' "$log" 2>/dev/null)
    real_pass=$((pass - skip))
    echo "SUITE ${s}: pass=${real_pass} skip=${skip} fail=${fail} rc=${rc} (log /tmp/ll-${s}.tap)" >>"$OUT"
done

echo "=== DONE ===" >>"$OUT"
