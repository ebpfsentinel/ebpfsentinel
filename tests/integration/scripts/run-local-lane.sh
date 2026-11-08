#!/usr/bin/env bash
# run-local-lane.sh - run a set of agent-local (netns) bats suites on the agent
# VM, one at a time with a clean eBPF/netns slate between each, and write a
# compact pass/skip/fail summary to /tmp/local-lane-result.txt.
#
# Usage (on the agent VM):
#   sudo PROJECT_ROOT=/home/vagrant/ebpfsentinel bash scripts/run-local-lane.sh 33 52 57 58
#
# The same runner drives the container runtimes lane, which is one machine
# too but a different one: ../vagrant-runtimes carries Podman, containerd and
# CRI-O, and the suites written for it run there and nowhere else. On that VM:
#   sudo EBPFSENTINEL_LANE=runtimes PROJECT_ROOT=/home/vagrant/ebpfsentinel \
#       bash scripts/run-local-lane.sh
#
# BATS_FILTER, when set, is handed to bats as --filter, so a fix reruns only
# the tests it touches.
set -u

# Which one-machine lane this is: `local` (../vagrant, the agent VM) or
# `runtimes` (../vagrant-runtimes). Read against the `lanes` field of
# coverage-matrix.yaml.
LANE="${EBPFSENTINEL_LANE:-local}"
case "${LANE}" in
    local|runtimes) ;;
    *)
        echo "ERROR: EBPFSENTINEL_LANE must be local or runtimes, not '${LANE}'" >&2
        exit 1
        ;;
esac

PROJECT_ROOT="${PROJECT_ROOT:-/home/vagrant/ebpfsentinel}"
# The canonical lane provisions every prerequisite a suite owns, so a
# `soft_skip` here means a regression rather than a missing capability.
# Export EBPFSENTINEL_STRICT_SKIPS=1 before calling this script to turn those
# skips into failures (env_skip is unaffected - see lib/skip_policy.bash).
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
    # A broker a suite left behind goes with its whole session: in its own
    # mount namespace it pins the test netns file, and the next suite could
    # not create the namespace again.
    local wp wpg
    for wp in $(pgrep -f 'warden serve /tmp/ebpfsentinel-warden-' 2>/dev/null); do
        wpg="$(ps -o pgid= -p "${wp}" 2>/dev/null | tr -d ' ')"
        [ -n "${wpg}" ] && kill -KILL -- "-${wpg}" 2>/dev/null || true
    done
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

# ── Build suite list ───────────────────────────────────────────────
# Suites named on the command line win: the lane is also how a single suite
# is re-run after a fix. With no argument the lane runs what it is written
# for, read off the `lanes` field of coverage-matrix.yaml.
#
# Running every suite on disk was the older behaviour and it was wrong the
# same way it was wrong on the two- and three-machine lanes: a suite whose
# traffic comes off a second machine has no way to produce it here, so it
# skips test by test and the run reports thirty-four skips that are a fact
# about the lane rather than about the product.
list_off_lane_suites() {
    awk '
        /^attack_suites:/ { inblk=1; next }
        inblk && /^[a-z_]+:/ { inblk=0 }
        inblk && /^[[:space:]]*-?[[:space:]]*suite:/ {
            s=$NF; gsub(/[\042\047]/,"",s); last=s; next
        }
        inblk && /^[[:space:]]*lanes:/ {
            if (last != "" && index($0, "local") == 0) print last
            last=""
        }
    ' coverage-matrix.yaml | sort -u
}

# Suites whose row names the runtimes lane and not the local one: they need
# the runtimes the agent VM does not carry.
list_runtimes_only_suites() {
    awk '
        /^attack_suites:/ { inblk=1; next }
        inblk && /^[a-z_]+:/ { inblk=0 }
        inblk && /^[[:space:]]*-?[[:space:]]*suite:/ {
            s=$NF; gsub(/[\042\047]/,"",s); last=s; next
        }
        inblk && /^[[:space:]]*lanes:/ {
            if (last != "" && index($0, "runtimes") > 0 && index($0, "local") == 0) print last
            last=""
        }
    ' coverage-matrix.yaml | sort -u
}

# Suites a row writes for the runtimes lane, with or without the local one.
list_runtimes_suites() {
    awk '
        /^attack_suites:/ { inblk=1; next }
        inblk && /^[a-z_]+:/ { inblk=0 }
        inblk && /^[[:space:]]*-?[[:space:]]*suite:/ {
            s=$NF; gsub(/[\042\047]/,"",s); last=s; next
        }
        inblk && /^[[:space:]]*lanes:/ {
            if (last != "" && index($0, "runtimes") > 0) print last
            last=""
        }
    ' coverage-matrix.yaml | sort -n -u
}

list_local_suites() {
    local off
    off=" $(list_off_lane_suites | tr '\n' ' ')"
    for f in suites/*.bats; do
        local n
        n="$(basename "$f" | sed 's/-.*//')"
        case "$off" in
            *" ${n} "*) continue ;;
        esac
        echo "$n"
    done
}

if [ "$#" -gt 0 ]; then
    SUITES="$*"
elif [ "${LANE}" = runtimes ]; then
    SUITES="$(list_runtimes_suites | tr '\n' ' ')"
else
    SUITES="$(list_local_suites | tr '\n' ' ')"
fi
if [ -z "${SUITES// /}" ]; then
    echo "ERROR: no suite under suites/ is written for the ${LANE} lane" >&2
    exit 1
fi
RUNTIMES_ONLY=" $(list_runtimes_only_suites | tr '\n' ' ')"
BATS_ARGS=()
[ -n "${BATS_FILTER:-}" ] && BATS_ARGS=(--filter "${BATS_FILTER}")

for s in $SUITES; do
    suite="$(ls suites/${s}-*.bats 2>/dev/null | head -1)"
    if [ -z "$suite" ]; then
        echo "SUITE ${s}: NOT FOUND" >>"$OUT"
        continue
    fi
    # Named on the command line of the agent VM's lane, a runtimes suite
    # would only skip on the runtimes it cannot find there. Say where it runs
    # rather than report a skip that is a fact about the machine.
    if [ "${LANE}" = local ]; then
        case "${RUNTIMES_ONLY}" in
            *" ${s} "*)
                echo "SUITE ${s}: NOT RUN (written for the runtimes lane: EBPFSENTINEL_LANE=runtimes on ../vagrant-runtimes)" >>"$OUT"
                continue
                ;;
        esac
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
            timeout "$UNPRIVILEGED_TIMEOUT" bats "${BATS_ARGS[@]}" "$suite" >"$log" 2>&1
    else
        PROJECT_ROOT="$PROJECT_ROOT" timeout "$DEFAULT_TIMEOUT" bats "${BATS_ARGS[@]}" "$suite" >"$log" 2>&1
    fi
    rc=$?
    pass=$(grep -cE '^ok ' "$log" 2>/dev/null)
    skip=$(grep -cE '# skip' "$log" 2>/dev/null)
    fail=$(grep -cE '^not ok ' "$log" 2>/dev/null)
    real_pass=$((pass - skip))
    echo "SUITE ${s}: pass=${real_pass} skip=${skip} fail=${fail} rc=${rc} (log /tmp/ll-${s}.tap)" >>"$OUT"
done

echo "=== DONE ===" >>"$OUT"
