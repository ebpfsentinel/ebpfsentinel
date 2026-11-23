#!/usr/bin/env bash
# run-kernel-matrix.sh - run the agent on every kernel of kernels.toml.
#
# For each release, in order: the newest kernel.ubuntu.com mainline build of it
# is resolved (check-kernel-matrix.py --resolve), the agent VM boots it
# (AGENT_KERNEL, kernel-mainline provisioner), scripts/kernel-matrix-guest.sh
# runs the in-kernel harness and the local lane on it, and for the full tier
# the two-machine and transit lanes follow on the same kernel. One kernel at a
# time, on one set of VMs: the build in the VM is made once and reused, since
# nothing in it depends on the kernel.
#
# Usage:
#   run-kernel-matrix.sh                         # full + load tiers (the run that is recorded)
#   run-kernel-matrix.sh --tiers preview         # the release candidate alone
#   run-kernel-matrix.sh --kernels 6.18,7.3
#   run-kernel-matrix.sh --no-2vm --no-3vm       # local lane only, even on full kernels
#   run-kernel-matrix.sh --keep                  # leave the VMs up, back on the HWE kernel
#
# Results land in target/kernel-matrix/<UTC date>/ (override with --out):
# one directory per release with the guest's summary, harness logs and TAP files,
# the lane logs of the full tier, and matrix.md, the table a record under
# records/ is written from. Exits 1 when any blocking kernel failed; a preview
# kernel's failure is reported and does not count.
#
# The VMs are destroyed at the end unless --keep: a run takes hours and must
# not leave three machines behind (build hygiene).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEG="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${INTEG}/../.." && pwd)"
VAGRANT_DIR="${INTEG}/vagrant"
CHECK="${SCRIPT_DIR}/check-kernel-matrix.py"

TIERS="full,load"
KERNELS=""
OUT=""
RUN_2VM=true
RUN_3VM=true
KEEP=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tiers)   TIERS="$2"; shift 2 ;;
        --kernels) KERNELS="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --no-2vm)  RUN_2VM=false; shift ;;
        --no-3vm)  RUN_3VM=false; shift ;;
        --keep)    KEEP=true; shift ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

python3 "$CHECK" >/dev/null || { python3 "$CHECK"; exit 1; }
if [ -n "$KERNELS" ]; then
    list="$(tr ',' '\n' <<<"$KERNELS")"
    for v in $list; do
        python3 "$CHECK" --tier "$v" >/dev/null || exit 1
    done
else
    list="$(python3 "$CHECK" --list "$TIERS")" || exit 1
fi
[ -n "$list" ] || { echo "no kernel selected" >&2; exit 1; }

OUT="${OUT:-${ROOT}/target/kernel-matrix/$(date -u +%Y-%m-%d)}"
mkdir -p "$OUT"
MATRIX="${OUT}/matrix.md"
GUEST_OUT=/tmp/kernel-matrix

echo "kernel matrix: $(echo "$list" | tr '\n' ' ')"
echo "results: ${OUT}"

{
    echo "| kernel | tier | running | harness | local lane | 2VM | 3VM | verdict |"
    echo "|---|---|---|---|---|---|---|---|"
} >"$MATRIX"

blocking_failed=0
cd "$VAGRANT_DIR" || exit 1

# The first `up` provisions the VM in full, builds included, on whatever kernel
# AGENT_KERNEL names, so the matrix starts from the first kernel's boot.
first="$(head -1 <<<"$list")"
first_build="$(python3 "$CHECK" --resolve "$first")" || { echo "no build of ${first}" >&2; exit 1; }
AGENT_KERNEL="$first_build" vagrant up agent || { echo "agent VM did not come up" >&2; exit 1; }

for v in $list; do
    tier="$(python3 "$CHECK" --tier "$v")"
    dir="${OUT}/${v}"
    mkdir -p "$dir"
    if ! build="$(python3 "$CHECK" --resolve "$v")"; then
        echo "| ${v} | ${tier} | - | - | - | - | - | no build on kernel.ubuntu.com |" >>"$MATRIX"
        [ "$tier" = preview ] || blocking_failed=1
        continue
    fi
    export AGENT_KERNEL="$build"
    echo "=== ${v} -> ${build} (${tier}) ==="

    if ! vagrant provision agent --provision-with kernel-mainline >"${dir}/boot.log" 2>&1; then
        echo "| ${v} | ${tier} | - | - | - | - | - | did not boot (boot.log) |" >>"$MATRIX"
        [ "$tier" = preview ] || blocking_failed=1
        continue
    fi
    # The VM rebooted: the rsync folder is pushed again so the guest runs the
    # tree under test, not the one the first boot carried.
    vagrant rsync agent >>"${dir}/boot.log" 2>&1 || true

    vagrant ssh agent -c "sudo bash /home/vagrant/ebpfsentinel/tests/integration/scripts/kernel-matrix-guest.sh '${build}' '${tier}' '${GUEST_OUT}/${v}'" \
        >"${dir}/guest.log" 2>&1
    guest_rc=$?
    vagrant ssh agent -c "sudo tar -C '${GUEST_OUT}' -cz '${v}'" 2>/dev/null | tar -C "$OUT" -xz 2>/dev/null || true

    summary="${dir}/summary.txt"
    running="$(sed -n 's/^running //p' "$summary" 2>/dev/null | head -1)"
    harness="$(grep -c '^harness .* ok' "$summary" 2>/dev/null)/4"
    lane="$(sed -n 's/^local lane *//p' "$summary" 2>/dev/null | head -1)"
    v2="-"
    v3="-"
    rc=$guest_rc

    if [ "$tier" = full ] && $RUN_2VM; then
        if EBPFSENTINEL_STRICT_SKIPS=1 bash "${SCRIPT_DIR}/run-in-2vm.sh" >"${dir}/2vm.log" 2>&1; then v2=ok; else v2=FAIL; rc=1; fi
    fi
    if [ "$tier" = full ] && $RUN_3VM; then
        if EBPFSENTINEL_STRICT_SKIPS=1 bash "${SCRIPT_DIR}/run-in-3vm.sh" >"${dir}/3vm.log" 2>&1; then v3=ok; else v3=FAIL; rc=1; fi
        # The transit lane leaves the agent on its own topology; the next
        # kernel starts from the default one.
        VAGRANT_3VM=1 vagrant destroy -f backend >/dev/null 2>&1 || true
    fi

    verdict=ok
    if [ "$rc" -ne 0 ]; then
        verdict=FAIL
        [ "$tier" = preview ] && verdict="FAIL (preview, not blocking)" || blocking_failed=1
    fi
    echo "| ${v} | ${tier} | ${running:--} | ${harness} | ${lane:--} | ${v2} | ${v3} | ${verdict} |" >>"$MATRIX"
    echo "    ${verdict}"
done

unset AGENT_KERNEL
if $KEEP; then
    vagrant provision agent --provision-with kernel-mainline >/dev/null 2>&1 || true
    echo "VMs kept, agent back on the HWE kernel"
else
    VAGRANT_3VM=1 vagrant destroy -f agent attacker backend >/dev/null 2>&1 || true
    vagrant destroy -f agent attacker >/dev/null 2>&1 || true
fi

echo
cat "$MATRIX"
exit "$blocking_failed"
