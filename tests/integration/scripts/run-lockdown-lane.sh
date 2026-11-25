#!/usr/bin/env bash
# run-lockdown-lane.sh - run suite 158 on the agent VM booted with
# `lockdown=confidentiality`, then boot it back without it.
#
# The level is a boot parameter: the kernel lets root raise it at run time
# through /sys/kernel/security/lockdown and never lower it, so the only way to
# have it for one suite and give the VM back to the others is a boot each way.
# Both go through the `lockdown` provisioner of ../vagrant/Vagrantfile, never
# through a hand edit of the guest.
#
# Usage:
#   run-lockdown-lane.sh            # boot locked down, run 158, boot back, destroy the VM
#   run-lockdown-lane.sh --keep     # leave the VM up, booted back without lockdown
#
# Results land in target/lockdown-lane/<UTC date>/ (override with --out): the
# provisioner logs, the lane's summary and the suite's TAP file.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEG="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${INTEG}/../.." && pwd)"
VAGRANT_DIR="${INTEG}/vagrant"
LEVEL=confidentiality
OUT=""
KEEP=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out)  OUT="$2"; shift 2 ;;
        --keep) KEEP=true; shift ;;
        -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

OUT="${OUT:-${ROOT}/target/lockdown-lane/$(date -u +%Y-%m-%d)}"
mkdir -p "$OUT"
cd "$VAGRANT_DIR" || exit 1

vagrant up agent >"${OUT}/up.log" 2>&1 || { echo "agent VM did not come up (up.log)" >&2; exit 1; }

rc=0
if AGENT_LOCKDOWN="$LEVEL" vagrant provision agent --provision-with lockdown >"${OUT}/boot-locked.log" 2>&1; then
    vagrant rsync agent >>"${OUT}/boot-locked.log" 2>&1 || true
    vagrant ssh agent -c "sudo EBPFSENTINEL_STRICT_SKIPS=1 \
EBPFSENTINEL_LANE_CLAIMS='bpf-lsm openssl-mlkem userns root lockdown' \
PROJECT_ROOT=/home/vagrant/ebpfsentinel \
bash /home/vagrant/ebpfsentinel/tests/integration/scripts/run-local-lane.sh 158" \
        >"${OUT}/lane.log" 2>&1 || rc=1
    vagrant ssh agent -c "cat /tmp/local-lane-result.txt" >"${OUT}/local-lane-result.txt" 2>/dev/null || true
    vagrant ssh agent -c "sudo sh -c 'cat /tmp/ll-*.tap'" >"${OUT}/158.tap" 2>/dev/null || true
    grep -q '^SUITE .*fail=0 rc=0' "${OUT}/local-lane-result.txt" 2>/dev/null || rc=1
else
    echo "the VM did not boot locked down (boot-locked.log)" >&2
    rc=1
fi

# Back without lockdown whatever happened above: every other suite expects the
# VM unlocked, and a VM left locked down fails them for a reason of the lane.
AGENT_LOCKDOWN="" vagrant provision agent --provision-with lockdown >"${OUT}/boot-back.log" 2>&1 \
    || { echo "the VM did not boot back without lockdown (boot-back.log)" >&2; rc=1; }

if ! $KEEP; then
    vagrant destroy -f agent >/dev/null 2>&1 || true
fi

echo "lockdown lane: $([ "$rc" -eq 0 ] && echo ok || echo FAIL), results in ${OUT}"
exit "$rc"
