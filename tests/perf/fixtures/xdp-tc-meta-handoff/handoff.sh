#!/usr/bin/env bash
# handoff.sh - load, attach, read and remove the programs of handoff.bpf.o on
# the agent VM, for perf/13. Run as root, from the directory build.sh wrote.
#
#   handoff.sh prepare <obj> <copies>
#       Load <copies> copies of the object, each with its own maps, under
#       /sys/fs/bpf/hm-handoff (programs in i<n>, maps in m<n>), and switch
#       kernel.bpf_stats_enabled on, keeping the value it had. Copies, because
#       a tcx chain takes one program once: a chain of K identical programs is
#       K loaded programs, as the agent's chain is.
#   handoff.sh attach <dev> <drv|generic> <xdp_prog> <tc_prog|-> <count>
#       Attach <xdp_prog> of copy 0 in that XDP mode and <tc_prog> of copies
#       0 to <count>-1 to <dev>'s tcx ingress, after removing ours. Refuses
#       (exit 3) when another XDP or tcx program is on <dev>, and exits 4 when
#       the mode is refused by the driver. Prints what is attached.
#   handoff.sh detach <dev>
#       Remove every program of ours from <dev> and nothing else.
#   handoff.sh sample <dev>
#       One JSON line of readings (state.py sample).
#   handoff.sh probe-reset
#       Zero the probe counters of copy 0.
#   handoff.sh cleanup <dev>...
#       Detach from each <dev>, unpin, restore kernel.bpf_stats_enabled.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=/sys/fs/bpf/hm-handoff
STATS_SAVED=/run/hm-handoff.bpf_stats_enabled
PROGS="hm_xdp_parse hm_xdp_meta hm_tc_cb hm_tc_dyn hm_tc_dyn_all hm_tc_dmeta hm_tc_probe"
TC_PROGS="hm_tc_cb hm_tc_dyn hm_tc_dyn_all hm_tc_dmeta hm_tc_probe"
PROBE_SLOTS=16

state() { python3 "${HERE}/state.py" "$@"; }

copies() {
    local d
    for d in "${ROOT}"/i*; do
        [ -d "$d" ] && echo "$d"
    done
}

xdp_name() {
    state attached "$1" | python3 -c 'import json,sys; x=json.load(sys.stdin)["xdp"]; print(x["name"] if x else "")'
}

foreign_tcx() {
    state attached "$1" | python3 -c 'import json,sys; print(" ".join(n for n in json.load(sys.stdin)["tcx_ingress"] if not n.startswith("hm_")))'
}

detach() {
    local dev="$1" name mode pins=() d p
    [ -d "/sys/class/net/${dev}" ] || return 0
    name="$(xdp_name "$dev")"
    if [ -n "$name" ] && [ "${name#hm_}" != "$name" ]; then
        for mode in xdpdrv xdpgeneric; do
            bpftool net detach "$mode" dev "$dev" 2>/dev/null || true
        done
    fi
    for d in $(copies); do
        for p in $TC_PROGS; do
            pins+=("${d}/${p}")
        done
    done
    [ "${#pins[@]}" -eq 0 ] || state tcx-detach "$dev" "${pins[@]}"
}

case "${1:-}" in
    prepare)
        obj="${2:?usage: prepare <obj> <copies>}"
        count="${3:?usage: prepare <obj> <copies>}"
        [ -d "$ROOT" ] && { echo "${ROOT} already there: cleanup first" >&2; exit 1; }
        mkdir -p "$ROOT"
        sysctl -n kernel.bpf_stats_enabled > "$STATS_SAVED"
        sysctl -qw kernel.bpf_stats_enabled=1
        for ((n = 0; n < count; n++)); do
            bpftool prog loadall "$obj" "${ROOT}/i${n}" pinmaps "${ROOT}/m${n}"
        done
        for p in $PROGS; do
            [ -e "${ROOT}/i0/${p}" ] || { echo "program ${p} not loaded" >&2; exit 1; }
        done
        ;;
    attach)
        dev="${2:?}"; mode="${3:?}"; xdp="${4:?}"; tc="${5:?}"; count="${6:?}"
        detach "$dev"
        name="$(xdp_name "$dev")"
        [ -z "$name" ] || { echo "XDP program ${name} already on ${dev}" >&2; exit 3; }
        other="$(foreign_tcx "$dev")"
        [ -z "$other" ] || { echo "tcx ingress of ${dev} carries ${other}" >&2; exit 3; }
        case "$mode" in
            drv) kind=xdpdrv ;;
            generic) kind=xdpgeneric ;;
            *) echo "mode is drv or generic" >&2; exit 1 ;;
        esac
        bpftool net attach "$kind" pinned "${ROOT}/i0/${xdp}" dev "$dev" || exit 4
        if [ "$tc" != "-" ]; then
            for ((n = 0; n < count; n++)); do
                bpftool net attach tcx_ingress pinned "${ROOT}/i${n}/${tc}" dev "$dev"
            done
        fi
        state attached "$dev"
        ;;
    detach)
        detach "${2:?usage: detach <dev>}"
        ;;
    sample)
        state sample "${2:?usage: sample <dev>}" "$ROOT"
        ;;
    probe-reset)
        for ((k = 0; k < PROBE_SLOTS; k++)); do
            bpftool map update pinned "${ROOT}/m0/hm_probe" \
                key "$k" 0 0 0 value 0 0 0 0 0 0 0 0
        done
        ;;
    cleanup)
        shift
        for dev in "$@"; do
            detach "$dev"
        done
        rm -rf "$ROOT"
        if [ -f "$STATS_SAVED" ]; then
            sysctl -qw kernel.bpf_stats_enabled="$(cat "$STATS_SAVED")"
            rm -f "$STATS_SAVED"
        fi
        ;;
    *)
        sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2
        exit 2
        ;;
esac
