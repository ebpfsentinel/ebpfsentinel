#!/usr/bin/env bats
# 13-xdp-tc-meta-handoff.bats - should the tc ingress chain read the parse XDP
# already made, from the packet's metadata through bpf_dynptr_from_skb_meta,
# instead of parsing again in its first program and handing the result along
# in skb->cb (crates/ebpf-helpers/src/pktmeta.rs)? Decided on figures here.
#
# Pass criteria, all of them, for the metadata handoff (arm B-dynptr) to be
# taken:
#   1. Not slower. On every traffic profile, B-dynptr's median kernel time per
#      wire packet (XDP plus the whole tc chain) is at most A-cb's median plus
#      A-cb's own spread across its runs (max minus min).
#   2. Parse once kept. B-dynptr parses in tc at most once per skb, and
#      parses in tc on no more than 1 % of skbs when the record is there.
#   3. The record reaches tc. On vmxnet3 (eth1 of the lane, in the XDP mode
#      the timing ran in) and on veth, on untagged traffic, at least 99 % of
#      the IP packets the probe sees carry a valid record, and the timed
#      B-dynptr runs found it on at least 99 % of skbs.
#   4. VLAN accounted for. On every tagged cell where a record arrived, each
#      packet's record either matches tc's own parse or matches it once
#      shifted by the 4 bytes of a tag the stack took out of the frame.
# Any criterion false: the handoff stays in skb->cb as today, the first tc
# program parsing and writing the control block. Criterion 4 alone false or
# met only through the shift: the record may be adopted only with tc
# subtracting VLAN_HLEN from its offsets whenever skb->vlan_present and the
# record says XDP saw the tag in line, and taking the VLAN id from
# skb->vlan_tci. A driver on which the record does not arrive keeps the parse
# in tc there. In every case the egress chain (tc-nat-egress, tc-qos) keeps
# skb->cb, since no XDP program runs on egress.
#
# Arms, each a chain of HANDOFF_CHAIN identical tc programs (six by default,
# as many as pktmeta's users on the ingress chain) behind one XDP program, on
# the agent VM's eth1, the agent stopped:
#   A-cb          today: XDP parses and keeps nothing; the first tc program
#                 parses and writes skb->cb, the others read it.
#   B-dynptr      XDP parses and writes the record in front of the packet;
#                 the first tc program reads it through the dynptr and copies
#                 it into skb->cb, the others read skb->cb. The candidate.
#   B-dynptr-all  the same record read through the dynptr by every program.
#   B-datameta    as B-dynptr through the direct __sk_buff data_meta pointer,
#                 which the product could also use: reported, not judged.
#
# Profiles, each run HANDOFF_RUNS times for HANDOFF_SECONDS, arms rotated per
# round so that drift spreads over all of them:
#   udp-64     pktgen from this VM, 60-byte UDP frames, random sources: one
#              skb per frame, cost per packet at the most packets per second
#   tcp-gro    iperf3, 4 streams to the agent VM: GRO merges frames before
#              tc, so the tc chain runs once per merged skb, not per frame
# Read on the agent VM over the steady middle of a run: each program's run
# time and count (kernel.bpf_stats_enabled), eth1's rx_packets, /proc/stat,
# and the fixtures' counters of which path each program took.
#
# Facts recorded with the probe (hm_tc_probe alone behind hm_xdp_meta, ping
# traffic), each cell asserted to have seen traffic and reported as counted:
#   vmxnet3  eth1 in drv and generic XDP mode, receive VLAN offload on and
#            off, untagged, 802.1Q and QinQ (802.1ad outside 802.1Q)
#   veth     the host end of a veth pair into a namespace on the agent VM,
#            drv and generic, untagged and 802.1Q
#
# Why the fixtures stand for the product (fixtures/xdp-tc-meta-handoff/):
# the parse is pktmeta::parse rewritten in C step by step (two VLAN tags,
# IHL, six IPv6 extension headers with the same length rules and 512-byte
# cap, ports), the control block words and their check word are packed and
# compared as pktmeta does, the trace mark is honoured on write, the chain
# is tcx with every program returning TCX_NEXT as the agent attaches them,
# and every arm pays the same map lookup and counter increments, so what
# differs between arms is only the handoff itself.
#
# What this suite cannot tell: what the product's programs cost around the
# handoff (the IDS, threat intel, conntrack work is absent, so the handoff's
# share of a real chain is smaller than here); behaviour on a driver other
# than vmxnet3 and veth, or on real hardware; anything about egress; the cost
# of the 32-byte metadata cap against the trace record, which shares it; and
# whether the product's XDP programs, which tail-call and run several to a
# packet, would place the write where this one does. A lane guest is not a
# production node: no figure is asserted, the criteria are computed and the
# decision is written in the report for a reader to judge.
#
# Requires the 2VM lane (EBPF_2VM_MODE=true), pktgen, iperf3, jq and ping
# here; clang, bpftool, python3, iperf3, ethtool and ip on the agent VM, and
# an agent VM kernel carrying bpf_dynptr_from_skb_meta. Writes
# results/<date>-xdp-tc-meta-handoff/report.json beside this file and the
# same report to /tmp/ebpfsentinel-xdp-tc-meta-handoff.json.

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'
load '../integration/lib/pktgen_helpers'

HANDOFF_REPORT="/tmp/ebpfsentinel-xdp-tc-meta-handoff.json"
HANDOFF_RESULTS_DIR="${HANDOFF_RESULTS_DIR:-${BATS_TEST_DIRNAME}/results/$(date +%F)-xdp-tc-meta-handoff}"
HANDOFF_SECONDS="${HANDOFF_SECONDS:-15}"
HANDOFF_RUNS="${HANDOFF_RUNS:-3}"
HANDOFF_CHAIN="${HANDOFF_CHAIN:-6}"
REMOTE_DIR="/tmp/ebpfsentinel-meta-handoff"
IPERF_PORT=5313
NS=hm-ns
VID=413
SVID=414

# name:xdp program:tc program
ARMS="A-cb:hm_xdp_parse:hm_tc_cb B-dynptr:hm_xdp_meta:hm_tc_dyn B-dynptr-all:hm_xdp_meta:hm_tc_dyn_all B-datameta:hm_xdp_meta:hm_tc_dmeta"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 13 floods the agent VM's eth1 from this host (2VM lane only)"
    fi
    require_tool jq
    require_tool iperf3
    require_tool ping
    require_pktgen

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    local tool
    for tool in clang bpftool python3 iperf3 ethtool ip; do
        _agent_ssh_sudo which "$tool" &>/dev/null || soft_skip "${tool} not installed on agent VM"
    done
    [ "$HANDOFF_SECONDS" -ge 8 ] || { echo "HANDOFF_SECONDS must be at least 8" >&2; return 1; }
    [ "$HANDOFF_CHAIN" -ge 1 ] || { echo "HANDOFF_CHAIN must be at least 1" >&2; return 1; }

    export DATA_DIR="/tmp/ebpfsentinel-test-data-handoff-$$"
    mkdir -p "$DATA_DIR" "$HANDOFF_RESULTS_DIR"
    stop_ebpf_agent 2>/dev/null || true
    _handoff_cleanup

    _agent_ssh rm -rf "$REMOTE_DIR"
    local file
    for file in build.sh helpers.h handoff.bpf.c handoff.sh state.py; do
        _agent_scp "${FIXTURE_DIR}/xdp-tc-meta-handoff/${file}" "${REMOTE_DIR}/${file}" || {
            echo "cannot copy ${file} to the agent VM" >&2
            return 1
        }
    done
    _agent_scp "${FIXTURE_DIR}/bpf-qdisc/kfunc-externs.py" "${REMOTE_DIR}/kfunc-externs.py" || return 1
    local rc=0
    _agent_ssh bash "${REMOTE_DIR}/build.sh" "${REMOTE_DIR}/out" >"${HANDOFF_RESULTS_DIR}/build.log" 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        soft_skip "handoff fixtures not buildable on the agent VM: $(tail -1 "${HANDOFF_RESULTS_DIR}/build.log")"
    elif [ "$rc" -ne 0 ]; then
        cat "${HANDOFF_RESULTS_DIR}/build.log" >&2
        return 1
    fi
    _remote "bash ${REMOTE_DIR}/handoff.sh prepare ${REMOTE_DIR}/out/handoff.bpf.o ${HANDOFF_CHAIN}" \
        > "${DATA_DIR}/prepare.log" 2>&1 || { cat "${DATA_DIR}/prepare.log" >&2; return 1; }

    # The XDP mode the timing runs in: native where the driver takes it, as
    # the agent's automatic attach gets, else generic.
    local mode=drv
    rc=0
    _handoff_attach "$EBPF_AGENT_INTERFACE" drv hm_xdp_parse hm_tc_cb >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 4 ]; then
        mode=generic
    elif [ "$rc" -ne 0 ]; then
        echo "cannot attach to ${EBPF_AGENT_INTERFACE} on the agent VM (exit ${rc})" >&2
        return 1
    fi
    _handoff_detach "$EBPF_AGENT_INTERFACE"
    echo "$mode" > "${DATA_DIR}/mode"

    local rxvlan
    rxvlan="$(_remote "ethtool -k ${EBPF_AGENT_INTERFACE} | awk '/^rx-vlan-offload:/ {print \$2}'")"
    echo "$rxvlan" > "${DATA_DIR}/rxvlan.before"

    jq -n --arg kernel "$(_agent_ssh uname -r)" --argjson cpus "$(_agent_ssh nproc)" \
        --arg driver "$(_remote "ethtool -i ${EBPF_AGENT_INTERFACE} | awk '/^driver:/ {print \$2}'")" \
        --arg mode "$mode" --arg rxvlan "$rxvlan" \
        --argjson seconds "$HANDOFF_SECONDS" --argjson runs "$HANDOFF_RUNS" --argjson chain "$HANDOFF_CHAIN" \
        '{kernel: $kernel, cpus: $cpus, interface: {driver: $driver, xdp_mode_timed: $mode,
          rx_vlan_offload_default: $rxvlan}, seconds: $seconds, runs_per_profile: $runs,
          tc_chain_length: $chain, facts: {vmxnet3: {}, veth: {}}, arms: {}}' > "$HANDOFF_REPORT"
}

teardown_file() {
    pktgen_stop 2>/dev/null || true
    _handoff_cleanup
    [ -s "${DATA_DIR}/rxvlan.before" ] && _remote "ethtool -K ${EBPF_AGENT_INTERFACE} rxvlan $(cat "${DATA_DIR}/rxvlan.before")" >/dev/null 2>&1 || true
    _agent_ssh rm -rf "$REMOTE_DIR" 2>/dev/null || true
    [ -f "$HANDOFF_REPORT" ] && [ -d "${HANDOFF_RESULTS_DIR:-}" ] && cp "$HANDOFF_REPORT" "${HANDOFF_RESULTS_DIR}/report.json"
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-handoff-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# Run a script as root on the agent VM, fed on stdin so it needs no quoting.
_remote() {
    printf '%s\n' "$1" | $AGENT_SSH_CMD -- sudo bash -s
}

_handoff() {
    _remote "bash ${REMOTE_DIR}/handoff.sh $*"
}

# _handoff_attach <dev> <drv|generic> <xdp> <tc|-> [count]
_handoff_attach() {
    _handoff attach "$1" "$2" "$3" "$4" "${5:-$HANDOFF_CHAIN}"
}

_handoff_detach() {
    _handoff detach "$1" >/dev/null 2>&1 || true
}

# Removes everything the suite may have put on either VM, whatever stage the
# run stopped at.
_handoff_cleanup() {
    _remote "
        [ -x ${REMOTE_DIR}/handoff.sh ] && bash ${REMOTE_DIR}/handoff.sh cleanup ${EBPF_AGENT_INTERFACE} hm-v0 || true
        ip netns del ${NS} 2>/dev/null || true
        ip link del hm-v0 2>/dev/null || true
        ip link del ${EBPF_AGENT_INTERFACE}.${VID} 2>/dev/null || true
        ip link del ${EBPF_AGENT_INTERFACE}.s${SVID}.c13 2>/dev/null || true
        ip link del ${EBPF_AGENT_INTERFACE}.s${SVID} 2>/dev/null || true
        pkill -f 'iperf3 -s -D -p ${IPERF_PORT}' 2>/dev/null || true
    " >/dev/null 2>&1 || true
    sudo ip link del "${PKTGEN_IFACE}.${VID}" 2>/dev/null || true
    sudo ip link del "${PKTGEN_IFACE}.s${SVID}.c13" 2>/dev/null || true
    sudo ip link del "${PKTGEN_IFACE}.s${SVID}" 2>/dev/null || true
}

_sample() {
    _handoff sample "$1"
}

# Adds tagged links on both VMs: <tag> is 8021q or qinq. Echoes the agent's
# address on it.
_vlan_up() {
    local here="$PKTGEN_IFACE" there="$EBPF_AGENT_INTERFACE"
    case "$1" in
        8021q)
            _remote "modprobe 8021q
                ip link add link ${there} name ${there}.${VID} type vlan id ${VID}
                ip addr add 10.213.13.1/24 dev ${there}.${VID}
                ip link set ${there}.${VID} up" >/dev/null
            sudo modprobe 8021q
            sudo ip link add link "$here" name "${here}.${VID}" type vlan id "$VID"
            sudo ip addr add 10.213.13.2/24 dev "${here}.${VID}"
            sudo ip link set "${here}.${VID}" up
            echo 10.213.13.1
            ;;
        qinq)
            _remote "modprobe 8021q
                ip link add link ${there} name ${there}.s${SVID} type vlan proto 802.1ad id ${SVID}
                ip link add link ${there}.s${SVID} name ${there}.s${SVID}.c13 type vlan id 13
                ip addr add 10.213.14.1/24 dev ${there}.s${SVID}.c13
                ip link set ${there}.s${SVID} up
                ip link set ${there}.s${SVID}.c13 up" >/dev/null
            sudo modprobe 8021q
            sudo ip link add link "$here" name "${here}.s${SVID}" type vlan proto 802.1ad id "$SVID"
            sudo ip link add link "${here}.s${SVID}" name "${here}.s${SVID}.c13" type vlan id 13
            sudo ip addr add 10.213.14.2/24 dev "${here}.s${SVID}.c13"
            sudo ip link set "${here}.s${SVID}" up
            sudo ip link set "${here}.s${SVID}.c13" up
            echo 10.213.14.1
            ;;
    esac
}

_vlan_down() {
    _remote "
        ip link del ${EBPF_AGENT_INTERFACE}.${VID} 2>/dev/null || true
        ip link del ${EBPF_AGENT_INTERFACE}.s${SVID}.c13 2>/dev/null || true
        ip link del ${EBPF_AGENT_INTERFACE}.s${SVID} 2>/dev/null || true
    " >/dev/null 2>&1 || true
    sudo ip link del "${PKTGEN_IFACE}.${VID}" 2>/dev/null || true
    sudo ip link del "${PKTGEN_IFACE}.s${SVID}.c13" 2>/dev/null || true
    sudo ip link del "${PKTGEN_IFACE}.s${SVID}" 2>/dev/null || true
}

# _probe_cell <section> <cell> <dev> <mode> <ping command run where the
# traffic starts>
# Attaches the probe behind hm_xdp_meta, pings, reads, and writes the cell
# into the report's facts. A mode the driver refuses is recorded as such.
_probe_cell() {
    local section="$1" cell="$2" dev="$3" mode="$4" ping_cmd="$5" rc=0 before after
    _handoff_attach "$dev" "$mode" hm_xdp_meta hm_tc_probe 1 > "${DATA_DIR}/attach.log" 2>&1 || rc=$?
    if [ "$rc" -eq 4 ]; then
        _handoff_detach "$dev"
        jq --arg s "$section" --arg c "$cell" '.facts[$s][$c] = {attached: false}' \
            "$HANDOFF_REPORT" > "${HANDOFF_REPORT}.tmp" && mv "${HANDOFF_REPORT}.tmp" "$HANDOFF_REPORT"
        echo "  ${section} ${cell}: ${mode} XDP refused by the driver" >&3
        return 0
    elif [ "$rc" -ne 0 ]; then
        cat "${DATA_DIR}/attach.log" >&2
        return 1
    fi
    _handoff probe-reset >/dev/null
    before="$(_sample "$dev")"
    eval "$ping_cmd" > "${DATA_DIR}/ping.log" 2>&1 || true
    after="$(_sample "$dev")"
    _handoff_detach "$dev"
    jq --arg s "$section" --arg c "$cell" --argjson b "$before" --argjson a "$after" '
        .facts[$s][$c] = {
            attached: true,
            probe: $a.probe,
            xdp_runs: ($a.cnt.xdp_run - $b.cnt.xdp_run),
            xdp_saw_tag_inline: ($a.cnt.xdp_vlan_inline - $b.cnt.xdp_vlan_inline),
            xdp_meta_refused: ($a.cnt.xdp_meta_refused - $b.cnt.xdp_meta_refused),
            record_rate: (if $a.probe.ip > 0 then ($a.probe.agree + $a.probe.disagree) / $a.probe.ip else null end),
            offsets_explained: (if ($a.probe.dynptr_valid + $a.probe.datameta_valid) == 0 then null
                                else ($a.probe.disagree - $a.probe.agree_after_strip) == 0 end),
            needs_strip_shift: ($a.probe.agree_after_strip > 0)
        }' "$HANDOFF_REPORT" > "${HANDOFF_REPORT}.tmp" && mv "${HANDOFF_REPORT}.tmp" "$HANDOFF_REPORT"
    echo "  ${section} ${cell}: $(jq -c --arg s "$section" --arg c "$cell" '.facts[$s][$c] | {record_rate, offsets_explained, needs_strip_shift, xdp_saw_tag_inline, probe: (.probe | {runs, ip, dynptr_valid, datameta_valid, meta_absent, meta_bad, skb_vlan, meta_vlan, tc_inline_vlan, vlan_id_agree})}' "$HANDOFF_REPORT")" >&3
    # A cell that saw no packet at all says nothing, which is a fault here.
    [ "$(jq --arg s "$section" --arg c "$cell" '.facts[$s][$c].probe.runs' "$HANDOFF_REPORT")" -gt 0 ]
}

# One timed run of <arm> on <profile>: the traffic starts, the agent VM is
# read after two seconds and again two seconds before it stops.
_timed_run() {
    local arm="$1" profile="$2" name xdp tc before after mode pid
    name="${arm%%:*}"; xdp="${arm#*:}"; tc="${xdp#*:}"; xdp="${xdp%%:*}"
    mode="$(cat "${DATA_DIR}/mode")"
    _handoff_attach "$EBPF_AGENT_INTERFACE" "$mode" "$xdp" "$tc" > "${DATA_DIR}/attach.log" 2>&1 || {
        cat "${DATA_DIR}/attach.log" >&2
        return 1
    }
    case "$profile" in
        udp-64)
            pktgen_run "$HANDOFF_SECONDS" 60 9 0 > "${DATA_DIR}/traffic.log" 2>&1 &
            pid=$!
            ;;
        tcp-gro)
            iperf3 -c "$AGENT_VM_IP" -p "$IPERF_PORT" -P 4 -t "$HANDOFF_SECONDS" -J > "${DATA_DIR}/traffic.log" 2>&1 &
            pid=$!
            ;;
    esac
    sleep 2
    before="$(_sample "$EBPF_AGENT_INTERFACE")"
    sleep "$((HANDOFF_SECONDS - 4))"
    after="$(_sample "$EBPF_AGENT_INTERFACE")"
    wait "$pid" || true
    pktgen_stop 2>/dev/null || true
    _handoff_detach "$EBPF_AGENT_INTERFACE"
    jq --arg arm "$name" --arg p "$profile" --arg xdp "$xdp" --arg tc "$tc" --argjson k "$HANDOFF_CHAIN" \
       --argjson b "$before" --argjson a "$after" '
        def d(f): ($a | f) - ($b | f);
        def per(x; y): if y > 0 then x / y else null end;
        (d(.t_ns) / 1e9) as $dt
        | d(.progs[$xdp].run_cnt // 0) as $xr | d(.progs[$xdp].run_time_ns // 0) as $xt
        | d(.progs[$tc].run_cnt // 0) as $tr | d(.progs[$tc].run_time_ns // 0) as $tt
        | ($tr / $k) as $skbs
        | (([$a.cpu[]] | add) - ([$b.cpu[]] | add)) as $jif
        | {
            seconds: $dt,
            wire_pps: per($xr; $dt),
            rx_pps: per(d(.rx_packets); $dt),
            xdp_ns_per_run: per($xt; $xr),
            tc_chain_ns_per_skb: per($tt; $skbs),
            ns_per_wire_packet: per($xt + $tt; $xr),
            skbs_per_wire_packet: per($skbs; $xr),
            cpu_busy_pct: (if $jif > 0 then 100 * (1 - (d(.cpu.idle) + d(.cpu.iowait)) / $jif) else null end),
            cpu_softirq_pct: (if $jif > 0 then 100 * d(.cpu.softirq) / $jif else null end),
            tc_parses_per_skb: per(d(.cnt.tc_parse); $skbs),
            record_hit_rate: per(d(.cnt.tc_meta_hit); d(.cnt.tc_meta_hit) + d(.cnt.tc_parse)),
            record_bad: d(.cnt.tc_meta_bad),
            cb_hits_per_skb: per(d(.cnt.tc_cb_hit); $skbs),
            xdp_meta_refused: d(.cnt.xdp_meta_refused),
            xdp_runs: $xr,
            tc_runs: $tr
          } as $run
        | .arms[$arm].xdp = $xdp | .arms[$arm].tc = $tc
        | .arms[$arm].profiles[$p].runs += [$run]
    ' "$HANDOFF_REPORT" > "${HANDOFF_REPORT}.tmp" && mv "${HANDOFF_REPORT}.tmp" "$HANDOFF_REPORT"
    echo "  ${name} ${profile}: $(jq -c --arg a "$name" --arg p "$profile" '.arms[$a].profiles[$p].runs[-1] | {wire_pps, ns_per_wire_packet, xdp_ns_per_run, tc_chain_ns_per_skb, skbs_per_wire_packet, cpu_busy_pct, tc_parses_per_skb, record_hit_rate}' "$HANDOFF_REPORT")" >&3
    [ "$(jq --arg a "$name" --arg p "$profile" '.arms[$a].profiles[$p].runs[-1].xdp_runs' "$HANDOFF_REPORT")" -gt 0 ]
}

# Rounds of every arm on <profile>, the order rotated each round.
_profile() {
    local profile="$1" round arms i n
    read -r -a arms <<< "$ARMS"
    n="${#arms[@]}"
    for ((round = 0; round < HANDOFF_RUNS; round++)); do
        for ((i = 0; i < n; i++)); do
            _timed_run "${arms[$(((i + round) % n))]}" "$profile"
        done
    done
}

# ── Facts ───────────────────────────────────────────────────────────

@test "facts: the record across vmxnet3, by XDP mode, VLAN offload and tagging" {
    local mode rxvlan tag addr rc
    for mode in drv generic; do
        for rxvlan in on off; do
            rc=0
            _remote "ethtool -K ${EBPF_AGENT_INTERFACE} rxvlan ${rxvlan}" >/dev/null 2>&1 || rc=$?
            if [ "$rc" -ne 0 ]; then
                echo "  vmxnet3 ${mode}: rx-vlan-offload cannot be set ${rxvlan}" >&3
                continue
            fi
            _probe_cell vmxnet3 "${mode}-rxvlan-${rxvlan}-untagged" "$EBPF_AGENT_INTERFACE" "$mode" \
                "ping -c 40 -i 0.05 -W 1 ${AGENT_VM_IP}"
            for tag in 8021q qinq; do
                addr="$(_vlan_up "$tag")"
                _probe_cell vmxnet3 "${mode}-rxvlan-${rxvlan}-${tag}" "$EBPF_AGENT_INTERFACE" "$mode" \
                    "ping -c 40 -i 0.05 -W 1 ${addr}"
                _vlan_down
            done
        done
    done
    _remote "ethtool -K ${EBPF_AGENT_INTERFACE} rxvlan $(cat "${DATA_DIR}/rxvlan.before")" >/dev/null 2>&1 || true
}

@test "facts: the record across veth, by XDP mode and tagging" {
    _remote "
        ip netns add ${NS}
        ip link add hm-v0 type veth peer name hm-v1 netns ${NS}
        ip addr add 10.213.20.1/24 dev hm-v0
        ip link set hm-v0 up
        ip -n ${NS} addr add 10.213.20.2/24 dev hm-v1
        ip -n ${NS} link set hm-v1 up
        ip -n ${NS} link set lo up
        modprobe 8021q
        ip link add link hm-v0 name hm-v0.${VID} type vlan id ${VID}
        ip addr add 10.213.21.1/24 dev hm-v0.${VID}
        ip link set hm-v0.${VID} up
        ip -n ${NS} link add link hm-v1 name hm-v1.${VID} type vlan id ${VID}
        ip -n ${NS} addr add 10.213.21.2/24 dev hm-v1.${VID}
        ip -n ${NS} link set hm-v1.${VID} up
    " >/dev/null
    local mode
    for mode in drv generic; do
        _probe_cell veth "${mode}-untagged" hm-v0 "$mode" \
            "_remote 'ip netns exec ${NS} ping -c 40 -i 0.05 -W 1 10.213.20.1'"
        _probe_cell veth "${mode}-8021q" hm-v0 "$mode" \
            "_remote 'ip netns exec ${NS} ping -c 40 -i 0.05 -W 1 10.213.21.1'"
    done
    _remote "ip netns del ${NS}; ip link del hm-v0 2>/dev/null || true" >/dev/null 2>&1 || true
}

# ── Timing ──────────────────────────────────────────────────────────

@test "timing: 60-byte UDP frames from pktgen, every arm" {
    _profile udp-64
}

@test "timing: four TCP streams, GRO merging before tc, every arm" {
    _remote "iperf3 -s -D -p ${IPERF_PORT}" >/dev/null
    sleep 1
    _profile tcp-gro
    _remote "pkill -f 'iperf3 -s -D -p ${IPERF_PORT}'" >/dev/null 2>&1 || true
}

# ── Report ──────────────────────────────────────────────────────────

@test "report: medians, the four criteria, and the decision" {
    jq -e '.arms["A-cb"].profiles and .arms["B-dynptr"].profiles' "$HANDOFF_REPORT" >/dev/null || {
        echo "A-cb or B-dynptr has no figures, nothing to compare" >&2
        return 1
    }
    jq '
        def median: map(select(. != null)) | sort
            | if length == 0 then null else .[(length - 1) / 2 | floor] end;
        def spread: map(select(. != null)) | if length == 0 then null else (max - min) end;
        def med(f): [.runs[] | f] | median;
        .medians = (.arms | map_values(.profiles | map_values({
            ns_per_wire_packet: med(.ns_per_wire_packet),
            ns_per_wire_packet_spread: ([.runs[].ns_per_wire_packet] | spread),
            xdp_ns_per_run: med(.xdp_ns_per_run),
            tc_chain_ns_per_skb: med(.tc_chain_ns_per_skb),
            wire_pps: med(.wire_pps),
            skbs_per_wire_packet: med(.skbs_per_wire_packet),
            cpu_busy_pct: med(.cpu_busy_pct),
            cpu_softirq_pct: med(.cpu_softirq_pct),
            tc_parses_per_skb: med(.tc_parses_per_skb),
            record_hit_rate: med(.record_hit_rate),
            tc_parses_per_skb_max: ([.runs[].tc_parses_per_skb] | map(select(. != null)) | max)
          })))
        | .medians["A-cb"] as $a | .medians["B-dynptr"] as $b
        | .interface.xdp_mode_timed as $mode
        | (.facts.vmxnet3 | to_entries | map(select(.key | test("^" + $mode + "-rxvlan-.*-untagged$")))
           | map(.value.record_rate)) as $vmx
        | ([.facts.veth["drv-untagged"].record_rate]) as $veth
        | ([.facts[][] | select(.attached and (.probe.ip // 0) > 0 and (.probe.skb_vlan > 0 or .probe.tc_inline_vlan > 0 or .xdp_saw_tag_inline > 0))]) as $tagged
        | .criteria = {
            not_slower: ([$a | keys[] as $p
                | if $a[$p].ns_per_wire_packet == null or $b[$p].ns_per_wire_packet == null then null
                  else $b[$p].ns_per_wire_packet <= $a[$p].ns_per_wire_packet + ($a[$p].ns_per_wire_packet_spread // 0) end]
                | if length == 0 or any(. == null) then null else all end),
            parse_once: ([$b[] | (.tc_parses_per_skb_max != null and .tc_parses_per_skb_max <= 1.0)
                          and ((.record_hit_rate // 0) < 0.99 or (.tc_parses_per_skb // 1) <= 0.01)] | all),
            record_reaches_tc: (($vmx + $veth) as $r
                | if ($r | length) == 0 or any($r[]; . == null) then null
                  else (all($r[]; . >= 0.99) and (($b["udp-64"].record_hit_rate // 0) >= 0.99)) end),
            vlan_accounted: (if ($tagged | length) == 0 then null
                             else all($tagged[]; .offsets_explained != false) end),
            vlan_needs_strip_shift: any($tagged[]; .needs_strip_shift)
          }
        | .decision = (
            if (.criteria | [.not_slower, .parse_once, .record_reaches_tc, .vlan_accounted] | all(. == true)) then
                (if .criteria.vlan_needs_strip_shift then
                    "adopt the record through bpf_dynptr_from_skb_meta, with tc subtracting VLAN_HLEN from its offsets when skb->vlan_present and the record saw the tag in line, and taking the VLAN id from skb->vlan_tci; egress keeps skb->cb"
                 else
                    "adopt the record through bpf_dynptr_from_skb_meta, read once by the first tc program and handed on in skb->cb; egress keeps skb->cb"
                 end)
            else
                "keep skb->cb: the first tc program parses and writes the control block, as today; failed: \([.criteria | to_entries[] | select(.key != "vlan_needs_strip_shift" and .value != true) | .key] | join(", "))"
            end)
    ' "$HANDOFF_REPORT" > "${HANDOFF_REPORT}.tmp" && mv "${HANDOFF_REPORT}.tmp" "$HANDOFF_REPORT"

    local arm
    for arm in A-cb B-dynptr B-dynptr-all B-datameta; do
        echo "== ${arm}" >&3
        jq -r --arg a "$arm" '
            (.medians[$a] // {}) | to_entries[]
            | "  \(.key): \(.value.ns_per_wire_packet // "-" | tostring) ns/wire pkt (spread \(.value.ns_per_wire_packet_spread // "-" | tostring)), xdp \(.value.xdp_ns_per_run // "-" | tostring) ns, tc chain \(.value.tc_chain_ns_per_skb // "-" | tostring) ns/skb, \(.value.wire_pps // "-" | tostring) pps, busy \(.value.cpu_busy_pct // "-" | tostring) %, tc parses/skb \(.value.tc_parses_per_skb // "-" | tostring), record hit \(.value.record_hit_rate // "-" | tostring)"
        ' "$HANDOFF_REPORT" >&3
    done
    echo "criteria: $(jq -c '.criteria' "$HANDOFF_REPORT")" >&3
    echo "decision: $(jq -r '.decision' "$HANDOFF_REPORT")" >&3
    cp "$HANDOFF_REPORT" "${HANDOFF_RESULTS_DIR}/report.json"
    echo "report: ${HANDOFF_RESULTS_DIR}/report.json" >&3
    jq -e '.decision | length > 0' "$HANDOFF_REPORT" >/dev/null
}
