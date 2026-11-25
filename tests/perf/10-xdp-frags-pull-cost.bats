#!/usr/bin/env bats
# 10-xdp-frags-pull-cost.bats - what declaring multi-buffer frames, and pulling
# a frame's head into its first buffer, cost xdp_firewall.
#
# Every XDP program loads declaring multi-buffer frames (BPF_F_XDP_HAS_FRAGS)
# where the kernel takes bpf_xdp_pull_data, and xdp-firewall and
# xdp-loadbalancer pull up to 256 bytes past the first buffer when a frame's
# headers do not fit in it (counted in the frags_pulled slot). Two questions,
# answered separately because one lane cannot answer both on the wire:
#
#   1. Does the declaration cost anything on frames that fit in one buffer,
#      and on jumbo frames whose headers sit in the first buffer? Answered on
#      the wire: pktgen floods the agent VM's eth1 from this VM, at 1500 and
#      at 9000 bytes, once with the current objects and once with the
#      baseline objects, in interleaved pairs (baseline then current, back to
#      back, as perf/07 does, so a slow minute costs both arms the same).
#   2. What does the pull itself cost? Not answerable on the wire here: a
#      vmxnet3 or veth frame keeps its headers in the first buffer, so the
#      pull never runs (frags_pulled stays at 0, which the wire runs record).
#      Answered with BPF_PROG_TEST_RUN on the live xdp_firewall, through
#      fixtures/xdp-frags/agent.py: one 9000-byte frame laid out whole (the
#      headers in the first buffer, no pull) against the same frame with a
#      PULL_LINEAR-byte first buffer (34 by default: the Ethernet and IPv4
#      headers in it, the UDP header past it, so the parse fails, the pull
#      runs, and frags_pulled must grow by one per run). The difference is
#      the pull as the program pays it: the failed parse, the pull and the
#      parse again. One run per call, since a repeated run reuses the buffer
#      the previous one pulled.
#
# Baseline. The objects of the commit before multi-buffer frames were
# declared (44d05584^), built with that tree's `cargo xtask ebpf-build` and
# signed with this tree's `cargo xtask ebpf-sign --dir`, since the warden
# refuses an unsigned load through the agent's token. Only the seven xdp-*
# objects are swapped: the suite copies /usr/local/lib/ebpfsentinel on the
# agent VM, lays the baseline xdp-* objects and their .loaders over the copy,
# and bind-mounts the copy over /usr/local/lib/ebpfsentinel for the baseline
# arm. Same agent binary, same kernel, same configuration, same tc and other
# programs: the one thing that differs is the XDP objects. Their only source
# difference from the current ones is the declaration, the pull and the
# frags_pulled slot (the commits since touched them only by rustfmt), so the
# baseline xdp_firewall publishes no frags_pulled line (it reads null).
#
# Limits of the baseline, stated so a figure is not read past them:
#   - A program that does not declare multi-buffer frames is refused in
#     driver mode at a 9000-byte MTU by drivers that hand XDP fragments (veth
#     does; vmxnet3 may). Where the baseline does not attach at 9000, or
#     attaches in another XDP mode than the current objects, the jumbo wire
#     criterion has no baseline and reads null: the report says why.
#   - BPF_PROG_TEST_RUN refuses a frame larger than one buffer to a program
#     without the declaration, so the baseline is timed on 1500 bytes only.
#   - The pull's cost is the current program against itself on two layouts
#     of one frame: that is the honest baseline for the pull, since no
#     earlier program could read such a frame at all.
#   - Only xdp_firewall is measured. xdp_loadbalancer calls the same helper
#     (ebpf-helpers xdp.rs) but needs a VIP configuration to run.
#
# Pass criteria (asserted by the last test; a criterion without both sides
# reads null and is reported, not asserted):
#   wire_1500_ns     median xdp_firewall ns per run (bpf_stats), current at
#                    most baseline x XDP_MAX_NS_RATIO + XDP_MAX_NS_ABS
#   wire_1500_pps    median packets per second through xdp_firewall, current
#                    at least baseline x XDP_MIN_PPS_RATIO
#   wire_jumbo_ns    as wire_1500_ns at JUMBO_MTU, where both attached in the
#                    same XDP mode
#   wire_jumbo_pps   as wire_1500_pps at JUMBO_MTU, same condition
#   testrun_1500_ns  median BPF_PROG_TEST_RUN ns on a 1500-byte frame, current
#                    at most baseline x XDP_MAX_NS_RATIO + XDP_MAX_NS_ABS
#   pull_fired       frags_pulled grew by at least the number of runs on the
#                    PULL_LINEAR-byte first buffer layout
#   pull_ns          median ns of the pulled layout minus the whole layout, at
#                    most XDP_PULL_MAX_NS
# The bounds are what a guest on a virtual NIC can hold run to run, not a
# target the product aims at.
#
# Requires the 2VM lane (EBPF_2VM_MODE=true): pktgen, jq and passwordless
# sudo here; python3, bpftool and the baseline objects in XDP_BASELINE_DIR on
# the agent VM (tests/perf/README.md says how to build them). A jumbo path
# both VMs' eth1 accept at JUMBO_MTU, else the jumbo test skips with the
# reason. Kernel >= 6.18. Writes /tmp/ebpfsentinel-xdp-frags-pull-cost.json
# and results/<date>-xdp-frags-pull-cost/ (report.json, raw/).

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'
load '../integration/lib/pktgen_helpers'

XDP_REPORT="/tmp/ebpfsentinel-xdp-frags-pull-cost.json"
XDP_BENCH_SECONDS="${XDP_BENCH_SECONDS:-20}"
XDP_BENCH_PAIRS="${XDP_BENCH_PAIRS:-3}"
XDP_TESTRUN_RUNS="${XDP_TESTRUN_RUNS:-2000}"
XDP_TESTRUN_WARMUP="${XDP_TESTRUN_WARMUP:-200}"
XDP_BASELINE_DIR="${XDP_BASELINE_DIR:-/var/tmp/ebpfsentinel-xdp-baseline}"
XDP_METRIC_SETTLE="${XDP_METRIC_SETTLE:-5}"
JUMBO_MTU="${JUMBO_MTU:-9000}"
# pktgen's pkt_size counts the Ethernet header: 1514 is a 1500-byte IP packet.
SMALL_PKT_SIZE="${SMALL_PKT_SIZE:-1514}"
JUMBO_PKT_SIZE="${JUMBO_PKT_SIZE:-$((JUMBO_MTU + 14))}"
# Ethernet (14) and IPv4 (20) in the first buffer, the UDP header past it.
PULL_LINEAR="${PULL_LINEAR:-34}"

XDP_MAX_NS_RATIO="${XDP_MAX_NS_RATIO:-1.05}"
XDP_MAX_NS_ABS="${XDP_MAX_NS_ABS:-5}"
XDP_MIN_PPS_RATIO="${XDP_MIN_PPS_RATIO:-0.95}"
XDP_PULL_MAX_NS="${XDP_PULL_MAX_NS:-500}"

REMOTE_DIR="/tmp/ebpfsentinel-xdp-frags-bench"
LIVE_DIR="/usr/local/lib/ebpfsentinel"
OVERLAY_DIR="/var/tmp/ebpfsentinel-xdp-frags-overlay"
XDP_OBJECTS="xdp-firewall xdp-firewall-reject xdp-ratelimit xdp-ratelimit-syncookie xdp-loadbalancer xdp-vip-announcer xdp-pass"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 10 floods the agent VM from this host with pktgen (2VM lane only)"
    fi
    require_kernel 6 18
    require_tool jq
    require_pktgen

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    local tool
    for tool in python3 bpftool mountpoint; do
        _agent_ssh_sudo which "$tool" &>/dev/null || soft_skip "${tool} not installed on agent VM"
    done

    export DATA_DIR="/tmp/ebpfsentinel-test-data-xdp-frags-$$"
    mkdir -p "$DATA_DIR"
    export RESULTS_DIR
    RESULTS_DIR="${PERF_RESULTS_DIR:-${BATS_TEST_DIRNAME}/results}/$(date +%F)-xdp-frags-pull-cost"
    mkdir -p "${RESULTS_DIR}/raw"

    stop_ebpf_agent 2>/dev/null || true
    _agent_ssh rm -rf "$REMOTE_DIR"
    _agent_scp "${FIXTURE_DIR}/xdp-frags/agent.py" "${REMOTE_DIR}/agent.py" || {
        echo "cannot copy agent.py to the agent VM" >&2
        return 1
    }

    local rc=0 missing
    missing="$(_remote "
        for o in ${XDP_OBJECTS}; do
            [ -s ${XDP_BASELINE_DIR}/\$o ] && [ -s ${XDP_BASELINE_DIR}/\$o.loaders ] || echo \$o
        done
    ")" || rc=$?
    if [ "$rc" -ne 0 ] || [ -n "$missing" ]; then
        soft_skip "baseline objects missing in ${XDP_BASELINE_DIR} on the agent VM (${missing//$'\n'/ }): build and sign them as tests/perf/README.md says"
    fi
    # Signed sidecars are only good against the keyring the warden reads.
    _remote "
        [ -e ${XDP_BASELINE_DIR}/loader-signing.der ] || exit 0
        cmp -s ${XDP_BASELINE_DIR}/loader-signing.der ${LIVE_DIR}/loader-signing.der
    " || {
        echo "the baseline objects were signed with another key than ${LIVE_DIR}/loader-signing.der" >&2
        return 1
    }
    _remote "mountpoint -q ${LIVE_DIR}" && {
        echo "${LIVE_DIR} is already a mount point on the agent VM; refusing to stack the baseline on it" >&2
        return 1
    }
    _remote "
        set -e
        rm -rf ${OVERLAY_DIR}
        cp -a ${LIVE_DIR} ${OVERLAY_DIR}
        for o in ${XDP_OBJECTS}; do
            cp ${XDP_BASELINE_DIR}/\$o ${XDP_BASELINE_DIR}/\$o.loaders ${OVERLAY_DIR}/
        done
        sysctl -n kernel.bpf_stats_enabled > ${REMOTE_DIR}/bpf_stats.before
        sysctl -qw kernel.bpf_stats_enabled=1
    "

    _agent_ssh cat "/sys/class/net/${EBPF_AGENT_INTERFACE}/mtu" > "${DATA_DIR}/agent-mtu.before"
    cat "/sys/class/net/${PKTGEN_IFACE}/mtu" > "${DATA_DIR}/local-mtu.before"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-perf-xdp-frags.yaml" "${DATA_DIR}/config-prepared.yaml")"
    export PREPARED_CONFIG

    local baseline_commit
    baseline_commit="$(_agent_ssh cat "${XDP_BASELINE_DIR}/COMMIT" 2>/dev/null | head -1)"
    jq -n --arg kernel "$(_agent_ssh uname -r)" --argjson cpus "$(_agent_ssh nproc)" \
        --arg driver "$(_agent_ssh "basename \$(readlink -f /sys/class/net/${EBPF_AGENT_INTERFACE}/device/driver)" 2>/dev/null)" \
        --arg baseline_dir "$XDP_BASELINE_DIR" --arg baseline_commit "${baseline_commit:-unrecorded}" \
        --argjson seconds "$XDP_BENCH_SECONDS" --argjson pairs "$XDP_BENCH_PAIRS" \
        --argjson jumbo "$JUMBO_MTU" --argjson runs "$XDP_TESTRUN_RUNS" \
        '{kernel: $kernel, cpus: $cpus, nic_driver: $driver, seconds: $seconds, pairs: $pairs,
          jumbo_mtu: $jumbo, testrun_runs: $runs,
          baseline: {dir: $baseline_dir, commit: $baseline_commit},
          status: {}, runs: [], testrun: {}}' > "$XDP_REPORT"
}

teardown_file() {
    pktgen_stop 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    _unbind 2>/dev/null || true
    _set_mtu_both "$(cat "${DATA_DIR}/agent-mtu.before" 2>/dev/null || echo 1500)" \
        "$(cat "${DATA_DIR}/local-mtu.before" 2>/dev/null || echo 1500)" 2>/dev/null || true
    _remote "
        [ -s ${REMOTE_DIR}/bpf_stats.before ] && sysctl -qw kernel.bpf_stats_enabled=\$(cat ${REMOTE_DIR}/bpf_stats.before)
        rm -rf ${OVERLAY_DIR} ${REMOTE_DIR}
    " 2>/dev/null || true
    [ -n "${RESULTS_DIR:-}" ] && [ -s "$XDP_REPORT" ] && cp "$XDP_REPORT" "${RESULTS_DIR}/report.json"
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-xdp-frags-$$}"
}

teardown() {
    pktgen_stop 2>/dev/null || true
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# Run a script as root on the agent VM, fed on stdin so it needs no quoting.
_remote() {
    printf '%s\n' "$1" | $AGENT_SSH_CMD -- sudo bash -s
}

_report() {
    local tmp
    tmp="$(jq "$@" "$XDP_REPORT")" && printf '%s\n' "$tmp" > "$XDP_REPORT"
}

_unbind() {
    _remote "
        [ -e ${REMOTE_DIR}/bound ] || exit 0
        umount ${LIVE_DIR} && rm -f ${REMOTE_DIR}/bound
    "
}

# _use_tree <current|baseline> - the agent stopped, and the objects under
# /usr/local/lib/ebpfsentinel the ones of that tree when it starts next.
_use_tree() {
    stop_ebpf_agent 2>/dev/null || true
    _unbind || { echo "cannot unmount the baseline from ${LIVE_DIR}" >&2; return 1; }
    [ "$1" = "baseline" ] || return 0
    _remote "mount --bind ${OVERLAY_DIR} ${LIVE_DIR} && touch ${REMOTE_DIR}/bound" || {
        echo "cannot bind the baseline over ${LIVE_DIR}" >&2
        return 1
    }
}

# _set_mtu_both <agent_mtu> <local_mtu> - with no program attached, since a
# driver checks the MTU against a program's declaration at attach time.
_set_mtu_both() {
    _remote "ip link set dev ${EBPF_AGENT_INTERFACE} mtu $1"
    sudo ip link set dev "$PKTGEN_IFACE" mtu "$2"
}

# _start <label> - start the agent, saving its log tail when the XDP
# programs did not attach.
_start() {
    if start_ebpf_agent "$PREPARED_CONFIG" && wait_for_ebpf_loaded 30 \
        && wait_for_ebpf_program "xdp-firewall" 30; then
        return 0
    fi
    _agent_ssh tail -60 "$_REMOTE_LOG_FILE" > "${RESULTS_DIR}/raw/agent-log-$1.txt" 2>/dev/null || true
    return 1
}

_snapshot() {
    _remote "python3 ${REMOTE_DIR}/agent.py snapshot ${EBPF_AGENT_INTERFACE}"
}

# The firewall's frags_pulled counter, or empty where the loaded objects have
# no such slot (the baseline).
_pulled() {
    ebpf_counter FIREWALL_METRICS frags_pulled
}

_delta_or_null() {
    if [ -n "$1" ] && [ -n "$2" ]; then echo $(($2 - $1)); else echo null; fi
}

# _wire_run <tree> <size_label> <pkt_size> <pair> - one pktgen flood and the
# difference of two snapshots around it, appended to the report.
_wire_run() {
    local tree="$1" size="$2" pkt="$3" pair="$4" before after pps p0 p1 row
    p0="$(_pulled)"
    before="$(_snapshot)" || { echo "snapshot before ${tree}/${size} failed" >&2; return 1; }
    pps="$(pktgen_run "$XDP_BENCH_SECONDS" "$pkt" 9)"
    after="$(_snapshot)" || { echo "snapshot after ${tree}/${size} failed" >&2; return 1; }
    sleep "$XDP_METRIC_SETTLE"
    p1="$(_pulled)"
    printf '%s\n%s\n' "$before" "$after" > "${RESULTS_DIR}/raw/wire-${size}-${tree}-${pair}.json"
    row="$(jq -n --argjson b "$before" --argjson a "$after" --arg tree "$tree" --arg size "$size" \
        --argjson pair "$pair" --argjson pps "${pps:-0}" --argjson pulled "$(_delta_or_null "$p0" "$p1")" '
        ($a.cpu | map(tonumber)) as $ac | ($b.cpu | map(tonumber)) as $bc
        | ([range(0; 8)] | map($ac[.] - $bc[.])) as $d
        | ($d | add) as $total
        | ($total - $d[3] - $d[4]) as $busy
        | ($d[2] + $d[5] + $d[6]) as $kern
        | (1e9 / $a.clk_tck) as $tick
        | (($a.ns - $b.ns) / 1e9) as $secs
        | ($a.rx_packets - $b.rx_packets) as $rx
        | ($b.progs | map({key: (.id | tostring), value: .}) | from_entries) as $pb
        | [$a.progs[] | select(.run_cnt != null) | . as $p
           | ($pb[($p.id | tostring)] // {run_cnt: 0, run_time_ns: 0}) as $q
           | {id: $p.id, name: $p.name, runs: ($p.run_cnt - ($q.run_cnt // 0)),
              ns: ($p.run_time_ns - ($q.run_time_ns // 0))}
           | select(.runs > 0) | . + {ns_per_run: (.ns / .runs)}] as $progs
        | ([$progs[] | select(.name == "xdp_firewall")]
           | {runs: (map(.runs) | add // 0), ns: (map(.ns) | add // 0)}) as $fw
        | {tree: $tree, size: $size, pair: $pair, window_s: $secs, link_mtu: $a.mtu,
           xdp_mode: ($a.xdp.mode // null),
           pktgen_pps: $pps, rx_pps: ($rx / $secs),
           fw_runs: $fw.runs,
           fw_ns_per_run: (if $fw.runs > 0 then $fw.ns / $fw.runs else null end),
           xdp_pps: ($fw.runs / $secs),
           cpu_busy_pct: (if $total > 0 then $busy * 100 / $total else null end),
           kernel_ns_per_packet: (if $rx > 0 then $kern * $tick / $rx else null end),
           frags_pulled: $pulled, programs: $progs}')" || {
        echo "${tree}/${size} pair ${pair}: unreadable snapshots" >&2
        return 1
    }
    _report --argjson row "$row" '.runs += [$row]'
    echo "${tree}/${size} pair ${pair}: $(jq -c '{xdp_mode, pktgen_pps, xdp_pps, fw_ns_per_run, kernel_ns_per_packet, cpu_busy_pct, frags_pulled}' <<< "$row")" >&3
}

# _testrun <tree> <shape> <frame_len> <linear_len> - BPF_PROG_TEST_RUN on the
# live xdp_firewall, with the frags_pulled growth over the runs.
_testrun() {
    local tree="$1" shape="$2" p0 p1 out
    p0="$(_pulled)"
    out="$(_remote "python3 ${REMOTE_DIR}/agent.py testrun xdp_firewall $3 $4 ${XDP_TESTRUN_RUNS} ${XDP_TESTRUN_WARMUP}")" || {
        echo "agent.py testrun ${tree}/${shape} failed: ${out}" >&2
        return 1
    }
    sleep "$XDP_METRIC_SETTLE"
    p1="$(_pulled)"
    _report --arg t "$tree" --arg s "$shape" --argjson o "$out" --argjson pulled "$(_delta_or_null "$p0" "$p1")" \
        '.testrun[$t][$s] = ($o + {frags_pulled: $pulled})'
    echo "testrun ${tree}/${shape}: $(jq -c '{ok, error, retvals, ns, runs_total}' <<< "$out") frags_pulled=$(_delta_or_null "$p0" "$p1")" >&3
}

_bpf_stats() {
    _remote "sysctl -qw kernel.bpf_stats_enabled=$1"
}

# ── Tests ───────────────────────────────────────────────────────────

@test "wire, 1500-byte packets: baseline and current objects in interleaved pairs" {
    _set_mtu_both 1500 1500
    local pair tree
    for pair in $(seq 1 "$XDP_BENCH_PAIRS"); do
        for tree in baseline current; do
            _use_tree "$tree"
            _start "1500-${tree}-${pair}" || {
                echo "the ${tree} objects did not attach at 1500 bytes: raw/agent-log-1500-${tree}-${pair}.txt" >&2
                return 1
            }
            _wire_run "$tree" 1500 "$SMALL_PKT_SIZE" "$pair"
        done
    done
    _use_tree current
}

@test "wire, jumbo packets: baseline and current objects in interleaved pairs" {
    _use_tree current
    _set_mtu_both "$JUMBO_MTU" "$JUMBO_MTU"
    if ! ping -M do -s $((JUMBO_MTU - 28)) -c 2 -W 2 -I "$PKTGEN_IFACE" "$AGENT_VM_IP" >/dev/null 2>&1; then
        _report --arg r "the path between the VMs refuses ${JUMBO_MTU}-byte frames" '.status.jumbo = $r'
        _set_mtu_both 1500 1500
        env_skip "the path between the VMs refuses ${JUMBO_MTU}-byte frames"
    fi
    local pair tree baseline_ok=true
    for pair in $(seq 1 "$XDP_BENCH_PAIRS"); do
        for tree in baseline current; do
            if [ "$tree" = "baseline" ] && [ "$baseline_ok" != "true" ]; then
                continue
            fi
            _use_tree "$tree"
            if ! _start "jumbo-${tree}-${pair}"; then
                if [ "$tree" = "baseline" ]; then
                    # A program without the declaration refused at this MTU is
                    # a result, not a fault: the baseline has no jumbo figure.
                    baseline_ok=false
                    _report --arg r "baseline objects did not attach at ${JUMBO_MTU} bytes (raw/agent-log-jumbo-baseline-${pair}.txt)" \
                        '.status.jumbo_baseline = $r'
                    echo "baseline did not attach at ${JUMBO_MTU}: no jumbo baseline" >&3
                    continue
                fi
                echo "the current objects did not attach at ${JUMBO_MTU} bytes: raw/agent-log-jumbo-current-${pair}.txt" >&2
                return 1
            fi
            _wire_run "$tree" jumbo "$JUMBO_PKT_SIZE" "$pair"
        done
    done
    _use_tree current
    _set_mtu_both 1500 1500
}

@test "test run: current xdp_firewall on a 1500-byte frame, a jumbo frame whole, and a jumbo frame with a ${PULL_LINEAR}-byte first buffer" {
    _use_tree current
    _start "testrun-current" || { echo "the current objects did not attach" >&2; return 1; }
    # bpf_stats adds its own accounting to every run; the test runs are timed
    # without it, the same way for both trees.
    _bpf_stats 0
    _testrun current single 1514 0
    _testrun current jumbo_whole "$JUMBO_PKT_SIZE" 0
    _testrun current jumbo_pulled "$JUMBO_PKT_SIZE" "$PULL_LINEAR"
    _bpf_stats 1
    jq -e '.testrun.current.single.ok and .testrun.current.jumbo_whole.ok' "$XDP_REPORT" >/dev/null || {
        echo "the current xdp_firewall refused a test run: $(jq -c '.testrun.current' "$XDP_REPORT")" >&2
        return 1
    }
    if ! jq -e '.testrun.current.jumbo_pulled.ok' "$XDP_REPORT" >/dev/null; then
        # Older kernels take data_end only equal to the frame length.
        env_skip "the kernel refuses a ${PULL_LINEAR}-byte first buffer in BPF_PROG_TEST_RUN: $(jq -r '.testrun.current.jumbo_pulled.error' "$XDP_REPORT")"
    fi
}

@test "test run: baseline xdp_firewall on the same frames" {
    _use_tree baseline
    _start "testrun-baseline" || { echo "the baseline objects did not attach" >&2; return 1; }
    _bpf_stats 0
    _testrun baseline single 1514 0
    # Expected refused: a frame past one buffer needs the declaration. Kept
    # in the report as the evidence.
    _testrun baseline jumbo_whole "$JUMBO_PKT_SIZE" 0
    _bpf_stats 1
    _use_tree current
    jq -e '.testrun.baseline.single.ok' "$XDP_REPORT" >/dev/null || {
        echo "the baseline xdp_firewall refused a 1500-byte test run: $(jq -c '.testrun.baseline.single' "$XDP_REPORT")" >&2
        return 1
    }
}

@test "report: medians per tree and the criteria" {
    _report --argjson ratio "$XDP_MAX_NS_RATIO" --argjson abs "$XDP_MAX_NS_ABS" \
        --argjson ppsr "$XDP_MIN_PPS_RATIO" --argjson pullmax "$XDP_PULL_MAX_NS" '
        def median: map(select(. != null)) | sort
            | if length == 0 then null else .[(length - 1) / 2 | floor] end;
        def le(a; b): if a == null or b == null then null else a <= b end;
        def ge(a; b): if a == null or b == null then null else a >= b end;
        def bound(x): if x == null then null else x * $ratio + $abs end;
        . as $r
        | def side(t; s): [$r.runs[] | select(.tree == t and .size == s)] as $rows
            | if ($rows | length) == 0 then null else {
                runs: ($rows | length),
                xdp_modes: ($rows | map(.xdp_mode) | unique),
                fw_ns_per_run: ($rows | map(.fw_ns_per_run) | median),
                xdp_pps: ($rows | map(.xdp_pps) | median),
                pktgen_pps: ($rows | map(.pktgen_pps) | median),
                kernel_ns_per_packet: ($rows | map(.kernel_ns_per_packet) | median),
                cpu_busy_pct: ($rows | map(.cpu_busy_pct) | median),
                frags_pulled: ($rows | map(.frags_pulled) | median)
              } end;
          def same_mode(s): side("baseline"; s) != null and side("current"; s) != null
            and side("baseline"; s).xdp_modes == side("current"; s).xdp_modes
            and (side("current"; s).xdp_modes | length) == 1;
        .medians = {
            wire: {"1500": {baseline: side("baseline"; "1500"), current: side("current"; "1500")},
                   jumbo: {baseline: side("baseline"; "jumbo"), current: side("current"; "jumbo")}},
            pull_added_ns: (if (.testrun.current.jumbo_pulled.ok // false) and (.testrun.current.jumbo_whole.ok // false)
                            then .testrun.current.jumbo_pulled.ns.median - .testrun.current.jumbo_whole.ns.median
                            else null end)
          }
        | .medians.wire as $w
        | .criteria = {
            wire_1500_ns: le($w["1500"].current.fw_ns_per_run; bound($w["1500"].baseline.fw_ns_per_run)),
            wire_1500_pps: ge($w["1500"].current.xdp_pps; ($w["1500"].baseline.xdp_pps // null) | if . == null then null else . * $ppsr end),
            wire_jumbo_ns: (if same_mode("jumbo")
                            then le($w.jumbo.current.fw_ns_per_run; bound($w.jumbo.baseline.fw_ns_per_run))
                            else null end),
            wire_jumbo_pps: (if same_mode("jumbo")
                             then ge($w.jumbo.current.xdp_pps; $w.jumbo.baseline.xdp_pps * $ppsr)
                             else null end),
            testrun_1500_ns: le(.testrun.current.single.ns.median; bound(.testrun.baseline.single.ns.median)),
            pull_fired: (if (.testrun.current.jumbo_pulled.ok // false)
                         then ge(.testrun.current.jumbo_pulled.frags_pulled; .testrun.current.jumbo_pulled.runs_total)
                         else null end),
            pull_ns: le(.medians.pull_added_ns; $pullmax)
          }
        | .thresholds = {max_ns_ratio: $ratio, max_ns_abs: $abs, min_pps_ratio: $ppsr, pull_max_ns: $pullmax}
    '
    cp "$XDP_REPORT" "${RESULTS_DIR}/report.json"
    echo "medians: $(jq -c '.medians' "$XDP_REPORT")" >&3
    echo "status: $(jq -c '.status' "$XDP_REPORT")" >&3
    echo "criteria: $(jq -c '.criteria' "$XDP_REPORT")" >&3
    echo "written to ${RESULTS_DIR}" >&3
    jq -e '.medians.wire["1500"].current != null and .medians.wire["1500"].baseline != null' "$XDP_REPORT" >/dev/null || {
        echo "no 1500-byte pair was measured" >&2
        return 1
    }
    jq -e '[.criteria[] | select(. == false)] | length == 0' "$XDP_REPORT" >/dev/null || {
        echo "criteria not met: $(jq -c '.criteria | with_entries(select(.value == false))' "$XDP_REPORT")" >&2
        return 1
    }
}
