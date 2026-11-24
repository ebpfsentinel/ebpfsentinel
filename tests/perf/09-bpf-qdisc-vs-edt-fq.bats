#!/usr/bin/env bats
# 09-bpf-qdisc-vs-edt-fq.bats - shaping a workload by its cgroup, three ways,
# on the same traffic, so that whether a BPF qdisc should replace the
# departure time tc-qos writes for fq is decided on figures.
#
# Arms, each run with the same agent and the same configuration (one rule per
# cgroup below), only the root qdisc of the agent VM's eth1 differing:
#   edt-fq      today: tc-qos stamps a departure time per cgroup and sch_fq
#               holds each packet until it.
#   edt-bpf-fq  tc-qos stamps the same way and the kernel's bpf_fq selftest,
#               a BPF qdisc registered under the name fq, holds the packets:
#               what the BPF qdisc framework costs against sch_fq when it does
#               the same job. Needs sch_fq unloaded, since two qdiscs cannot
#               share a name.
#   bpf-shaper  the agent's rules name the same cgroups, but the root is the
#               benchmark-only qdisc in fixtures/bpf-qdisc/bench-shaper.bpf.c,
#               which is not fq, so tc-qos stands aside and the qdisc holds
#               each cgroup to its rate by itself.
#
# Profiles, each run QDISC_BENCH_RUNS times for QDISC_BENCH_SECONDS, senders on
# the agent VM (iperf3 clients, each moved into its cgroup first) and
# receivers on this host (one iperf3 server per port):
#   unshaped-tcp8          8 TCP streams from no shaped cgroup: what every
#                          packet pays for the qdisc, and the ceiling
#   rate8m-tcp1            1 stream held to 8 Mbit/s, pinged from inside the
#                          cgroup and from outside it
#   rate100m-tcp8          8 streams held to 100 Mbit/s: accuracy and the
#                          fairness of the streams inside one cgroup, pinged
#                          from inside and outside
#   rate1g-tcp64           64 streams held to 1 Gbit/s: cost when shaping binds
#   pair-tcp4              two cgroups at 50 and 150 Mbit/s at once, 4 streams
#                          each: each held to its own rate beside the other
#   rate100m-udp-overload  UDP offered at 200 Mbit/s to a 100 Mbit/s cgroup: a
#                          sender that does not back off, and the horizon
#   pps-udp64              64-byte UDP datagrams as fast as 4 streams send
#                          them, through the 1 Gbit/s cgroup: cost per packet
#
# Read per run (fixtures/bpf-qdisc/run-profile.sh, over the steady part of the
# run): /proc/stat, the root qdisc's sent bytes, packets and drops, every BPF
# program's run time and count (kernel.bpf_stats_enabled), and iperf3's own
# report. The last test reduces the runs to medians per arm and profile and
# sets each BPF arm against edt-fq on the criteria the decision rests on. No
# figure is asserted here: a lane guest is not a production node, and the
# figures are read, then judged, from the report.
#
# Requires the 2VM lane (EBPF_2VM_MODE=true), iperf3 and jq here; iperf3,
# ping, tc, bpftool, clang and a kernel with CONFIG_NET_SCH_BPF on the agent
# VM. Outputs JSON to /tmp/ebpfsentinel-bpf-qdisc-vs-edt-fq.json.

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

QDISC_REPORT="/tmp/ebpfsentinel-bpf-qdisc-vs-edt-fq.json"
QDISC_BENCH_SECONDS="${QDISC_BENCH_SECONDS:-20}"
QDISC_BENCH_RUNS="${QDISC_BENCH_RUNS:-3}"
REMOTE_DIR="/tmp/ebpfsentinel-qdisc-bench"
HORIZON_MS=2000
IPERF_PORTS="5301 5302"

# cgroup (under /sys/fs/cgroup) and the rate its rule sets, in bits per second.
CLASSES="qb-8m:8000000 qb-100m:100000000 qb-1g:1000000000 qb-pair-a:50000000 qb-pair-b:150000000"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 09 sends from the agent VM to this host (2VM lane only)"
    fi
    require_tool iperf3
    require_tool jq
    require_tool tc
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    local tool
    for tool in iperf3 ping clang; do
        _agent_ssh_sudo which "$tool" &>/dev/null || soft_skip "${tool} not installed on agent VM"
    done
    [ "$QDISC_BENCH_SECONDS" -ge 6 ] || { echo "QDISC_BENCH_SECONDS must be at least 6" >&2; return 1; }

    export DATA_DIR="/tmp/ebpfsentinel-test-data-qdisc-$$"
    mkdir -p "$DATA_DIR"
    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset

    _agent_ssh rm -rf "$REMOTE_DIR"
    local file
    for file in build.sh bench-shaper.bpf.c run-profile.sh; do
        _agent_scp "${FIXTURE_DIR}/bpf-qdisc/${file}" "${REMOTE_DIR}/${file}" || {
            echo "cannot copy ${file} to the agent VM" >&2
            return 1
        }
    done
    local rc=0
    _agent_ssh bash "${REMOTE_DIR}/build.sh" "${REMOTE_DIR}/out" >"${DATA_DIR}/build.log" 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        soft_skip "BPF qdiscs not buildable on the agent VM: $(tail -1 "${DATA_DIR}/build.log")"
    elif [ "$rc" -ne 0 ]; then
        cat "${DATA_DIR}/build.log" >&2
        return 1
    fi

    local class
    for class in $CLASSES; do
        _agent_ssh_sudo mkdir -p "/sys/fs/cgroup/${class%%:*}"
    done

    local port
    for port in $IPERF_PORTS; do
        iperf3 -s -D -B "$EBPF_NS_IP" -p "$port" --pidfile "${DATA_DIR}/iperf3-${port}.pid"
    done
    sleep 1

    PREPARED_CONFIG="$(prepare_ebpf_config "$(_write_config)" "${DATA_DIR}/config-prepared.yaml")"
    export PREPARED_CONFIG

    jq -n --arg kernel "$(_agent_ssh uname -r)" --argjson cpus "$(_agent_ssh nproc)" \
        --argjson seconds "$QDISC_BENCH_SECONDS" --argjson runs "$QDISC_BENCH_RUNS" \
        --argjson classes "$(_classes_json)" \
        '{kernel: $kernel, cpus: $cpus, seconds: $seconds, runs_per_profile: $runs,
          classes: $classes, arms: {}}' > "$QDISC_REPORT"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
    local class port
    for class in $CLASSES; do
        _agent_ssh_sudo rmdir "/sys/fs/cgroup/${class%%:*}" 2>/dev/null || true
    done
    _agent_ssh rm -rf "$REMOTE_DIR" 2>/dev/null || true
    for port in $IPERF_PORTS; do
        [ -f "${DATA_DIR}/iperf3-${port}.pid" ] && kill "$(cat "${DATA_DIR}/iperf3-${port}.pid")" 2>/dev/null || true
    done
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-qdisc-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# Run a script as root on the agent VM, fed on stdin so it needs no quoting.
_remote() {
    printf '%s\n' "$1" | $AGENT_SSH_CMD -- sudo bash -s
}

# Put eth1 back to its default root and take every BPF qdisc this suite may
# have registered out of the kernel, so that no later suite asking for fq is
# given the BPF one. A struct_ops map is named after its C variable (fq in the
# selftest, bench_shaper here); a link bpftool may have pinned goes too.
_qdisc_reset() {
    _remote "
        tc qdisc del dev ${EBPF_AGENT_INTERFACE} root 2>/dev/null || true
        bpftool struct_ops unregister name fq 2>/dev/null || true
        bpftool struct_ops unregister name bench_shaper 2>/dev/null || true
        rm -f /sys/fs/bpf/fq /sys/fs/bpf/bench_shaper
    " 2>/dev/null || true
}

_classes_json() {
    local class out="{}"
    for class in $CLASSES; do
        out="$(jq -c --arg k "${class%%:*}" --argjson v "${class##*:}" '. + {($k): $v}' <<< "$out")"
    done
    echo "$out"
}

# The agent configuration: one cgroup_shaping rule per class, with the same
# horizon the bench shaper is given.
_write_config() {
    local cfg="${DATA_DIR}/config-qdisc.yaml" class
    cat > "$cfg" <<EOF
agent:
  interfaces:
    - __INTERFACE__
  bind_address: "0.0.0.0"
  allow_unauthenticated_api: true
  allow_plaintext_api: true
  log_level: info
  http_port: 8080
  grpc_port: 50051
  metrics_port: 9090

firewall:
  enabled: true
  default_policy: pass
  rules: []

ids:
  enabled: false

ips:
  enabled: false

dlp:
  enabled: false

ratelimit:
  enabled: false

threatintel:
  enabled: false

ddos:
  enabled: false

l7:
  enabled: false

alerting:
  enabled: false

audit:
  enabled: true
  storage_path: __DATA_DIR__/audit.redb

auth:
  enabled: false

qos:
  enabled: true
  cgroup_shaping:
EOF
    for class in $CLASSES; do
        cat >> "$cfg" <<EOF
    - id: ${class%%:*}
      workload:
        cgroup: /${class%%:*}
      rate: $((${class##*:} / 1000))kbps
      horizon_ms: ${HORIZON_MS}
EOF
    done
    echo "$cfg"
}

_start_agent() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded" >&2; return 1; }
    wait_for_ebpf_program "tc-qos" 30 || { echo "tc-qos did not load" >&2; return 1; }
}

# _le64 <n> - n as 8 bytes little-endian, the way bpftool takes `hex` input.
_le64() {
    printf '%016x' "$1" | sed 's/../& /g' | awk '{ for (i = 8; i >= 1; i--) printf "%s%s", $i, (i > 1 ? " " : "") }'
}

# Write one bench_classes entry per class: its cgroup id, then picoseconds per
# byte at its rate and the horizon in nanoseconds, the clock and counters zero.
_write_bench_classes() {
    local class name rate id script=""
    for class in $CLASSES; do
        name="${class%%:*}"
        rate="${class##*:}"
        id="$(_agent_ssh stat -c %i "/sys/fs/cgroup/${name}")"
        script+="bpftool map update name bench_classes key hex $(_le64 "$id") value hex $(_le64 $((8000000000000 / rate))) $(_le64 $((HORIZON_MS * 1000000))) $(_le64 0) $(_le64 0) $(_le64 0) $(_le64 0)
"
    done
    _remote "set -e
$script"
}

# What did the shaping itself count: the agent's report for the EDT arms, the
# bench shaper's map for its own arm.
_shaper_counters() {
    case "$1" in
        bpf-shaper) _remote "bpftool -j map dump name bench_classes" ;;
        *) api_get /api/v1/qos/shaping | jq -c '.cgroups // []' ;;
    esac
}

# Reduce one run-profile.sh object to the figures compared across arms.
_derive() {
    jq -c '
        def nums: split(" ") | map(select(length > 0) | tonumber);
        def root(q): (q | map(select(.root == true)) | first) // (q | first) // {};
        def jain: if length == 0 then null
                  else (add * add) / (length * (map(. * .) | add)) end;
        (.cpu_before | nums) as $b | (.cpu_after | nums) as $a
        | ([range(0; [$a, $b] | map(length) | min)] | map($a[.] - $b[.])) as $d
        | ($d[0:8] | add) as $total
        | ($total - $d[3] - $d[4]) as $busy
        | ($d[2] + $d[5] + $d[6]) as $kernel
        | (1e9 / .clk_tck) as $ns_per_tick
        | (.window_ns / 1e9) as $secs
        | root(.qdisc_before) as $qb | root(.qdisc_after) as $qa
        | (($qa.bytes // 0) - ($qb.bytes // 0)) as $bytes
        | (($qa.packets // 0) - ($qb.packets // 0)) as $packets
        | (.progs_before | map({key: (.id | tostring), value: .}) | from_entries) as $pb
        | {
            window_s: $secs,
            root_qdisc: ($qa.kind // null),
            wire_bps: ($bytes * 8 / $secs),
            pps: ($packets / $secs),
            qdisc_drops: (($qa.drops // 0) - ($qb.drops // 0)),
            cpu_busy_pct: (if $total > 0 then $busy * 100 / $total else null end),
            cpu_kernel_pct: (if $total > 0 then $kernel * 100 / $total else null end),
            kernel_ns_per_packet: (if $packets > 0 then $kernel * $ns_per_tick / $packets else null end),
            busy_ns_per_packet: (if $packets > 0 then $busy * $ns_per_tick / $packets else null end),
            bpf_programs: [
                .progs_after[]
                | select(.run_cnt != null)
                | . as $p
                | ($pb[($p.id | tostring)] // {run_cnt: 0, run_time_ns: 0}) as $q
                | {name: $p.name, type: $p.type,
                   runs: ($p.run_cnt - ($q.run_cnt // 0)),
                   ns: ($p.run_time_ns - ($q.run_time_ns // 0))}
                | select(.runs > 0)
                | . + {ns_per_run: (.ns / .runs)}
            ],
            flows: [
                .flows[]
                | (.spec | split(":")) as $s
                | {
                    cgroup: $s[0], streams: ($s[2] | tonumber), proto: $s[3],
                    error: (.iperf3.error // null),
                    goodput_bps: (.iperf3.end.sum_received.bits_per_second
                                  // .iperf3.end.sum.bits_per_second // null),
                    retransmits: (.iperf3.end.sum_sent.retransmits // null),
                    lost_pct: (.iperf3.end.sum.lost_percent // null),
                    jain: ([.iperf3.end.streams[]?
                            | (.receiver.bits_per_second // .udp.bits_per_second // empty)] | jain)
                  }
              ],
            pings: [.pings[] | {cgroup, loss_pct,
                                rtt_ms_p50: .rtt_ms_p50_p99_max[0],
                                rtt_ms_p99: .rtt_ms_p50_p99_max[1],
                                rtt_ms_max: .rtt_ms_p50_p99_max[2]}]
          }
    '
}

# _profile <arm> <name> <flow>... [-- <ping_cgroup>...]
_profile() {
    local arm="$1" name="$2" run raw derived counters
    shift 2
    for run in $(seq 1 "$QDISC_BENCH_RUNS"); do
        raw="$(_agent_ssh_sudo bash "${REMOTE_DIR}/run-profile.sh" "$EBPF_AGENT_INTERFACE" \
            "$EBPF_NS_IP" "$QDISC_BENCH_SECONDS" "$@")" || {
            echo "${arm}/${name} run ${run}: run-profile.sh failed" >&2
            return 1
        }
        derived="$(_derive <<< "$raw")" || {
            echo "${arm}/${name} run ${run}: unreadable output: ${raw:0:400}" >&2
            return 1
        }
        counters="$(_shaper_counters "$arm" 2>/dev/null)"
        [ -n "$counters" ] || counters="null"
        jq --arg arm "$arm" --arg name "$name" --argjson run "$derived" --argjson counters "$counters" \
            '.arms[$arm].profiles[$name].runs += [$run + {shaper_counters: $counters}]' \
            "$QDISC_REPORT" > "${QDISC_REPORT}.tmp" && mv "${QDISC_REPORT}.tmp" "$QDISC_REPORT"
        echo "${arm}/${name} run ${run}: $(jq -c '{wire_bps, pps, cpu_busy_pct, kernel_ns_per_packet, qdisc_drops,
            goodput: [.flows[] | {cgroup, goodput_bps, jain}], pings: [.pings[] | {cgroup, rtt_ms_p99}]}' <<< "$derived")" >&3
    done
}

_all_profiles() {
    local arm="$1"
    _profile "$arm" unshaped-tcp8 "-:5301:8:tcp:0:0" -- -
    _profile "$arm" rate8m-tcp1 "qb-8m:5301:1:tcp:0:0" -- qb-8m -
    _profile "$arm" rate100m-tcp8 "qb-100m:5301:8:tcp:0:0" -- qb-100m -
    _profile "$arm" rate1g-tcp64 "qb-1g:5301:64:tcp:0:0"
    _profile "$arm" pair-tcp4 "qb-pair-a:5301:4:tcp:0:0" "qb-pair-b:5302:4:tcp:0:0" -- -
    _profile "$arm" rate100m-udp-overload "qb-100m:5301:1:udp:1400:200M"
    _profile "$arm" pps-udp64 "qb-1g:5301:4:udp:64:0"
}

_arm_status() {
    jq --arg arm "$1" --arg status "$2" '.arms[$arm].status = $status' \
        "$QDISC_REPORT" > "${QDISC_REPORT}.tmp" && mv "${QDISC_REPORT}.tmp" "$QDISC_REPORT"
}

# The agent reads eth1's root qdisc and reports whether it stamps for it.
_agent_honours_eth1() {
    local body
    for _ in $(seq 1 15); do
        body="$(api_get /api/v1/qos/shaping)"
        [ "$(jq -r --arg i "$EBPF_AGENT_INTERFACE" \
            '[.interfaces[]? | select(.name == $i) | .honoured] | first // false' <<< "$body")" = "$1" ] && return 0
        sleep 1
    done
    echo "eth1 not reported with honoured=$1: $body" >&2
    return 1
}

# ── Tests ───────────────────────────────────────────────────────────

# First, while sch_fq can still be unloaded: once edt-fq has run it is in use.
@test "edt-bpf-fq: tc-qos departure times served by the kernel's bpf_fq registered as fq" {
    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
    local rc=0
    _remote "
        if lsmod | grep -q '^sch_fq '; then modprobe -r sch_fq || exit 3; fi
        grep -qx 'CONFIG_NET_SCH_FQ=y' /boot/config-\$(uname -r) && exit 3
        exit 0
    " || rc=$?
    if [ "$rc" -eq 3 ]; then
        _arm_status edt-bpf-fq "not run: sch_fq could not be taken out of the kernel"
        skip "sch_fq is built in or in use, so the BPF fq cannot take its name"
    fi
    _remote "bpftool -d struct_ops register ${REMOTE_DIR}/out/fq.bpf.o /sys/fs/bpf" >"${DATA_DIR}/register-fq.log" 2>&1 || {
        _arm_status edt-bpf-fq "not run: bpf_fq refused at registration"
        tail -60 "${DATA_DIR}/register-fq.log" >&2
        return 1
    }
    _remote "
        set -e
        tc qdisc replace dev ${EBPF_AGENT_INTERFACE} root handle 1: fq
        ! lsmod | grep -q '^sch_fq '
    " || { echo "eth1 root is not the BPF fq" >&2; return 1; }

    _start_agent
    _agent_honours_eth1 true
    _arm_status edt-bpf-fq "run"
    _all_profiles edt-bpf-fq

    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
}

@test "bpf-shaper: each cgroup held to its rate by a BPF qdisc, tc-qos standing aside" {
    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
    _remote "bpftool -d struct_ops register ${REMOTE_DIR}/out/bench-shaper.bpf.o /sys/fs/bpf" >"${DATA_DIR}/register-shaper.log" 2>&1 || {
        _arm_status bpf-shaper "not run: bench_shaper refused at registration"
        tail -60 "${DATA_DIR}/register-shaper.log" >&2
        return 1
    }
    _write_bench_classes
    _remote "tc qdisc replace dev ${EBPF_AGENT_INTERFACE} root handle 1: bench_shaper" || {
        echo "bench_shaper not installed as eth1 root" >&2
        return 1
    }

    _start_agent
    _agent_honours_eth1 false
    _arm_status bpf-shaper "run"
    _all_profiles bpf-shaper

    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
}

@test "edt-fq: tc-qos departure times served by sch_fq (today)" {
    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
    _remote "tc qdisc replace dev ${EBPF_AGENT_INTERFACE} root handle 1: fq"
    _start_agent
    _agent_honours_eth1 true
    _arm_status edt-fq "run"
    _all_profiles edt-fq

    stop_ebpf_agent 2>/dev/null || true
    _qdisc_reset
}

# Medians per arm and profile, then each BPF arm against edt-fq:
#   cost        kernel ns per packet at most 1.10 times edt-fq's on
#               unshaped-tcp8, rate1g-tcp64 and pps-udp64
#   ceiling     unshaped-tcp8 wire rate at least 0.95 times edt-fq's
#   accuracy    on every shaped TCP profile, each cgroup's goodput off its
#               rate by at most 2 points more than under edt-fq
#   fairness    Jain index of rate100m-tcp8's streams at least edt-fq's - 0.02
#   latency     p99 round trip of the ping outside the shaped cgroup, in
#               rate100m-tcp8, at most 1.25 times edt-fq's
#   overload    rate100m-udp-overload goodput off its rate by at most 2 points
#               more than under edt-fq
@test "report: medians per arm and each BPF arm set against edt-fq" {
    local arm
    jq -e '.arms["edt-fq"].profiles' "$QDISC_REPORT" >/dev/null || {
        echo "edt-fq has no figures, nothing to compare against" >&2
        return 1
    }
    jq '
        def median: map(select(. != null)) | sort
            | if length == 0 then null else .[(length - 1) / 2 | floor] end;
        def med(f): [.runs[] | f] | median;
        def err(rate): if . == null then null else ((. / rate) - 1) | fabs end;
        .classes as $classes
        | .medians = (.arms | map_values(
            (.profiles // {}) | map_values({
                wire_bps: med(.wire_bps),
                pps: med(.pps),
                cpu_busy_pct: med(.cpu_busy_pct),
                kernel_ns_per_packet: med(.kernel_ns_per_packet),
                qdisc_drops: med(.qdisc_drops),
                flows: (. as $prof | [.runs[].flows[].cgroup] | unique | map(. as $c
                    | [$prof.runs[].flows[] | select(.cgroup == $c)] as $f
                    | {key: $c, value: {
                        goodput_bps: ($f | map(.goodput_bps) | median),
                        rate_error: (if $classes[$c] then ($f | map(.goodput_bps) | median | err($classes[$c]))
                                     else null end),
                        jain: ($f | map(.jain) | median),
                        retransmits: ($f | map(.retransmits) | median)
                      }}) | from_entries),
                ping_p99_ms: (. as $prof | [.runs[].pings[]?.cgroup] | unique | map(. as $c
                    | {key: $c, value: ([$prof.runs[].pings[]? | select(.cgroup == $c) | .rtt_ms_p99] | median)})
                    | from_entries)
            })
          ))
        | .medians["edt-fq"] as $base
        | def le(a; b): if a == null or b == null then null else a <= b end;
          def worse_err(arm; p; c): le(arm[p].flows[c].rate_error; ($base[p].flows[c].rate_error // 0) + 0.02);
        .criteria = (.medians | to_entries | map(select(.key != "edt-fq")) | map(.key as $arm | .value as $m | {
            key: $arm,
            value: {
                cost: ([("unshaped-tcp8", "rate1g-tcp64", "pps-udp64") as $p
                        | le($m[$p].kernel_ns_per_packet; ($base[$p].kernel_ns_per_packet // 0) * 1.10)]
                       | if any(. == null) then null else all end),
                ceiling: (if $m["unshaped-tcp8"].wire_bps == null then null
                          else $m["unshaped-tcp8"].wire_bps >= ($base["unshaped-tcp8"].wire_bps // 0) * 0.95 end),
                accuracy: ([("rate8m-tcp1", "rate100m-tcp8", "rate1g-tcp64") as $p
                            | ($base[$p].flows // {} | keys[] | select($classes[.] != null)) as $c
                            | worse_err($m; $p; $c)]
                           + [("qb-pair-a", "qb-pair-b") as $c | worse_err($m; "pair-tcp4"; $c)]
                           | if any(. == null) then null else all end),
                fairness: (if $m["rate100m-tcp8"].flows["qb-100m"].jain == null then null
                           else $m["rate100m-tcp8"].flows["qb-100m"].jain
                                >= ($base["rate100m-tcp8"].flows["qb-100m"].jain // 0) - 0.02 end),
                latency: le($m["rate100m-tcp8"].ping_p99_ms["-"];
                            ($base["rate100m-tcp8"].ping_p99_ms["-"] // 0) * 1.25),
                overload: worse_err($m; "rate100m-udp-overload"; "qb-100m")
            }
        }) | from_entries)
    ' "$QDISC_REPORT" > "${QDISC_REPORT}.tmp" && mv "${QDISC_REPORT}.tmp" "$QDISC_REPORT"

    for arm in edt-fq edt-bpf-fq bpf-shaper; do
        echo "== ${arm}: $(jq -r --arg a "$arm" '.arms[$a].status // "absent"' "$QDISC_REPORT")" >&3
        jq -r --arg a "$arm" '
            (.medians[$a] // {}) | to_entries[]
            | "  \(.key): wire \(.value.wire_bps // "-" | tostring) bps, \(.value.pps // "-" | tostring) pps, busy \(.value.cpu_busy_pct // "-" | tostring) %, \(.value.kernel_ns_per_packet // "-" | tostring) kernel ns/pkt, drops \(.value.qdisc_drops // "-" | tostring), flows \(.value.flows | tojson), ping p99 \(.value.ping_p99_ms | tojson)"
        ' "$QDISC_REPORT" >&3
    done
    echo "criteria against edt-fq: $(jq -c '.criteria' "$QDISC_REPORT")" >&3
    jq -e '.medians["edt-fq"] | length > 0' "$QDISC_REPORT" >/dev/null
}
