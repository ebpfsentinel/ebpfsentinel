#!/usr/bin/env bats
# 12-tcp-tx-timestamp-cost.bats - what timing writes from the kernel's
# transmit timestamps costs a TCP sender, per write.
#
# With tcp_health.send_latency on, the TCP health counter attaches a sock_ops
# program (tcp_health_send_timestamps) to the attribution cgroup root, the
# whole host by default. It opts every established connection in to the
# timestamp callbacks, runs on each sendmsg to tag a write when the socket
# has none in flight, and again at each stage of the tagged write. That is
# work on the sender's own path, per write, which no packet-path suite sees.
# This suite runs one iperf3 sender on the agent VM, where the program
# attaches, to an iperf3 server on this VM, in three arms:
#
#   none   tcp_health disabled: no TCP health program at all
#   off    tcp_health on, send_latency off: the tracepoints, no sock_ops
#   on     tcp_health on, send_latency on: the tracepoints and the sock_ops
#
# and two write profiles:
#
#   small  TS_SMALL_LEN-byte writes (64) with TCP_NODELAY, so every write is
#          a segment and a sendmsg the callback runs on: the worst case
#   bulk   TS_BULK_LEN-byte writes (128 KiB), iperf3's default shape
#
# A round runs the three arms back to back (the agent restarted with the
# arm's configuration), each arm both profiles; TS_BENCH_RUNS rounds, and the
# figures are medians over rounds, so a slow minute costs every arm alike.
# Same agent binary, same objects, same kernel in every arm: the arms differ
# only in the two configuration keys. on against off is the cost of the
# timestamps; off against none is the tracepoints' share, reported so the
# first is not mistaken for the whole of tcp_health.
#
# Per run: iperf3's sent throughput and bytes, the writes (bytes over the
# write length), the sender's CPU from the rusage wait4 returns for it (the
# time its sendmsg calls spent in the kernel, the sock_ops callbacks
# included) per write and per byte, the host's busy CPU per write from
# /proc/stat, retransmits, and the sock_ops program's runs and ns per run
# from bpf_stats, with its runs per write.
#
# Pass criteria (asserted by the last test, on the medians):
#   small_tput_on_off     on throughput at least off x TS_SMALL_MIN_TPUT_RATIO
#   small_cpu_on_off      on sender ns per write at most off x TS_SMALL_MAX_CPU_RATIO
#   bulk_tput_on_off      on throughput at least off x TS_BULK_MIN_TPUT_RATIO
#   bulk_cpu_on_off       on sender ns per byte at most off x TS_BULK_MAX_CPU_RATIO
#   small_tput_off_none, small_cpu_off_none, bulk_tput_off_none,
#   bulk_cpu_off_none     the same four bounds, off against none
#   on_timed              every on run grew the client send latency count and
#                         ran the sock_ops program
#   off_untimed           no off or none run ran the sock_ops program
# The bounds are what a guest sender holds run to run (iperf3 over a virtual
# NIC moves by a few percent between identical runs), not a target.
#
# Limits: bpf_stats is on in every arm so the sock_ops runs can be counted;
# it adds two clock reads to every program run, which the on arm pays per
# write and the others do not, so the on arm's CPU is overstated by that
# amount, never understated. The sender is iperf3 in a loop of writes, not an
# application doing work between them, so the per-write cost is the most it
# can weigh relative to the rest. One connection: a host with many sockets
# pays the same per write, and the timestamp table bounds what is in flight.
#
# Requires the 2VM lane (EBPF_2VM_MODE=true): iperf3 and jq here; iperf3,
# python3 and bpftool on the agent VM. Kernel >= 6.18. Writes
# /tmp/ebpfsentinel-tcp-tx-timestamp-cost.json and
# results/<date>-tcp-tx-timestamp-cost/ (report.json, raw/).

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

TS_REPORT="/tmp/ebpfsentinel-tcp-tx-timestamp-cost.json"
TS_BENCH_SECONDS="${TS_BENCH_SECONDS:-15}"
TS_BENCH_RUNS="${TS_BENCH_RUNS:-5}"
TS_SMALL_LEN="${TS_SMALL_LEN:-64}"
TS_BULK_LEN="${TS_BULK_LEN:-131072}"
TS_PORT="${TS_PORT:-5412}"
# auto pins the sender to the agent VM's last CPU when it has two or more;
# empty leaves it to the scheduler.
TS_SENDER_CPU="${TS_SENDER_CPU-auto}"

TS_SMALL_MIN_TPUT_RATIO="${TS_SMALL_MIN_TPUT_RATIO:-0.95}"
TS_SMALL_MAX_CPU_RATIO="${TS_SMALL_MAX_CPU_RATIO:-1.10}"
TS_BULK_MIN_TPUT_RATIO="${TS_BULK_MIN_TPUT_RATIO:-0.98}"
TS_BULK_MAX_CPU_RATIO="${TS_BULK_MAX_CPU_RATIO:-1.05}"

REMOTE_DIR="/tmp/ebpfsentinel-tx-ts-bench"
ARMS="none off on"
PROFILES="small bulk"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 12 sends from the agent VM to this host (2VM lane only)"
    fi
    require_kernel 6 18
    require_tool iperf3
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    local tool
    for tool in iperf3 python3 bpftool; do
        _agent_ssh_sudo which "$tool" &>/dev/null || soft_skip "${tool} not installed on agent VM"
    done

    export DATA_DIR="/tmp/ebpfsentinel-test-data-tx-ts-$$"
    mkdir -p "$DATA_DIR"
    export RESULTS_DIR
    RESULTS_DIR="${PERF_RESULTS_DIR:-${BATS_TEST_DIRNAME}/results}/$(date +%F)-tcp-tx-timestamp-cost"
    mkdir -p "${RESULTS_DIR}/raw"

    stop_ebpf_agent 2>/dev/null || true
    _agent_ssh rm -rf "$REMOTE_DIR"
    _agent_scp "${FIXTURE_DIR}/tx-timestamps/run-sender.py" "${REMOTE_DIR}/run-sender.py" || {
        echo "cannot copy run-sender.py to the agent VM" >&2
        return 1
    }
    _remote "
        sysctl -n kernel.bpf_stats_enabled > ${REMOTE_DIR}/bpf_stats.before
        sysctl -qw kernel.bpf_stats_enabled=1
    "

    local cpus
    cpus="$(_agent_ssh nproc)"
    if [ "$TS_SENDER_CPU" = "auto" ]; then
        if [ "$cpus" -ge 2 ]; then TS_SENDER_CPU=$((cpus - 1)); else TS_SENDER_CPU=""; fi
    fi
    export TS_SENDER_CPU

    iperf3 -s -D -B "$EBPF_NS_IP" -p "$TS_PORT" --pidfile "${DATA_DIR}/iperf3.pid"
    sleep 1

    local arm
    for arm in $ARMS; do
        prepare_ebpf_config "$(_write_config "$arm")" "${DATA_DIR}/config-${arm}-prepared.yaml" >/dev/null
    done

    jq -n --arg kernel "$(_agent_ssh uname -r)" --argjson cpus "$cpus" \
        --argjson seconds "$TS_BENCH_SECONDS" --argjson rounds "$TS_BENCH_RUNS" \
        --argjson small "$TS_SMALL_LEN" --argjson bulk "$TS_BULK_LEN" --arg pin "$TS_SENDER_CPU" \
        '{kernel: $kernel, cpus: $cpus, seconds: $seconds, rounds: $rounds,
          write_len: {small: $small, bulk: $bulk},
          sender_cpu: (if $pin == "" then null else $pin end),
          capability: {}, runs: []}' > "$TS_REPORT"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _remote "
        [ -s ${REMOTE_DIR}/bpf_stats.before ] && sysctl -qw kernel.bpf_stats_enabled=\$(cat ${REMOTE_DIR}/bpf_stats.before)
        rm -rf ${REMOTE_DIR}
    " 2>/dev/null || true
    [ -f "${DATA_DIR}/iperf3.pid" ] && kill "$(cat "${DATA_DIR}/iperf3.pid")" 2>/dev/null || true
    [ -n "${RESULTS_DIR:-}" ] && [ -s "$TS_REPORT" ] && cp "$TS_REPORT" "${RESULTS_DIR}/report.json"
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-tx-ts-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# Run a script as root on the agent VM, fed on stdin so it needs no quoting.
_remote() {
    printf '%s\n' "$1" | $AGENT_SSH_CMD -- sudo bash -s
}

_report() {
    local tmp
    tmp="$(jq "$@" "$TS_REPORT")" && printf '%s\n' "$tmp" > "$TS_REPORT"
}

# _write_config <arm> - the agent configuration of one arm. Only the
# tcp_health block differs between arms.
_write_config() {
    local arm="$1" cfg="${DATA_DIR}/config-${1}.yaml" block
    case "$arm" in
        none) block="tcp_health:
  enabled: false" ;;
        off) block="tcp_health:
  enabled: true
  send_latency: false" ;;
        on) block="tcp_health:
  enabled: true
  send_latency: true" ;;
    esac
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

${block}

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
EOF
    echo "$cfg"
}

_start_arm() {
    local arm="$1"
    start_ebpf_agent "${DATA_DIR}/config-${arm}-prepared.yaml"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded (${arm})" >&2; return 1; }
    if [ "$arm" != "none" ]; then
        wait_for_ebpf_program "tracepoint-tcp-health" 30 || {
            echo "the TCP health counter did not attach (${arm})" >&2
            return 1
        }
    fi
}

# _send_count - the client writes timed so far, summed over every edge and
# stage; 0 when the family has no series.
_send_count() {
    scrape_metrics 2>/dev/null \
        | grep '^ebpfsentinel_tcp_send_latency_seconds_count{' | grep 'role="client"' \
        | awk '{ s += $2 } END { printf "%d\n", s + 0 }'
}

_capability() {
    api_get /api/v1/ebpf/kernel-features 2>/dev/null \
        | jq -c '.capabilities[]? | select(.id == "tcp_send_timestamps")'
}

# _send <arm> <profile> <round> - one sender run, reduced and appended to the
# report, its raw output kept.
_send() {
    local arm="$1" profile="$2" round="$3" len nodelay raw c0=0 c1=0 row
    if [ "$profile" = "small" ]; then len="$TS_SMALL_LEN"; nodelay=1; else len="$TS_BULK_LEN"; nodelay=0; fi
    raw="${RESULTS_DIR}/raw/${arm}-${profile}-${round}.json"
    [ "$arm" = "on" ] && c0="$(_send_count)"
    _remote "python3 ${REMOTE_DIR}/run-sender.py ${EBPF_NS_IP} ${TS_PORT} ${TS_BENCH_SECONDS} ${len} ${nodelay} ${TS_SENDER_CPU}" > "$raw" || {
        echo "run-sender.py failed for ${arm}/${profile}" >&2
        return 1
    }
    local timed=null
    if [ "$arm" = "on" ]; then
        # The agent publishes the histogram on its poll; wait one past the run.
        sleep "${TS_METRIC_SETTLE:-11}"
        c1="$(_send_count)"
        timed=$((c1 - c0))
    fi
    row="$(jq -c --arg arm "$arm" --arg profile "$profile" --argjson round "$round" \
        --argjson timed "$timed" '
        def nums: map(tonumber);
        (.cpu_before | nums) as $b | (.cpu_after | nums) as $a
        | ([range(0; 8)] | map($a[.] - $b[.])) as $d
        | ($d | add) as $total
        | ($total - $d[3] - $d[4]) as $busy
        | (1e9 / .clk_tck) as $tick
        | (.iperf3.end.sum_sent.bytes // 0) as $bytes
        | (if .write_len > 0 then $bytes / .write_len else 0 end) as $writes
        | (.sender_user_ns + .sender_sys_ns) as $sender
        | (.progs_before | map({key: (.id | tostring), value: .}) | from_entries) as $pb
        | [.progs_after[] | select(.run_cnt != null) | . as $p
           | ($pb[($p.id | tostring)] // {run_cnt: 0, run_time_ns: 0}) as $q
           | {name: $p.name, type: $p.type, runs: ($p.run_cnt - ($q.run_cnt // 0)),
              ns: ($p.run_time_ns - ($q.run_time_ns // 0))}
           | select(.runs > 0) | . + {ns_per_run: (.ns / .runs)}] as $progs
        | ([$progs[] | select(.type == "sock_ops" and (.name | startswith("tcp_health_send")))]
           | {runs: (map(.runs) | add // 0), ns: (map(.ns) | add // 0)}) as $so
        | {arm: $arm, profile: $profile, round: $round,
           error: (.iperf3.error // null), exit: .exit,
           window_s: (.window_ns / 1e9),
           throughput_bps: (.iperf3.end.sum_sent.bits_per_second // null),
           bytes: $bytes, writes: $writes,
           retransmits: (.iperf3.end.sum_sent.retransmits // null),
           sender_cpu_pct: (if .window_ns > 0 then $sender * 100 / .window_ns else null end),
           sender_ns_per_write: (if $writes > 0 then $sender / $writes else null end),
           sender_ns_per_byte: (if $bytes > 0 then $sender / $bytes else null end),
           host_busy_pct: (if $total > 0 then $busy * 100 / $total else null end),
           host_busy_ns_per_write: (if $writes > 0 then $busy * $tick / $writes else null end),
           sock_ops_runs: $so.runs,
           sock_ops_ns_per_run: (if $so.runs > 0 then $so.ns / $so.runs else null end),
           sock_ops_runs_per_write: (if $writes > 0 then $so.runs / $writes else null end),
           sock_ops_ns_per_write: (if $writes > 0 then $so.ns / $writes else null end),
           send_latency_timed: $timed,
           programs: $progs}' "$raw")" || {
        echo "${arm}/${profile} round ${round}: unreadable output, see ${raw}" >&2
        return 1
    }
    _report --argjson row "$row" '.runs += [$row]'
    echo "${arm}/${profile} round ${round}: $(jq -c '{error, throughput_bps, writes, sender_ns_per_write, sender_ns_per_byte, sock_ops_runs_per_write, sock_ops_ns_per_run, send_latency_timed}' <<< "$row")" >&3
    jq -e '.error == null and .exit == 0' <<< "$row" >/dev/null || {
        echo "iperf3 failed for ${arm}/${profile}: $(jq -r '.error' <<< "$row")" >&2
        return 1
    }
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the capability report follows send_latency (off, then on)" {
    local arm entry
    for arm in off on; do
        _start_arm "$arm"
        entry="$(_capability)"
        _report --arg arm "$arm" --arg e "${entry:-null}" '.capability[$arm] = ($e | fromjson? // null)'
        echo "${arm}: ${entry}" >&3
        [ -n "$entry" ] || { echo "tcp_send_timestamps missing from the report" >&2; return 1; }
        if [ "$arm" = "on" ]; then
            jq -e '.active == true' <<< "$entry" >/dev/null || {
                echo "send_latency on but the timing of writes is not active: ${entry}" >&2
                return 1
            }
        else
            jq -e '.active == false' <<< "$entry" >/dev/null || {
                echo "send_latency off but the timing of writes is active: ${entry}" >&2
                return 1
            }
        fi
    done
    stop_ebpf_agent 2>/dev/null || true
}

@test "rounds: none, off and on, small and bulk writes" {
    local round arm profile
    for round in $(seq 1 "$TS_BENCH_RUNS"); do
        for arm in $ARMS; do
            _start_arm "$arm"
            for profile in $PROFILES; do
                _send "$arm" "$profile" "$round"
            done
        done
    done
    stop_ebpf_agent 2>/dev/null || true
}

@test "report: medians per arm and profile, and the criteria" {
    _report --argjson st "$TS_SMALL_MIN_TPUT_RATIO" --argjson sc "$TS_SMALL_MAX_CPU_RATIO" \
        --argjson bt "$TS_BULK_MIN_TPUT_RATIO" --argjson bc "$TS_BULK_MAX_CPU_RATIO" '
        def median: map(select(. != null)) | sort
            | if length == 0 then null else .[(length - 1) / 2 | floor] end;
        def ge(a; b): if a == null or b == null then null else a >= b end;
        def le(a; b): if a == null or b == null then null else a <= b end;
        def times(x; k): if x == null then null else x * k end;
        . as $r
        | def m(arm; profile; field): [$r.runs[] | select(.arm == arm and .profile == profile) | .[field]] | median;
          def side(arm; profile): {
              runs: ([$r.runs[] | select(.arm == arm and .profile == profile)] | length),
              throughput_bps: m(arm; profile; "throughput_bps"),
              writes: m(arm; profile; "writes"),
              retransmits: m(arm; profile; "retransmits"),
              sender_cpu_pct: m(arm; profile; "sender_cpu_pct"),
              sender_ns_per_write: m(arm; profile; "sender_ns_per_write"),
              sender_ns_per_byte: m(arm; profile; "sender_ns_per_byte"),
              host_busy_ns_per_write: m(arm; profile; "host_busy_ns_per_write"),
              sock_ops_ns_per_run: m(arm; profile; "sock_ops_ns_per_run"),
              sock_ops_runs_per_write: m(arm; profile; "sock_ops_runs_per_write"),
              sock_ops_ns_per_write: m(arm; profile; "sock_ops_ns_per_write")
            };
        .medians = {small: {none: side("none"; "small"), off: side("off"; "small"), on: side("on"; "small")},
                    bulk: {none: side("none"; "bulk"), off: side("off"; "bulk"), on: side("on"; "bulk")}}
        | .medians as $m
        | .criteria = {
            small_tput_on_off: ge($m.small.on.throughput_bps; times($m.small.off.throughput_bps; $st)),
            small_cpu_on_off: le($m.small.on.sender_ns_per_write; times($m.small.off.sender_ns_per_write; $sc)),
            bulk_tput_on_off: ge($m.bulk.on.throughput_bps; times($m.bulk.off.throughput_bps; $bt)),
            bulk_cpu_on_off: le($m.bulk.on.sender_ns_per_byte; times($m.bulk.off.sender_ns_per_byte; $bc)),
            small_tput_off_none: ge($m.small.off.throughput_bps; times($m.small.none.throughput_bps; $st)),
            small_cpu_off_none: le($m.small.off.sender_ns_per_write; times($m.small.none.sender_ns_per_write; $sc)),
            bulk_tput_off_none: ge($m.bulk.off.throughput_bps; times($m.bulk.none.throughput_bps; $bt)),
            bulk_cpu_off_none: le($m.bulk.off.sender_ns_per_byte; times($m.bulk.none.sender_ns_per_byte; $bc)),
            on_timed: ([.runs[] | select(.arm == "on")] as $on
                       | if ($on | length) == 0 then null
                         else ($on | all(.send_latency_timed > 0 and .sock_ops_runs > 0)) end),
            off_untimed: ([.runs[] | select(.arm != "on")] as $rest
                          | if ($rest | length) == 0 then null
                            else ($rest | all(.sock_ops_runs == 0)) end)
          }
        | .thresholds = {small_min_tput_ratio: $st, small_max_cpu_ratio: $sc,
                         bulk_min_tput_ratio: $bt, bulk_max_cpu_ratio: $bc}
    '
    cp "$TS_REPORT" "${RESULTS_DIR}/report.json"
    echo "small: $(jq -c '.medians.small' "$TS_REPORT")" >&3
    echo "bulk: $(jq -c '.medians.bulk' "$TS_REPORT")" >&3
    echo "criteria: $(jq -c '.criteria' "$TS_REPORT")" >&3
    echo "written to ${RESULTS_DIR}" >&3
    jq -e '[.criteria[] | select(. == null)] | length == 0' "$TS_REPORT" >/dev/null || {
        echo "criteria with no measurement behind them: $(jq -c '.criteria | with_entries(select(.value == null))' "$TS_REPORT")" >&2
        return 1
    }
    jq -e '[.criteria[] | select(. == false)] | length == 0' "$TS_REPORT" >/dev/null || {
        echo "criteria not met: $(jq -c '.criteria | with_entries(select(.value == false))' "$TS_REPORT")" >&2
        return 1
    }
}
