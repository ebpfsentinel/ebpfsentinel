#!/usr/bin/env bats
# 07-attribution-overhead.bats - what naming the workload behind a flow costs.
#
# The attribution hooks do not sit on the packet path, so none of the other
# perf suites can see them: a throughput run pays the socket hooks once per
# connection and the process tracepoints not at all. Their cost is paid where
# they run, which is the connect() of a task opening a socket and the exec()
# of a program starting. This suite times exactly those two syscalls, with the
# hooks attached and without, and reports the difference per operation.
#
#   - connect(): both arms run the same agent, one with attribution off and
#     one with it on, so the delta is connect4 plus the sock_ops record and
#     not the agent's own background work. An arm with no agent at all was
#     the first attempt and measured the agent, not the hooks.
#   - execve(): the same subtraction with the process table off and on, so
#     the delta is sched_process_exec plus sched_process_exit plus the
#     userspace read of /proc that follows them.
#
# The two arms are interleaved rather than run one after the other, and the
# figure is the median of the per-pair differences. Running every baseline
# first and every measured run after it measures the guest's drift as much as
# the hooks: that is how a first attempt produced a delta that changed sign
# between runs and a published range wide enough to contain zero. A pair is
# baseline then measured, back to back, so a slow minute costs both arms the
# same. The driver and the listener are pinned to their own CPUs where
# taskset and four vCPUs allow it, which takes the scheduler's migrations out
# of the same figure.
#
# Requires: root, kernel >= 6.9, a C compiler, python3, jq, bc.
# Nightly tier. Outputs JSON to /tmp/ebpfsentinel-attribution-overhead.json

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

OVERHEAD_REPORT="/tmp/ebpfsentinel-attribution-overhead.json"
CONNECT_ITERATIONS="${CONNECT_ITERATIONS:-200000}"
EXEC_ITERATIONS="${EXEC_ITERATIONS:-10000}"
PAIR_RUNS="${PAIR_RUNS:-7}"
LISTEN_PORT="${LISTEN_PORT:-19321}"

# A hook that observes and returns the allow verdict has no reason to cost
# microseconds; these bounds are what a four-vCPU guest can hold without the
# run turning into a scheduler measurement, not a target the product aims at.
MAX_CONNECT_OVERHEAD_NS="${MAX_CONNECT_OVERHEAD_NS:-5000}"
MAX_EXEC_OVERHEAD_NS="${MAX_EXEC_OVERHEAD_NS:-200000}"

setup_file() {
    require_root
    require_kernel 6 9
    require_tool cc
    require_tool python3
    require_tool jq
    require_tool bc

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-attribution-$$"
    mkdir -p "$DATA_DIR"
    stop_ebpf_agent 2>/dev/null || true
    create_test_netns

    export BENCH_BIN="${DATA_DIR}/connect-bench"
    cc -O2 -o "$BENCH_BIN" "${FIXTURE_DIR}/connect-bench.c"

    # Pinning, where the guest has the CPUs for it: the driver on one, the
    # listener on another, so a measured difference is not the scheduler
    # moving one of them. Absent taskset or a fourth CPU, both run unpinned
    # and the report says which it was.
    DRIVER_PIN=""
    LISTENER_PIN=""
    if command -v taskset >/dev/null 2>&1 && [ "$(nproc)" -ge 4 ]; then
        DRIVER_PIN="taskset -c 2"
        LISTENER_PIN="taskset -c 3"
    fi
    export DRIVER_PIN LISTENER_PIN

    # A listener that accepts and closes, so every iteration of the driver
    # completes a handshake and the sock_ops hook has an established socket to
    # record. The backlog is deep enough that the driver never waits on it.
    $LISTENER_PIN python3 - "$LISTEN_PORT" >/dev/null 2>&1 <<'PY' &
import socket, sys
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(1024)
while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    conn.close()
PY
    export LISTENER_PID=$!
    sleep 1

    rm -f "$OVERHEAD_REPORT"
    echo '{}' > "$OVERHEAD_REPORT"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-attribution-$$}"
}

_report_set() {
    local tmp; tmp="$(jq --arg k "$1" --argjson v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}
_report_set_str() {
    local tmp; tmp="$(jq --arg k "$1" --arg v "$2" '. + {($k): $v}' "$OVERHEAD_REPORT")"; echo "$tmp" > "$OVERHEAD_REPORT"
}

# _median <value>... - the middle value of an odd-sized list, the lower middle
# of an even-sized one. A pair of syscall loops on a guest has one slow
# outlier often enough that a mean would report the scheduler.
_median() {
    local sorted; sorted="$(printf '%s\n' "$@" | sort -n)"
    local count; count="$(printf '%s\n' "$@" | wc -l)"
    echo "$sorted" | sed -n "$(( (count + 1) / 2 ))p"
}

_min() { printf '%s\n' "$@" | sort -n | head -1; }
_max() { printf '%s\n' "$@" | sort -n | tail -1; }

# _driver <mode> - one run of the C driver, echoing nanoseconds per operation.
_driver() {
    local mode="$1" output
    if [ "$mode" = "connect" ]; then
        output="$($DRIVER_PIN "$BENCH_BIN" connect "$CONNECT_ITERATIONS" "$LISTEN_PORT")" || return 1
    else
        output="$($DRIVER_PIN "$BENCH_BIN" exec "$EXEC_ITERATIONS")" || return 1
    fi
    echo "$output" | awk '{print $3}'
}

# _attribution_config <variant> - firewall in pass mode plus the subsystem under
# measurement, so the delta is the hooks and not a policy lookup.
#   none         -> neither, which is the baseline arm
#   both         -> all of it, for the arm that reads the kernel's own clock
#   attribution  -> the seven cgroup programs, no process table
#   process      -> the two tracepoints and the userspace table, no attribution
_attribution_config() {
    local variant="$1"
    local attribution="false" process="false"
    case "$variant" in
        attribution) attribution="true" ;;
        process)     process="true" ;;
        both)        attribution="true"; process="true" ;;
    esac
    local cfg="${DATA_DIR}/config-${variant}-$$.yaml"
    cat > "$cfg" <<EOF
agent:
  interfaces:
    - __INTERFACE__
  bind_address: "127.0.0.1"
  # Info, not warn: the harness proves the agent is running this fixture by
  # finding the startup line that carries the config path, and that line is
  # logged at info.
  log_level: info
  http_port: 8080
  grpc_port: 50051
  metrics_port: 9090

firewall:
  enabled: true
  default_policy: pass
  rules: []

attribution:
  enabled: ${attribution}
  cgroup_root: /sys/fs/cgroup
  max_sockets: 65536

process_table:
  enabled: ${process}
  capacity: 8192
  capture_command_line: false

# The suite reads the attribution status back over HTTP to record how many
# hooks the kernel took, and a bearer token would add a round trip to every
# arm without changing what is being timed.
auth:
  enabled: false

alerting:
  enabled: false
audit:
  enabled: false
  storage_path: __DATA_DIR__/audit.redb
EOF
    echo "$cfg"
}

# _record_hooks - what the kernel actually took, read while the agent is up. A
# host that refuses the socket-to-flow join pays six hooks and not seven, and
# a number published without that is a number measured on another machine.
_record_hooks() {
    local hooks reason attempt
    # The status is published as the hooks attach, which is after the eBPF
    # objects load: ask again rather than record a zero that reads as a
    # kernel refusing all seven.
    for attempt in $(seq 1 20); do
        hooks="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null | jq '.attribution.hooks | length' 2>/dev/null)"
        [ "${hooks:-0}" -gt 0 ] && break
        sleep 0.5
    done
    # The sentence, not the verifier log that follows it: the log belongs in
    # the agent's own output, and a published result stays readable.
    reason="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null \
        | jq -r '.attribution.reason // ""' 2>/dev/null \
        | head -1 | sed 's/; verifier log:.*//')"
    _report_set "attribution_hooks_attached" "${hooks:-0}"
    _report_set_str "attribution_degraded_reason" "${reason:-}"
}

# _paired <mode> <baseline_variant> <measured_variant> <prefix> - PAIR_RUNS
# pairs of "the agent with the subsystem off, then the same agent with it on",
# the driver run once in each half. Writes the medians, the per-pair deltas
# and their spread under <prefix> and echoes the median delta.
_paired() {
    local mode="$1" off_variant="$2" on_variant="$3" prefix="$4"
    local off_config on_config
    off_config="$(prepare_ebpf_config "$(_attribution_config "$off_variant")")"
    on_config="$(prepare_ebpf_config "$(_attribution_config "$on_variant")")"

    local -a base_runs=() meas_runs=() deltas=()
    local pair base meas
    for pair in $(seq 1 "$PAIR_RUNS"); do
        start_ebpf_agent "$off_config" >/dev/null 2>&1
        wait_for_ebpf_loaded 30 || { stop_ebpf_agent; return 2; }
        base="$(_driver "$mode")" || { stop_ebpf_agent; return 1; }
        stop_ebpf_agent 2>/dev/null || true

        start_ebpf_agent "$on_config" >/dev/null 2>&1
        wait_for_ebpf_loaded 30 || { stop_ebpf_agent; return 2; }
        [ "$pair" -eq 1 ] && [ "$on_variant" = "attribution" ] && _record_hooks
        meas="$(_driver "$mode")" || { stop_ebpf_agent; return 1; }
        stop_ebpf_agent 2>/dev/null || true

        base_runs+=( "$base" )
        meas_runs+=( "$meas" )
        deltas+=( "$(echo "scale=1; $meas - $base" | bc -l)" )
        echo "# pair ${pair}: off ${base} ns, on ${meas} ns" >&3
    done

    local base_median meas_median delta_median
    base_median="$(_median "${base_runs[@]}")"
    meas_median="$(_median "${meas_runs[@]}")"
    delta_median="$(_median "${deltas[@]}")"

    _report_set_str "${prefix}_baseline_ns" "$base_median"
    _report_set_str "${prefix}_measured_ns" "$meas_median"
    _report_set_str "${prefix}_overhead_ns" "$delta_median"
    _report_set_str "${prefix}_overhead_min_ns" "$(_min "${deltas[@]}")"
    _report_set_str "${prefix}_overhead_max_ns" "$(_max "${deltas[@]}")"
    _report_set_str "${prefix}_overhead_pct" "$(echo "scale=2; ($delta_median / $base_median) * 100" | bc -l)"
    _report_set "${prefix}_per_s" "$(echo "scale=0; 1000000000 / $meas_median" | bc -l)"
    _report_set_str "${prefix}_deltas_ns" "$(printf '%s ' "${deltas[@]}" | sed 's/ $//')"

    echo "$delta_median"
}

@test "socket attribution: the cost of naming the task behind a connect()" {
    run _paired connect none attribution attribution_connect
    [ "$status" -ne 2 ] || skip "eBPF did not load"
    [ "$status" -eq 0 ]
    local delta; delta="$(echo "$output" | tail -1)"

    echo "# attribution: ${delta} ns added per connect() (median of ${PAIR_RUNS} pairs)" >&3

    # Both sides are asserted now that the arms are interleaved: a hook that
    # observes and returns cannot give time back, so a median delta below
    # minus the lane's own spread is a broken measurement rather than a fast
    # agent, and the suite says so instead of publishing it.
    local over under
    over="$(echo "$delta > $MAX_CONNECT_OVERHEAD_NS" | bc -l)"
    under="$(echo "$delta < -$MAX_CONNECT_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
    [ "$under" -eq 0 ]
}

@test "process tracing: the cost of keeping the table truthful across execve()" {
    run _paired exec none process process_exec
    [ "$status" -ne 2 ] || skip "eBPF did not load"
    [ "$status" -eq 0 ]
    local delta; delta="$(echo "$output" | tail -1)"

    echo "# process table: ${delta} ns added per execve() (median of ${PAIR_RUNS} pairs)" >&3

    local over under
    over="$(echo "$delta > $MAX_EXEC_OVERHEAD_NS" | bc -l)"
    under="$(echo "$delta < -$MAX_EXEC_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
    [ "$under" -eq 0 ]
}

# _prog_time <name regex> - "<run_time_ns> <run_cnt>" summed over the loaded
# programs whose kernel name matches. A kernel program name is cut to fifteen
# characters, so `connect4` and `connect6` arrive under one name; the sum is
# what is wanted here anyway, since a connection runs several of them.
_prog_time() {
    bpftool prog show -j 2>/dev/null | jq -r --arg p "$1" \
        '[.[] | select((.name // "") | test($p))]
         | "\([.[].run_time_ns // 0] | add // 0) \([.[].run_cnt // 0] | add // 0)"'
}

@test "the kernel's own clock: what the hooks run for, per operation" {
    require_tool bpftool
    local prepared; prepared="$(prepare_ebpf_config "$(_attribution_config both)")"
    start_ebpf_agent "$prepared" >/dev/null 2>&1
    wait_for_ebpf_loaded 30 || { stop_ebpf_agent; skip "eBPF did not load"; }

    # The kernel times every program run while this is on, which is the
    # figure the syscall arms cannot resolve: a hundred nanoseconds inside a
    # thirteen-microsecond connect(). It costs a few percent on every program
    # run and bills the accounting to the program, so the number it gives is
    # an upper bound on the hook and not a floor.
    sysctl -w kernel.bpf_stats_enabled=1 >/dev/null

    local before after
    before="$(_prog_time '^attribution_')"
    _driver connect >/dev/null
    after="$(_prog_time '^attribution_')"
    local attr_ns attr_cnt
    attr_ns="$(( $(echo "$after" | awk '{print $1}') - $(echo "$before" | awk '{print $1}') ))"
    attr_cnt="$(( $(echo "$after" | awk '{print $2}') - $(echo "$before" | awk '{print $2}') ))"

    before="$(_prog_time '^process_')"
    _driver exec >/dev/null
    after="$(_prog_time '^process_')"
    local proc_ns proc_cnt
    proc_ns="$(( $(echo "$after" | awk '{print $1}') - $(echo "$before" | awk '{print $1}') ))"
    proc_cnt="$(( $(echo "$after" | awk '{print $2}') - $(echo "$before" | awk '{print $2}') ))"

    sysctl -w kernel.bpf_stats_enabled=0 >/dev/null
    stop_ebpf_agent 2>/dev/null || true

    [ "$attr_cnt" -gt 0 ]
    [ "$proc_cnt" -gt 0 ]

    _report_set_str "attribution_kernel_ns_per_connect" \
        "$(echo "scale=1; $attr_ns / $CONNECT_ITERATIONS" | bc -l)"
    _report_set_str "attribution_kernel_ns_per_run" \
        "$(echo "scale=1; $attr_ns / $attr_cnt" | bc -l)"
    _report_set_str "attribution_kernel_runs_per_connect" \
        "$(echo "scale=2; $attr_cnt / $CONNECT_ITERATIONS" | bc -l)"
    _report_set_str "process_kernel_ns_per_exec" \
        "$(echo "scale=1; $proc_ns / $EXEC_ITERATIONS" | bc -l)"
    _report_set_str "process_kernel_ns_per_run" \
        "$(echo "scale=1; $proc_ns / $proc_cnt" | bc -l)"
    _report_set_str "process_kernel_runs_per_exec" \
        "$(echo "scale=2; $proc_cnt / $EXEC_ITERATIONS" | bc -l)"

    echo "# kernel clock: attribution $(jq -r .attribution_kernel_ns_per_connect "$OVERHEAD_REPORT") ns per connect(), process $(jq -r .process_kernel_ns_per_exec "$OVERHEAD_REPORT") ns per execve()" >&3

    # The syscall arms bound the same thing from outside; a kernel figure
    # above that bound means the stats are being read against the wrong
    # programs rather than that a hook became expensive.
    local over
    over="$(echo "$(jq -r .attribution_kernel_ns_per_connect "$OVERHEAD_REPORT") > $MAX_CONNECT_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
    over="$(echo "$(jq -r .process_kernel_ns_per_exec "$OVERHEAD_REPORT") > $MAX_EXEC_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
}

@test "the report names the rate every figure was measured at" {
    local measured; measured="$(jq -r '.attribution_connect_baseline_ns // empty' "$OVERHEAD_REPORT")"
    [ -n "$measured" ] || skip "no paired run recorded"

    _report_set_str "kernel" "$(uname -r)"
    _report_set "vcpus" "$(nproc)"
    _report_set "connect_iterations" "$CONNECT_ITERATIONS"
    _report_set "exec_iterations" "$EXEC_ITERATIONS"
    _report_set "pairs_per_arm" "$PAIR_RUNS"
    _report_set_str "pinning" "${DRIVER_PIN:-none} / ${LISTENER_PIN:-none}"

    run jq -e '.attribution_connect_overhead_ns and .process_exec_overhead_ns and .kernel' "$OVERHEAD_REPORT"
    [ "$status" -eq 0 ]
    cat "$OVERHEAD_REPORT" >&3
}
