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
#   - connect(): the baseline is the agent stopped. The measured arm runs the
#     agent with attribution on and nothing else, so the delta is connect4
#     plus the sock_ops record and not a firewall lookup.
#   - execve(): the same subtraction with the process table on, so the delta
#     is sched_process_exec plus sched_process_exit plus the userspace read of
#     /proc that follows them.
#
# Each arm is three runs and the median is kept, because a single run on a
# four-vCPU guest moves by more than the figure being measured.
#
# Requires: root, kernel >= 6.9, a C compiler, python3, jq, bc.
# Nightly tier. Outputs JSON to /tmp/ebpfsentinel-attribution-overhead.json

FIXTURE_DIR="${BATS_TEST_DIRNAME}/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

OVERHEAD_REPORT="/tmp/ebpfsentinel-attribution-overhead.json"
CONNECT_ITERATIONS="${CONNECT_ITERATIONS:-20000}"
EXEC_ITERATIONS="${EXEC_ITERATIONS:-3000}"
BENCH_RUNS="${BENCH_RUNS:-3}"
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

    # A listener that accepts and closes, so every iteration of the driver
    # completes a handshake and the sock_ops hook has an established socket to
    # record. The backlog is deep enough that the driver never waits on it.
    python3 - "$LISTEN_PORT" >/dev/null 2>&1 <<'PY' &
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
# of an even-sized one. Three runs of a syscall loop on a guest have one slow
# outlier often enough that a mean would report the scheduler.
_median() {
    local sorted; sorted="$(printf '%s\n' "$@" | sort -n)"
    local count; count="$(printf '%s\n' "$@" | wc -l)"
    echo "$sorted" | sed -n "$(( (count + 1) / 2 ))p"
}

# _bench <mode> - run the driver BENCH_RUNS times, echo "<ns_per_op> <ops_per_s>"
# for the median run.
_bench() {
    local mode="$1"
    local -a per_op=()
    local run output
    for run in $(seq 1 "$BENCH_RUNS"); do
        if [ "$mode" = "connect" ]; then
            output="$("$BENCH_BIN" connect "$CONNECT_ITERATIONS" "$LISTEN_PORT")" || return 1
        else
            output="$("$BENCH_BIN" exec "$EXEC_ITERATIONS")" || return 1
        fi
        per_op+=( "$(echo "$output" | awk '{print $3}')" )
    done
    local median; median="$(_median "${per_op[@]}")"
    local rate; rate="$(echo "scale=0; 1000000000 / $median" | bc -l)"
    echo "$median $rate"
}

# _attribution_config <variant> - firewall in pass mode plus the subsystem under
# measurement, so the delta is the hooks and not a policy lookup.
#   attribution  → the seven cgroup programs, no process table
#   process      → the two tracepoints and the userspace table, no attribution
_attribution_config() {
    local variant="$1"
    local attribution="false" process="false"
    case "$variant" in
        attribution) attribution="true" ;;
        process)     process="true" ;;
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

@test "baseline: connect() and execve() with no agent running" {
    stop_ebpf_agent 2>/dev/null || true

    run _bench connect
    [ "$status" -eq 0 ]
    local connect_ns connect_rate
    connect_ns="$(echo "$output" | awk '{print $1}')"
    connect_rate="$(echo "$output" | awk '{print $2}')"
    _report_set_str "baseline_connect_ns" "$connect_ns"
    _report_set "baseline_connect_per_s" "$connect_rate"

    run _bench exec
    [ "$status" -eq 0 ]
    local exec_ns
    exec_ns="$(echo "$output" | awk '{print $1}')"
    _report_set_str "baseline_exec_ns" "$exec_ns"

    echo "# baseline: ${connect_ns} ns/connect (${connect_rate} connects/s), ${exec_ns} ns/exec" >&3
}

@test "socket attribution: the cost of naming the task behind a connect()" {
    local baseline; baseline="$(jq -r '.baseline_connect_ns // empty' "$OVERHEAD_REPORT")"
    [ -n "$baseline" ] || skip "no baseline recorded"

    local prepared; prepared="$(prepare_ebpf_config "$(_attribution_config attribution)")"
    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || { stop_ebpf_agent; skip "eBPF did not load"; }

    # What the kernel actually took is part of the figure: a host that refused
    # the socket-to-flow join pays six hooks and not seven, and a number
    # published without that is a number measured on another machine.
    local hooks reason
    hooks="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null | jq '.attribution.hooks | length' 2>/dev/null)"
    # The sentence, not the verifier log that follows it: the log belongs in
    # the agent's own output, and a published result stays readable.
    reason="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null \
        | jq -r '.attribution.reason // ""' 2>/dev/null \
        | head -1 | sed 's/; verifier log:.*//')"
    _report_set "attribution_hooks_attached" "${hooks:-0}"
    _report_set_str "attribution_degraded_reason" "${reason:-}"

    run _bench connect
    [ "$status" -eq 0 ]
    local connect_ns connect_rate
    connect_ns="$(echo "$output" | awk '{print $1}')"
    connect_rate="$(echo "$output" | awk '{print $2}')"
    stop_ebpf_agent

    local delta; delta="$(echo "scale=1; $connect_ns - $baseline" | bc -l)"
    local pct; pct="$(echo "scale=2; ($delta / $baseline) * 100" | bc -l)"
    _report_set_str "attribution_connect_ns" "$connect_ns"
    _report_set "attribution_connect_per_s" "$connect_rate"
    _report_set_str "attribution_overhead_ns" "$delta"
    _report_set_str "attribution_overhead_pct" "$pct"

    echo "# attribution: ${connect_ns} ns/connect (${connect_rate} connects/s), ${delta} ns added (${pct}%)" >&3

    # A negative delta is the guest being faster on the second arm, which is
    # the lane's noise rather than a hook that gives time back; only the upper
    # bound is asserted.
    local over; over="$(echo "$delta > $MAX_CONNECT_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
}

@test "process tracing: the cost of keeping the table truthful across execve()" {
    local baseline; baseline="$(jq -r '.baseline_exec_ns // empty' "$OVERHEAD_REPORT")"
    [ -n "$baseline" ] || skip "no baseline recorded"

    local prepared; prepared="$(prepare_ebpf_config "$(_attribution_config process)")"
    start_ebpf_agent "$prepared"
    wait_for_ebpf_loaded 30 || { stop_ebpf_agent; skip "eBPF did not load"; }

    run _bench exec
    [ "$status" -eq 0 ]
    local exec_ns
    exec_ns="$(echo "$output" | awk '{print $1}')"
    stop_ebpf_agent

    local delta; delta="$(echo "scale=1; $exec_ns - $baseline" | bc -l)"
    local pct; pct="$(echo "scale=2; ($delta / $baseline) * 100" | bc -l)"
    _report_set_str "process_exec_ns" "$exec_ns"
    _report_set_str "process_overhead_ns" "$delta"
    _report_set_str "process_overhead_pct" "$pct"

    echo "# process table: ${exec_ns} ns/exec, ${delta} ns added (${pct}%)" >&3

    local over; over="$(echo "$delta > $MAX_EXEC_OVERHEAD_NS" | bc -l)"
    [ "$over" -eq 0 ]
}

@test "the report names the rate every figure was measured at" {
    local rate; rate="$(jq -r '.baseline_connect_per_s // empty' "$OVERHEAD_REPORT")"
    [ -n "$rate" ] || skip "no baseline recorded"

    _report_set_str "kernel" "$(uname -r)"
    _report_set "vcpus" "$(nproc)"
    _report_set "connect_iterations" "$CONNECT_ITERATIONS"
    _report_set "exec_iterations" "$EXEC_ITERATIONS"
    _report_set "runs_per_arm" "$BENCH_RUNS"

    run jq -e '.baseline_connect_ns and .baseline_connect_per_s and .kernel' "$OVERHEAD_REPORT"
    [ "$status" -eq 0 ]
    cat "$OVERHEAD_REPORT" >&3
}
