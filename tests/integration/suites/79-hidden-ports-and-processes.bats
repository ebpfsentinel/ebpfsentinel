#!/usr/bin/env bats
# 79-hidden-ports-and-processes.bats - both hidden sweeps on a busy host.
#
# A hidden port needs a rootkit to exist, so the positive case lives in the
# unit tests, injected at the port boundary. What only a real host can show is
# the negative: listeners in several network namespaces, two sockets sharing
# one port through SO_REUSEPORT, connections left in TIME_WAIT, a process
# carrying many threads and processes starting and exiting all through the
# sweep, and neither sweep reports anything. A sweep that cries wolf on a
# clean host is the failure mode, because it gets turned off.
#
# The suite asserts:
#
#   * Both sweeps run, and each explains what it met: the listeners by their
#     listing, the threads by their thread group.
#   * Neither sweep reports a port or a process on that host, twice in a row,
#     and no alert is raised under either component.
#   * The process sweep stays inside its budget: a full pass of the pid space
#     ends well inside its interval, and the agent averages a small share of
#     one core across a minute holding a sweep.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool python3
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 79 makes its host busy beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-hidden-$$"
    export BUSY_PIDS_FILE="${DATA_DIR}/busy.pids"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    _make_host_busy

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-hidden-checks.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    if [ -f "${BUSY_PIDS_FILE:-}" ]; then
        xargs -r kill 2>/dev/null < "${BUSY_PIDS_FILE}" || true
    fi
    ip netns pids "$EBPF_TEST_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-hidden-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _keep <pid> - remembers a background process for teardown.
_keep() {
    echo "$1" >> "${BUSY_PIDS_FILE}"
}

# _make_host_busy - everything a clean host carries that a naive sweep would
# report: listeners in two network namespaces, SO_REUSEPORT, TIME_WAIT, a
# process with many threads, and processes starting and exiting throughout.
_make_host_busy() {
    # Two TCP sockets sharing 9443 through SO_REUSEPORT, a TCP listener on
    # 8443 and a UDP socket on 5353, in the host's namespace, held by one
    # process that also carries forty idle threads.
    python3 - <<'PY' &
import socket, threading, time
held = []
for _ in range(2):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("::", 9443)); s.listen(); held.append(s)
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("0.0.0.0", 8443)); t.listen(); held.append(t)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", 5353)); held.append(u)
def accept_forever(sock):
    while True:
        c, _ = sock.accept(); c.close()
threading.Thread(target=accept_forever, args=(t,), daemon=True).start()
for _ in range(40):
    threading.Thread(target=time.sleep, args=(3600,), daemon=True).start()
time.sleep(3600)
PY
    _keep $!

    # A listener and a UDP socket inside the test namespace, on ports the
    # sweep also probes there.
    ip netns exec "$EBPF_TEST_NS" ncat -l -k 31337 >/dev/null 2>&1 &
    _keep $!
    ip netns exec "$EBPF_TEST_NS" ncat -u -l -k 5353 >/dev/null 2>&1 &
    _keep $!

    # Connections opened and closed from the namespace, each leaving a
    # TIME_WAIT entry behind on one end or the other.
    (
        while :; do
            ip netns exec "$EBPF_TEST_NS" ncat -z -w 1 "$EBPF_HOST_IP" 8443 >/dev/null 2>&1
            sleep 0.2
        done
    ) &
    _keep $!

    # Process churn: short-lived processes started and reaped all the time.
    (
        while :; do
            /bin/true
        done
    ) &
    _keep $!

    sleep 1
}

# _sweep <route> - the sweep's answer, empty when the route did not answer.
_sweep() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/${1:?route}" || true
}

# _wait_swept_after <route> <ns> <timeout_s> - polls until a sweep finished
# after <ns>, and prints its scanned_at_ns.
_wait_swept_after() {
    local route="$1" after="$2" timeout="$3" at i
    for ((i = 0; i < timeout; i++)); do
        at="$(_sweep "$route" | jq -r '.scanned_at_ns // 0')"
        if [ "${at:-0}" -gt "$after" ]; then
            echo "$at"
            return 0
        fi
        sleep 1
    done
    return 1
}

# _cpu_ticks - user plus system clock ticks of the agent and, when it runs
# one, its warden, which is where the rootless posture sweeps from.
_cpu_ticks() {
    local total=0 pid ticks
    for pid in "$(cat "$AGENT_PID_FILE" 2>/dev/null)" \
        "$(cat "${AGENT_PID_FILE}.warden" 2>/dev/null)"; do
        [ -n "$pid" ] && [ -r "/proc/${pid}/stat" ] || continue
        ticks="$(awk '{ sub(/^.*\) /, ""); print $12 + $13 }' "/proc/${pid}/stat")"
        total=$((total + ticks))
    done
    echo "$total"
}

# ── Tests ───────────────────────────────────────────────────────────

@test "both sweeps run on the busy host and explain what they met" {
    _wait_swept_after hidden-ports 0 90 >/dev/null
    _wait_swept_after hidden-processes 0 90 >/dev/null

    local ports processes
    ports="$(_sweep hidden-ports)"
    processes="$(_sweep hidden-processes)"

    [ "$(echo "$ports" | jq -r '.reading')" = "true" ]
    [ "$(echo "$processes" | jq -r '.reading')" = "true" ]
    [ "$(echo "$ports" | jq -r '.counts.namespaces')" -ge 2 ]
    [ "$(echo "$ports" | jq -r '.counts.explained_by_listener')" -ge 3 ]
    [ "$(echo "$processes" | jq -r '.counts.explained_by_thread')" -ge 40 ]
}

@test "neither sweep reports anything on a clean busy host, twice in a row" {
    local first_ports first_processes
    first_ports="$(_wait_swept_after hidden-ports 0 90)"
    first_processes="$(_wait_swept_after hidden-processes 0 90)"

    for route in hidden-ports hidden-processes; do
        local body
        body="$(_sweep "$route")"
        [ "$(echo "$body" | jq -r '.counts.hidden')" -eq 0 ] || {
            echo "${route} reported on a clean host: $(echo "$body" | jq -c '.hidden')" >&2
            return 1
        }
    done

    # A second pass under the same churn, so one lucky sweep is not the proof.
    _wait_swept_after hidden-ports "$first_ports" 90 >/dev/null
    _wait_swept_after hidden-processes "$first_processes" 90 >/dev/null
    [ "$(_sweep hidden-ports | jq -r '.hidden | length')" -eq 0 ]
    [ "$(_sweep hidden-processes | jq -r '.hidden | length')" -eq 0 ]

    local alerts
    alerts="$(api_get /api/v1/alerts)"
    [ "$(echo "$alerts" | jq '[.. | objects | select(.component? == "hidden_port"
        or .component? == "hidden_process")] | length')" -eq 0 ]
}

@test "the process sweep stays inside its budget" {
    local before after ticks_before ticks_after hz wall_ns space pace
    before="$(_wait_swept_after hidden-processes 0 90)"
    ticks_before="$(_cpu_ticks)"
    after="$(_wait_swept_after hidden-processes "$before" 120)"
    ticks_after="$(_cpu_ticks)"
    hz="$(getconf CLK_TCK)"

    space="$(_sweep hidden-processes | jq -r '.counts.pid_space')"
    pace="$(_sweep hidden-processes | jq -r '.pids_per_second')"

    # A full pass at this pace is a few seconds; the next one landing on its
    # interval rather than later says no pass overran it.
    [ $((space / pace)) -le 10 ]
    wall_ns=$((after - before))
    [ "$wall_ns" -le $(( (60 + 15) * 1000000000 )) ]

    # Under a quarter of one core, averaged across a minute holding a pass.
    local cpu_ms=$(( (ticks_after - ticks_before) * 1000 / hz ))
    local wall_ms=$(( wall_ns / 1000000 ))
    echo "agent cpu ${cpu_ms} ms over ${wall_ms} ms" >&3
    [ $((cpu_ms * 4)) -le "$wall_ms" ]
}
