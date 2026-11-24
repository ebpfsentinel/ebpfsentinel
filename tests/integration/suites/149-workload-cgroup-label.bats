#!/usr/bin/env bats
# 149-workload-cgroup-label.bats - a workload rule naming the label a cgroup
# directory carries in the `user.ebpfsentinel.workload` extended attribute.
#
# The suite asserts:
#
#   * A task in a cgroup created after the agent started, carrying the
#     label a rule names, is refused; the same client in a cgroup carrying
#     another label, or none, connects.
#   * A rule naming a label no cgroup carries refuses nothing.
#   * The kernel-features route answers `cgroup_labels`, and the start-up
#     log says which path reads the label: in the kernel when the entry is
#     active, by the agent off the cgroup directory with the reason when it
#     is not.
#   * Where the kernel reads it, a label set on a cgroup the client already
#     sits in is refused at the next connect, before the agent has resolved
#     the cgroup again.
#
# Requires: root, kernel >= 6.18, cgroup v2, jq, python3, ncat.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 149 runs its clients beside the agent (local lane only)"
    fi
    [ -f /sys/fs/cgroup/cgroup.controllers ] || env_skip "the host does not run cgroup v2"

    export DATA_DIR="/tmp/ebpfsentinel-test-data-wllabel-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    _remove_cgroups
    create_test_netns

    _write_client

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-workload-cgroup-label.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "cgroup-workload-firewall" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "cgroup-workload-firewall did not load" >&2; return 1; }
    }

    export LISTENER_PIDS=""
    local port
    for port in 7211 7212; do
        LISTENER_PIDS="${LISTENER_PIDS} $(_listen "$port")"
    done
}

teardown_file() {
    # shellcheck disable=SC2086
    kill ${LISTENER_PIDS:-} 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    _remove_cgroups
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-wllabel-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_remove_cgroups() {
    rmdir /sys/fs/cgroup/ebpf-wl-label-a /sys/fs/cgroup/ebpf-wl-label-b \
        /sys/fs/cgroup/ebpf-wl-label-none /sys/fs/cgroup/ebpf-wl-label-late 2>/dev/null || true
}

_listen() {
    local port="${1:?usage: _listen <port>}"
    ip netns exec "$EBPF_TEST_NS" ncat -l "$EBPF_NS_IP" "$port" -k >/dev/null 2>&1 &
    local pid=$!
    local attempt=0
    while [ "$attempt" -lt 25 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -tlnH "sport = :${port}" 2>/dev/null | grep -q . && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "$pid"
}

# The client connects after a delay given in seconds, prints "ok <pid>" or
# "refused <errno> <pid>", then, when given a second port, labels its own
# cgroup and connects again at once, printing a second line.
_write_client() {
    cat > "${DATA_DIR}/client.py" <<'PY'
import errno, os, socket, sys, time
host, port, delay = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
def attempt(p):
    try:
        c = socket.create_connection((host, p), timeout=3)
        c.close()
        print("ok", os.getpid(), flush=True)
    except OSError as e:
        print("refused", errno.errorcode.get(e.errno, e.errno), os.getpid(), flush=True)
time.sleep(delay)
attempt(port)
if len(sys.argv) > 5:
    cgroup, label = sys.argv[4], sys.argv[5]
    os.setxattr(cgroup, "user.ebpfsentinel.workload", label.encode())
    attempt(port)
PY
}

# _label <cgroup> <label> - create the cgroup and set its label.
_label() {
    local cg="/sys/fs/cgroup/${1:?usage: _label <cgroup> <label>}"
    mkdir -p "$cg"
    python3 -c 'import os, sys; os.setxattr(sys.argv[1], "user.ebpfsentinel.workload", sys.argv[2].encode())' \
        "$cg" "$2"
}

# _run_in_cgroup <cgroup> <port> <delay> [label-to-set-then-retry]
_run_in_cgroup() {
    local cg="/sys/fs/cgroup/${1:?usage: _run_in_cgroup <cgroup> <port> <delay> [label]}"
    local port="$2" delay="$3"
    mkdir -p "$cg"
    local extra=()
    [ -z "${4:-}" ] || extra=("$cg" "$4")
    bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' _ "$cg" \
        python3 "${DATA_DIR}/client.py" "$EBPF_NS_IP" "$port" "$delay" "${extra[@]}"
}

_expect() {
    local want="$1" got="$2" what="$3"
    [ "${got%% *}" = "$want" ] || {
        echo "# ${what}: expected ${want}, got: ${got}" >&3
        return 1
    }
}

_label_capability() {
    api_get /api/v1/ebpf/kernel-features | jq -c '.capabilities[] | select(.id == "cgroup_labels")'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a task in a cgroup carrying the label a rule names is refused, another label and none connect" {
    _label ebpf-wl-label-a payments-batch
    _label ebpf-wl-label-b reporting
    local out
    out="$(_run_in_cgroup ebpf-wl-label-a 7211 1.5)"
    _expect refused "$out" "the client in the cgroup labelled payments-batch"
    out="$(_run_in_cgroup ebpf-wl-label-b 7211 1.5)"
    _expect ok "$out" "the client in the cgroup labelled reporting"
    out="$(_run_in_cgroup ebpf-wl-label-none 7211 1.5)"
    _expect ok "$out" "the client in a cgroup with no label"
}

@test "a rule naming a label no cgroup carries refuses nothing" {
    _label ebpf-wl-label-a payments-batch
    local out
    out="$(_run_in_cgroup ebpf-wl-label-a 7212 1.5)"
    _expect ok "$out" "the labelled client on the port of the unset label"
}

@test "the route answers cgroup_labels and the log names the path that reads the label" {
    local entry
    entry="$(_label_capability)"
    [ -n "$entry" ]
    if [ "$(echo "$entry" | jq -r '.active')" = "true" ]; then
        grep -q 'workload labels are read off the cgroup in the kernel' "$AGENT_LOG_FILE"
    else
        [ -n "$(echo "$entry" | jq -r '.reason // ""')" ]
        grep -q 'workload labels are read off the cgroup by the agent' "$AGENT_LOG_FILE"
    fi
}

@test "where the kernel reads the label, one set on the client's own cgroup refuses its next connect" {
    [ "$(_label_capability | jq -r '.active')" = "true" ] ||
        env_skip "the kernel does not read cgroup labels on this host: $(_label_capability | jq -r '.reason')"
    local out
    out="$(_run_in_cgroup ebpf-wl-label-late 7211 0 payments-batch)"
    _expect ok "$(echo "$out" | sed -n 1p)" "the client before its cgroup is labelled"
    _expect refused "$(echo "$out" | sed -n 2p)" "the client right after its cgroup is labelled"
}
