#!/usr/bin/env bats
# 92-workload-matchers.bats - workload rules naming a task by what it runs
# and where it runs, decided by the kernel at connect.
#
# The suite asserts:
#
#   * `exe` refuses a copy of python3 at the path the rule names, lets the
#     system python3 through on the same port, and the denial alert carries
#     the workload block: the pid, the path and the digest of the binary.
#   * `exe_hash` names the bytes: the marked copy is refused under two
#     paths, and an unmarked copy at either path connects.
#   * `unit` refuses a task in the systemd scope it names, and the same
#     client outside the scope connects.
#   * `cgroup` refuses a task in a cgroup created after the agent started,
#     and the same client outside it connects.
#   * A rule that says no mode observes: the connect goes through and the
#     alert says it would have been refused.
#   * `fqdn` opens an address for the cgroup that resolved the name through
#     a listed resolver, and for nothing before the answer; the resolved
#     name is listed by the rule.
#
# Requires: root, kernel >= 6.12, jq, python3, ncat, sha256sum.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool ncat
    require_tool sha256sum

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 92 runs its clients beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-wlmatch-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rmdir /sys/fs/cgroup/ebpf-wl-cgroup /sys/fs/cgroup/ebpf-wl-fqdn 2>/dev/null || true
    create_test_netns

    # A copy of python3 run with the system's library, one carrying a byte
    # more at a first path and the same marked bytes at a second.
    export SYS_PYTHON PYTHONHOME_DIR PYCOPY PYMARK PYMARK_MOVED PYPLAIN_MOVED
    SYS_PYTHON="$(readlink -f "$(command -v python3)")"
    PYTHONHOME_DIR="$("$SYS_PYTHON" -c 'import sys; print(sys.base_prefix)')"
    PYCOPY="${DATA_DIR}/wl-python"
    PYMARK="${DATA_DIR}/wl-python-marked"
    PYMARK_MOVED="${DATA_DIR}/moved/wl-python-marked"
    PYPLAIN_MOVED="${DATA_DIR}/moved/wl-python-plain"
    mkdir -p "${DATA_DIR}/moved"
    cp "$SYS_PYTHON" "$PYCOPY"
    cp "$SYS_PYTHON" "$PYMARK"
    printf 'ebpfsentinel-test-mark' >> "$PYMARK"
    cp "$PYMARK" "$PYMARK_MOVED"
    cp "$SYS_PYTHON" "$PYPLAIN_MOVED"
    chmod 0755 "$PYCOPY" "$PYMARK" "$PYMARK_MOVED" "$PYPLAIN_MOVED"
    PYTHONHOME="$PYTHONHOME_DIR" "$PYMARK" -c 'pass' || {
        echo "a copied python3 does not start" >&2
        return 1
    }

    _write_client

    local hash
    hash="sha256:$(sha256sum "$PYMARK" | cut -d' ' -f1)"
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-workload-matchers.yaml")"
    export PREPARED_CONFIG
    sed -i -e "s|__PYCOPY__|${PYCOPY}|" -e "s|__PYMARK_HASH__|${hash}|" "$PREPARED_CONFIG"

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "cgroup-workload-firewall" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "cgroup-workload-firewall did not load" >&2; return 1; }
    }

    export LISTENER_PIDS="" DNS_PID=""
    local port
    for port in 7201 7202 7203 7204 7205 7206; do
        LISTENER_PIDS="${LISTENER_PIDS} $(_listen "$port")"
    done
    DNS_PID="$(_dns_server)"
}

teardown_file() {
    # shellcheck disable=SC2086
    kill ${LISTENER_PIDS:-} ${DNS_PID:-} 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rmdir /sys/fs/cgroup/ebpf-wl-cgroup /sys/fs/cgroup/ebpf-wl-fqdn 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-wlmatch-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

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

# _dns_server - answers every A query with the namespace's own address.
_dns_server() {
    ip netns exec "$EBPF_TEST_NS" python3 - "$EBPF_NS_IP" >/dev/null 2>&1 <<'PY' &
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
addr = socket.inet_aton(sys.argv[1])
while True:
    q, peer = s.recvfrom(512)
    end = 12
    while q[end] != 0:
        end += q[end] + 1
    question = q[12:end + 5]
    head = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + addr
    s.sendto(head + question + answer, peer)
PY
    local pid=$!
    local attempt=0
    while [ "$attempt" -lt 25 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -ulnH "sport = :53" 2>/dev/null | grep -q . && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "$pid"
}

# The client waits for the agent to have read its exec, optionally resolves
# a name through the namespace's resolver, then connects. It prints
# "ok <pid>" or "refused <errno> <pid>".
_write_client() {
    cat > "${DATA_DIR}/client.py" <<'PY'
import errno, os, random, socket, struct, sys, time
host, port = sys.argv[1], int(sys.argv[2])
time.sleep(1.5)
if len(sys.argv) > 3:
    name = sys.argv[3]
    qid = random.randint(1, 65535)
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    query += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    query += struct.pack(">HH", 1, 1)
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.settimeout(3)
    r.sendto(query, (host, 53))
    r.recv(512)
    time.sleep(0.5)
try:
    c = socket.create_connection((host, port), timeout=3)
    c.close()
    print("ok", os.getpid())
except OSError as e:
    print("refused", errno.errorcode.get(e.errno, e.errno), os.getpid())
# Stay alive a moment so the alert finds the process it names.
sys.stdout.flush()
time.sleep(1)
PY
}

# _run <python> <port> [name] - the client under the given interpreter.
_run() {
    local py="${1:?usage: _run <python> <port> [name]}"
    shift
    PYTHONHOME="$PYTHONHOME_DIR" "$py" "${DATA_DIR}/client.py" "$EBPF_NS_IP" "$@"
}

# _run_in_cgroup <cgroup> <port> [name] - the client exec'd inside a cgroup.
_run_in_cgroup() {
    local cg="/sys/fs/cgroup/${1:?usage: _run_in_cgroup <cgroup> <port> [name]}"
    shift
    mkdir -p "$cg"
    bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' _ "$cg" \
        "$SYS_PYTHON" "${DATA_DIR}/client.py" "$EBPF_NS_IP" "$@"
}

_denials() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/firewall/workload/rules" \
        | jq -r --arg rule "$1" '.rules[] | select(.rule == $rule) | .denials'
}

_expect() {
    local want="$1" got="$2" what="$3"
    [ "${got%% *}" = "$want" ] || {
        echo "# ${what}: expected ${want}, got: ${got}" >&3
        return 1
    }
}

# ── Tests ───────────────────────────────────────────────────────────

@test "exe refuses the binary at the named path, not the same bytes elsewhere, and the alert names the workload" {
    local before out pid
    before="$(_denials fw-wl-exe)"
    out="$(_run "$PYCOPY" 7201)"
    _expect refused "$out" "the named copy on 7201"
    assert_contains "$out" "EPERM"
    pid="${out##* }"
    [ "$(_denials fw-wl-exe)" -gt "$before" ]

    out="$(_run "$SYS_PYTHON" 7201)"
    _expect ok "$out" "the system python3 on 7201"

    run wait_for_alert ".[] | select(.rule_id == \"fw-wl-exe\" and .workload.pid == ${pid})" 15 1
    [ "$status" -eq 0 ] || {
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.rule_id == "fw-wl-exe")]' >&3
        false
    }
    local alert="$output"
    [ "$(echo "$alert" | jq -r '.action')" = "block" ]
    [ "$(echo "$alert" | jq -r '.dst_port')" = "7201" ]
    [ "$(echo "$alert" | jq -r '.workload.exe')" = "$PYCOPY" ]
    [ "$(echo "$alert" | jq -r '.workload.exe_hash')" = "sha256:$(sha256sum "$PYCOPY" | cut -d' ' -f1)" ]
    assert_contains "$(echo "$alert" | jq -r '.message')" "workload rule fw-wl-exe refused pid ${pid}"
}

@test "exe_hash refuses the marked bytes under two paths and lets other bytes through at both" {
    local out
    out="$(_run "$PYMARK" 7202)"
    _expect refused "$out" "the marked copy on 7202"
    out="$(_run "$PYMARK_MOVED" 7202)"
    _expect refused "$out" "the marked copy moved on 7202"
    out="$(_run "$PYPLAIN_MOVED" 7202)"
    _expect ok "$out" "an unmarked copy on 7202"
    out="$(_run "$PYCOPY" 7202)"
    _expect ok "$out" "the plain copy on 7202"
}

@test "unit refuses a task in the named scope and not outside it" {
    command -v systemd-run >/dev/null 2>&1 \
        || env_skip "systemd-run is not installed on this host"
    [ -d /run/systemd/system ] || env_skip "this host does not run systemd"

    local out
    out="$(PYTHONHOME="$PYTHONHOME_DIR" systemd-run --quiet --scope --unit=ebpf-wl-unit \
        "$SYS_PYTHON" "${DATA_DIR}/client.py" "$EBPF_NS_IP" 7203)"
    _expect refused "$out" "the client in ebpf-wl-unit.scope on 7203"
    out="$(_run "$SYS_PYTHON" 7203)"
    _expect ok "$out" "the client outside the scope on 7203"
}

@test "cgroup refuses a task in a cgroup created after the agent started" {
    local out
    out="$(_run_in_cgroup ebpf-wl-cgroup 7204)"
    _expect refused "$out" "the client in /ebpf-wl-cgroup on 7204"
    out="$(_run "$SYS_PYTHON" 7204)"
    _expect ok "$out" "the client outside the cgroup on 7204"
}

@test "a rule with no mode observes: the connect goes through and the alert would refuse" {
    local out pid
    out="$(_run "$PYCOPY" 7205)"
    _expect ok "$out" "the observed copy on 7205"
    pid="${out##* }"

    run wait_for_alert ".[] | select(.rule_id == \"fw-wl-observe\" and .workload.pid == ${pid})" 15 1
    [ "$status" -eq 0 ]
    [ "$(echo "$output" | jq -r '.action')" = "alert" ]
    assert_contains "$(echo "$output" | jq -r '.message')" "workload rule fw-wl-observe would refuse pid ${pid}"
}

@test "fqdn opens the resolved address for the cgroup that asked, and not before" {
    local out
    out="$(_run_in_cgroup ebpf-wl-fqdn 7206)"
    _expect refused "$out" "7206 before any answer"

    out="$(_run_in_cgroup ebpf-wl-fqdn 7206 allowed.wl.test)"
    _expect ok "$out" "7206 after resolving allowed.wl.test"

    # The rest of the cgroup's traffic stays refused.
    out="$(_run_in_cgroup ebpf-wl-fqdn 7204)"
    _expect refused "$out" "7204 from the named cgroup"

    run api_get /api/v1/firewall/workload/fqdn
    [ "$status" -eq 0 ]
    local rule
    rule="$(echo "$output" | jq -c '.rules[] | select(.rule == "fw-wl-by-name")')"
    [ -n "$rule" ] || {
        echo "# $output" >&3
        false
    }
    [ "$(echo "$rule" | jq -r '.patterns[0].pattern')" = "allowed.wl.test" ]
    [ "$(echo "$rule" | jq -r '.patterns[0].names[0].name')" = "allowed.wl.test" ]
    [ "$(echo "$rule" | jq -r '.patterns[0].names[0].addresses')" -ge 1 ]
    [ "$(echo "$rule" | jq -r '.patterns[0].names[0].workloads')" -ge 1 ]
}

@test "the label reading lists no container on a host whose containers carry no policy" {
    run api_get /api/v1/firewall/workload/labels
    [ "$status" -eq 0 ]
    [ "$(echo "$output" | jq -r '.containers | length')" = "0" ]
}
