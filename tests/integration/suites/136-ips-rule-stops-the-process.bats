#!/usr/bin/env bats
# An IPS rule in block mode that asks for it stops the process behind the
# flow it blocks.
#
# A copy of ncat on the agent's host dials a listener in the test namespace
# on 4444, the port the suite's block rule names with `kill_process: true`.
# The alert must name that copy as the flow's process, and the copy must be
# gone once the alert is raised. A second copy dialing 4445, under a block
# rule that does not ask for it, is blocked and keeps running.
#
# Requires: root, kernel >= 6.12, jq, ncat.

load '../lib/helpers'
load '../lib/ebpf_helpers'

KILL_PORT=4444
KEEP_PORT=4445

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 136 dials from the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ips-kill-$$"
    mkdir -p "$DATA_DIR"
    cp "$(readlink -f "$(command -v ncat)")" "${DATA_DIR}/ips-dialer"
    chmod 0755 "${DATA_DIR}/ips-dialer"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ips.yaml")"
    export PREPARED_CONFIG
    python3 - "$PREPARED_CONFIG" "$KILL_PORT" "$KEEP_PORT" <<'PY'
import sys
path, kill, keep = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
def rep(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)
# The dial leaves the host through the veth's egress, where the rules match
# only once egress is inspected.
rep("ids:\n  enabled: true\n", "ids:\n  enabled: true\n  inspect_egress: true\n")
rep("""      dst_port: 4444
      mode: block
      enabled: true
""", f"""      dst_port: {kill}
      mode: block
      enabled: true
      kill_process: true

    - id: ips-keep-dialer-block
      description: "Block without stopping the dialer"
      severity: high
      protocol: tcp
      dst_port: {keep}
      mode: block
      enabled: true
""")
text += """
process_table:
  enabled: true

attribution:
  enabled: true

response:
  kill_process:
    enabled: true
"""
open(path, "w").write(text)
PY

    local port
    for port in "$KILL_PORT" "$KEEP_PORT"; do
        ip netns exec "$EBPF_TEST_NS" ncat -lk "$EBPF_NS_IP" "$port" \
            </dev/null >/dev/null 2>&1 3>&- &
        echo $! > "${DATA_DIR}/listen-${port}.pid"
    done

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    # The flow is named from the exec the process table saw, so the table
    # has to be attached before any dialer starts.
    wait_for_ebpf_program tracepoint-process 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    sleep 2
}

teardown_file() {
    local f
    for f in "${DATA_DIR}"/*.pid; do
        [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
    done
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ips-kill-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _dial <port> - a copy of ncat holding a connection to the namespace and
# sending a line a second; prints its pid.
_dial() {
    (while true; do echo probe; sleep 1; done) \
        | "${DATA_DIR}/ips-dialer" "$EBPF_NS_IP" "$1" >/dev/null 2>&1 3>&- &
    echo $! | tee "${DATA_DIR}/dial-$1.pid"
}

# A prevention rule reports under the IPS component, not the IDS one.
_alert_on() {
    wait_for_alert "[.[] | select(.rule_id == \"$1\" and .component == \"ips\")] | first" 20 1
}

@test "the rule that asks for it is loaded in block mode with kill_process" {
    api_get /api/v1/ips/rules | jq -e '[(.rules? // .)[] | select(.id == "ips-reverse-shell-block")] | length == 1' >/dev/null
}

@test "a blocked flow's process is named and stopped" {
    local pid
    pid="$(_dial "$KILL_PORT")"
    run _alert_on ips-reverse-shell-block
    [ "$status" -eq 0 ] || {
        grep -i 'process kill' "$AGENT_LOG_FILE" | tail -5 >&3
        false
    }
    echo "$output" | jq -c '{rule_id, component, workload}'
    [ "$(echo "$output" | jq -r '.workload.pid // empty')" = "$pid" ]

    local i
    for i in $(seq 1 20); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
        grep -i 'process kill' "$AGENT_LOG_FILE" | tail -5 >&3
        false
    fi
    grep -q 'process kill: decided' "$AGENT_LOG_FILE"
}

@test "a block rule that does not ask for it leaves the process running" {
    local pid
    # Started from this shell rather than a substitution, so it is a child
    # whose exit status can be read.
    _dial "$KEEP_PORT" >/dev/null
    pid="$(cat "${DATA_DIR}/dial-${KEEP_PORT}.pid")"
    run _alert_on ips-keep-dialer-block
    [ "$status" -eq 0 ]
    sleep 3
    # The block cuts the connection, and ncat may leave on its own once its
    # peer is gone; what the rule must not do is stop it. A process the
    # agent stops dies of SIGKILL and leaves a decision in the log.
    if ! kill -0 "$pid" 2>/dev/null; then
        local rc=0
        wait "$pid" 2>/dev/null || rc=$?
        [ "$rc" -ne 137 ] || {
            echo "the dialer died of SIGKILL" >&2
            false
        }
    fi
    kill "$pid" 2>/dev/null || true
    ! grep 'process kill' "$AGENT_LOG_FILE" | grep -q 'ips-keep-dialer-block'
}
