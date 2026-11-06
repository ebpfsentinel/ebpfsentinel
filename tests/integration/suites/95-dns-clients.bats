#!/usr/bin/env bats
# 95-dns-clients.bats - which processes may resolve, decided at the socket.
#
# The suite asserts:
#
#   * A process that is not a listed client cannot send DNS to an address
#     that is not a listed resolver: the UDP query on 53 and the TCP
#     connect on 853 are both refused with EPERM, and the refusal is an
#     alert naming the process.
#   * The same query from the listed client is answered.
#   * The same query from the unlisted process to the listed resolver is
#     answered.
#   * The block is reported with its mode, ports, resolvers and client
#     count, the rules it expands into are listed beside the operator's,
#     and what a rule on the DNS ports does not see is said in the same
#     answer.
#
# Requires: root, kernel >= 6.12, jq, python3.

load '../lib/helpers'
load '../lib/ebpf_helpers'

RESOLVER_IP="10.200.0.53"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 95 runs its clients beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dnsclients-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    ip netns exec "$EBPF_TEST_NS" ip addr add "${RESOLVER_IP}/32" dev "$EBPF_VETH_NS"

    export SYS_PYTHON PYTHONHOME_DIR PYCOPY
    SYS_PYTHON="$(readlink -f "$(command -v python3)")"
    PYTHONHOME_DIR="$("$SYS_PYTHON" -c 'import sys; print(sys.base_prefix)')"
    PYCOPY="${DATA_DIR}/dns-python"
    cp "$SYS_PYTHON" "$PYCOPY"
    chmod 0755 "$PYCOPY"

    _write_client

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dns-clients.yaml")"
    export PREPARED_CONFIG
    sed -i -e "s|__PYCOPY__|${PYCOPY}|" "$PREPARED_CONFIG"

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_program "cgroup-workload-firewall" 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "cgroup-workload-firewall did not load" >&2; return 1; }
    }

    export DNS_PID=""
    DNS_PID="$(_dns_server)"
}

teardown_file() {
    # shellcheck disable=SC2086
    kill ${DNS_PID:-} 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dnsclients-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _dns_server - answers every A query on both of the namespace's
# addresses with the namespace's own address.
_dns_server() {
    ip netns exec "$EBPF_TEST_NS" python3 - "$EBPF_NS_IP" >/dev/null 2>&1 <<'PY' &
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 53))
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

# The client waits for the agent to have read its exec, then sends one
# query over UDP to <host>:53, or opens a TCP connection to <host>:853.
# It prints "answered <pid>", "refused <errno> <pid>" or "silent <pid>".
_write_client() {
    cat > "${DATA_DIR}/client.py" <<'PY'
import errno, os, socket, struct, sys, time
host, how = sys.argv[1], sys.argv[2]
time.sleep(1.5)
pid = os.getpid()
try:
    if how == "udp":
        query = struct.pack(">HHHHHH", 4242, 0x0100, 1, 0, 0, 0)
        query += b"\x04wire\x04test\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(query, (host, 53))
        s.recv(512)
        print("answered", pid)
    else:
        socket.create_connection((host, 853), timeout=3).close()
        print("answered", pid)
except socket.timeout:
    print("silent", pid)
except OSError as e:
    print("refused", errno.errorcode.get(e.errno, e.errno), pid)
sys.stdout.flush()
time.sleep(1)
PY
}

# _run <python> <host> <udp|tcp>
_run() {
    local py="${1:?usage: _run <python> <host> <udp|tcp>}"
    shift
    PYTHONHOME="$PYTHONHOME_DIR" "$py" "${DATA_DIR}/client.py" "$@"
}

_expect() {
    local want="$1" got="$2" what="$3"
    [ "${got%% *}" = "$want" ] || {
        echo "# ${what}: expected ${want}, got: ${got}" >&3
        return 1
    }
}

# ── Tests ───────────────────────────────────────────────────────────

@test "an unlisted process cannot send DNS to an unlisted address, over 53 or 853" {
    local out pid
    out="$(_run "$SYS_PYTHON" "$EBPF_NS_IP" udp)"
    _expect refused "$out" "a UDP query to ${EBPF_NS_IP}:53"
    assert_contains "$out" "EPERM"
    pid="${out##* }"

    # Nothing listens on 853 in the namespace, so a connect the hook let
    # through would come back ECONNREFUSED rather than EPERM.
    out="$(_run "$SYS_PYTHON" "$EBPF_NS_IP" tcp)"
    _expect refused "$out" "a TCP connect to ${EBPF_NS_IP}:853"
    assert_contains "$out" "EPERM"

    run wait_for_alert ".[] | select((.rule_id | startswith(\"dns-clients-rest-\")) and .workload.pid == ${pid})" 15 1
    [ "$status" -eq 0 ] || {
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.rule_id | startswith("dns-clients"))]' >&3
        false
    }
    [ "$(echo "$output" | jq -r '.action')" = "block" ]
    [ "$(echo "$output" | jq -r '.dst_port')" = "53" ]
    [ "$(echo "$output" | jq -r '.workload.exe')" = "$SYS_PYTHON" ]
}

@test "the listed client sends DNS anywhere and is answered" {
    local out
    out="$(_run "$PYCOPY" "$EBPF_NS_IP" udp)"
    _expect answered "$out" "the listed client to ${EBPF_NS_IP}:53"
}

@test "an unlisted process is answered by the listed resolver" {
    local out
    out="$(_run "$SYS_PYTHON" "$RESOLVER_IP" udp)"
    _expect answered "$out" "the system python3 to ${RESOLVER_IP}:53"
}

@test "the block is reported with what a rule on the DNS ports does not see" {
    run api_get /api/v1/ebpf/kernel-features
    [ "$status" -eq 0 ]
    local rule
    rule="$(echo "$output" | jq -c '.workload_firewall.dns_rule')"
    [ "$rule" != "null" ] || {
        echo "# $(echo "$output" | jq -c '.workload_firewall')" >&3
        false
    }
    [ "$(echo "$rule" | jq -r '.mode')" = "enforce" ]
    [ "$(echo "$rule" | jq -c '.ports')" = "[53,853]" ]
    [ "$(echo "$rule" | jq -c '.resolvers')" = "[\"${RESOLVER_IP}/32\"]" ]
    [ "$(echo "$rule" | jq -r '.clients')" = "2" ]
    [ "$(echo "$rule" | jq -r '.not_covered | length')" = "4" ]
    echo "$rule" | jq -e '.not_covered | any(contains("DNS over HTTPS"))' >/dev/null

    run api_get /api/v1/firewall/workload/rules
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '[.rules[] | select(.rule | startswith("dns-clients-rest-"))] | length == 2' >/dev/null
    echo "$output" | jq -e '[.rules[] | select(.rule | startswith("dns-clients-resolver-"))] | length >= 1' >/dev/null
}
