#!/usr/bin/env bats
# 85-encryption-over-the-network.bats - the writes this host pushes to file
# shares, read off its own flows, and what that reading cannot see.
#
# The suite asserts:
#
#   * A server this host wrote to while the history was learned stays quiet
#     however much it receives afterwards.
#   * One process writing to three servers it never wrote to raises one
#     alert naming every server, the SMB port and the bytes each received.
#   * The same writes behind the SMB 3 transform header, the way a session
#     that seals its messages sends them, raise the same alert, and the
#     alert says its reading is degraded to volume, server count and timing.
#
# The servers are addresses inside the test namespace with a listener on
# port 445 that reads and discards: what is read is this host's side of the
# flow, so no file service is needed on the far end. The receiving host's
# side, where a file service writing on a remote client's behalf names the
# client by its address, and the folding of both sides into one incident
# across an estate are asserted by the unit tests of the receiving reading
# and of the enterprise estate correlation, since a lane of single hosts
# has no second agent to correlate with.
#
# Requires: root, python3, jq, nft, ip

load '../lib/helpers'
load '../lib/ebpf_helpers'

# The fixture's learning period, and how long a window stays open.
LEARNING_SECS=5
WINDOW_SECS=8
# A write reaches the reading once the conntrack poll (2 s) has seen it, the
# flow has been idle for a second and the collector's one-second tick has
# ended it: up to about four seconds after the bytes left. Every wait that
# must land past a learning period or a window adds this.
READING_LAG_SECS=6
# Above the fixture's 64 KiB per server.
WRITE_BYTES=262144
LEARNED="10.200.0.20"
CLEAR_SERVERS=("10.200.0.21" "10.200.0.22" "10.200.0.23")
SEALED_SERVERS=("10.200.0.31" "10.200.0.32" "10.200.0.33")

setup_file() {
    require_root
    require_tool python3
    require_tool jq
    require_tool nft

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 85 writes from the agent's own host (local lane only)"
    fi

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    local server
    for server in "${LEARNED}" "${CLEAR_SERVERS[@]}" "${SEALED_SERVERS[@]}"; do
        ip netns exec "$EBPF_TEST_NS" ip addr add "${server}/32" dev "$EBPF_VETH_NS"
    done
    _start_sink

    # The host's conntrack table only follows a connection once something
    # hooks it; a stateful rule that accepts everything is that something.
    nft add table inet ebpfsentinel_suite85
    nft add chain inet ebpfsentinel_suite85 out '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet ebpfsentinel_suite85 out ct state new counter accept

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-share-writes.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    # The learning period starts at the first write the agent sees: the
    # one server written to now is the history.
    _write clear "${LEARNED}"
    sleep $((LEARNING_SECS + READING_LAG_SECS))
}

teardown_file() {
    [ -n "${SINK_PID:-}" ] && kill "${SINK_PID}" 2>/dev/null
    nft delete table inet ebpfsentinel_suite85 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _start_sink - one listener on port 445 for every address in the
# namespace, reading and discarding what it is sent.
_start_sink() {
    ip netns exec "$EBPF_TEST_NS" python3 - <<'PY' >/dev/null 2>&1 &
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 445))
s.listen(64)
def drain(c):
    with c:
        while c.recv(65536):
            pass
while True:
    c, _ = s.accept()
    threading.Thread(target=drain, args=(c,), daemon=True).start()
PY
    SINK_PID=$!
    export SINK_PID
    local attempt=0
    while [ "$attempt" -lt 50 ]; do
        ip netns exec "$EBPF_TEST_NS" ss -tlnH "sport = :445" 2>/dev/null | grep -q . && return 0
        sleep 0.1
        attempt=$((attempt + 1))
    done
    return 1
}

# _write <clear|sealed> <server>... - one SMB session's worth of writes to
# each <server>, all from one process, the way one encrypting program walks
# the shares it can reach: SMB 2 WRITE requests in the clear, or the same
# volume behind the SMB 3 transform header with nothing readable after it.
# The node names the writer by its process, so writes spread over several
# processes are several writers, each with its own window.
_write() {
    python3 - "${WRITE_BYTES}" "$@" <<'PY'
import os, socket, struct, sys
total, mode, servers = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
chunk = 16384
for server in servers:
    with socket.create_connection((server, 445), timeout=5) as s:
        sent = 0
        while sent < total:
            if mode == "clear":
                # SMB 2 header, command 0x0009 (WRITE), then the data.
                header = b"\xfeSMB" + struct.pack("<HHIHH", 64, 0, 0, 9, 0) + bytes(52)
            else:
                # SMB 3 transform header: signature, nonce, size, flags, session.
                header = b"\xfdSMB" + os.urandom(16) + os.urandom(16) + struct.pack("<IHHQ", chunk, 0, 1, 1)
            body = header + os.urandom(chunk)
            s.sendall(struct.pack(">I", len(body)) + body)
            sent += len(body)
PY
}

# _alert_for <server> - the share writes alert naming <server>, once raised.
_alert_for() {
    wait_for_alert "[.[] | select(.rule_id == \"share-writes-to-new-peers\" and (.message | contains(\"$1:445\")))] | last" 20 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a server written to while the history was learned stays quiet" {
    _write clear "${LEARNED}" "${LEARNED}"
    sleep "${READING_LAG_SECS}"
    run _alert_for "${LEARNED}"
    [ "$status" -ne 0 ]
}

@test "writes to three new servers name every one of them" {
    _write clear "${CLEAR_SERVERS[@]}"
    local alert
    local server
    alert="$(_alert_for "${CLEAR_SERVERS[0]}")"
    for server in "${CLEAR_SERVERS[@]}"; do
        jq -e --arg s "${server}:445" '.message | contains($s)' <<<"${alert}"
    done
    jq -e '.message | contains("over SMB to 3 file servers this host had never written to")' <<<"${alert}"
    [ "$(jq -r '.component' <<<"${alert}")" = "share_writes" ]
    [ "$(jq -r '.dst_port' <<<"${alert}")" = "445" ]
    jq -e '.message | contains("'"${LEARNED}"':445") | not' <<<"${alert}"
}

@test "sealed SMB sessions raise the same alert and say the reading is degraded" {
    # The window the cleartext writes opened closes first, so this one is
    # a window of its own.
    sleep $((WINDOW_SECS + READING_LAG_SECS))
    _write sealed "${SEALED_SERVERS[@]}"
    local alert
    local server
    alert="$(_alert_for "${SEALED_SERVERS[0]}")"
    for server in "${SEALED_SERVERS[@]}"; do
        jq -e --arg s "${server}:445" '.message | contains($s)' <<<"${alert}"
    done
    jq -e '.message | contains("degraded reading: volume, server count and timing only")' <<<"${alert}"
    jq -e '.message | contains("no SMB operation or content was read")' <<<"${alert}"
    # It never claims what it cannot see.
    jq -e '.message | ascii_downcase | contains("encrypted") | not' <<<"${alert}"
}
