#!/usr/bin/env bats
# 147-ddos-half-open-released.bats - The half-open guard counts handshakes in progress
# Requires: root, kernel >= 6.12, bpftool, ncat, taskset
#
# ddos.connection_tracking.half_open_threshold caps the handshakes one source
# has in progress. A handshake that completes gives its slot back, so a source
# opening many connections one after another is never refused; one the node
# never sees end (here: a SYN a closed port answered with a reset) stops
# counting once its count has aged. The guard counts per CPU, so every client
# runs on one CPU: the SYN and the ACK of a handshake are counted on the same
# one, and the threshold is the one configured. A veth pair may still receive
# on another CPU now and then, so the refusal test fills every CPU's count
# rather than assuming one.

load '../lib/helpers'
load '../lib/ebpf_helpers'

OPEN_PORT=9976
CLOSED_PORT=9977
THRESHOLD=5
# The count halves every 10 seconds: one halving brings THRESHOLD under it,
# and 25 seconds leaves room for the first halving to start late.
AGEING_WAIT=25

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat
    require_tool taskset

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-half-open-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ddos-half-open.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    wait_for_ebpf_counters DDOS_METRICS 30 || return 1

    # A listener that accepts any number of connections and lets each close
    # when its client does.
    timeout 900 ncat -lk "$EBPF_HOST_IP" "$OPEN_PORT" </dev/null >/dev/null 2>&1 3>&- &
    echo $! >"${DATA_DIR}/listener.pid"
    sleep 1
}

teardown_file() {
    if [ -f "${DATA_DIR:-}/listener.pid" ]; then
        xargs -r kill <"${DATA_DIR}/listener.pid" 2>/dev/null || true
    fi
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-half-open-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

# connect_once <port> - one connection from the namespace on CPU 0, closed
# as soon as it is open. Succeeds when the handshake completed in 3 seconds.
connect_once() {
    ip netns exec "$EBPF_TEST_NS" \
        taskset -c 0 timeout 3 ncat -w 3 "$EBPF_HOST_IP" "$1" </dev/null >/dev/null 2>&1
}

# ── Completed handshakes ───────────────────────────────────────────

@test "a source that completes its handshakes is never refused, however many it opens" {
    require_root

    local before after i ok=0
    before="$(ebpf_counter DDOS_METRICS half_open_drops)"
    for i in $(seq 1 $((THRESHOLD * 6))); do
        connect_once "$OPEN_PORT" && ok=$((ok + 1))
    done
    echo "completed=${ok} of $((THRESHOLD * 6))"
    [ "$ok" -eq $((THRESHOLD * 6)) ] || {
        echo "completed handshakes were held against the source" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
    # Wait one poll so the counter is the datapath's, then check it stayed.
    sleep 11
    after="$(ebpf_counter DDOS_METRICS half_open_drops)"
    [ "${after:-0}" -eq "${before:-0}" ]
}

# ── Handshakes the node never sees end ─────────────────────────────

@test "a source past the half-open ceiling is refused" {
    require_root

    local before after i sent=0 ceiling
    before="$(ebpf_counter DDOS_METRICS half_open_drops)"
    # A closed port answers each SYN with a reset that leaves by the egress
    # path, which this program does not see: every one stays half open.
    for i in $(seq 1 "$THRESHOLD"); do
        connect_once "$CLOSED_PORT" || true
    done
    sent=$THRESHOLD
    # The count is per CPU, and a veth pair does not always run its receive
    # on the CPU the client is pinned to, so a SYN can land on another one.
    # Every CPU at its ceiling is reached in at most THRESHOLD SYNs per CPU;
    # past that, the source is refused wherever its next SYN lands.
    ceiling=$((THRESHOLD * $(nproc)))
    while connect_once "$OPEN_PORT"; do
        if [ "$sent" -ge "$ceiling" ]; then
            echo "the source passed a half-open ceiling it was past on every CPU" >&2
            dump_ebpf_counters DDOS_METRICS >&2
            bpftool -j map dump name HALF_OPEN_COUNT >&2 || true
            return 1
        fi
        connect_once "$CLOSED_PORT" || true
        sent=$((sent + 1))
    done
    echo "refused after ${sent} handshakes left half open"
    after="$(ebpf_counter_above DDOS_METRICS half_open_drops "${before:-0}")"
    [ "$after" -gt "${before:-0}" ]
}

@test "a refused source is admitted again once its half-open count has aged" {
    require_root

    # The test before left the source past its ceiling.
    sleep "$AGEING_WAIT"
    connect_once "$OPEN_PORT" || {
        echo "handshakes the node never saw end still refuse the source" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
}
