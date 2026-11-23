#!/usr/bin/env bats
# 142-auto-capture.bats - an alert at or above the configured severity starts
# a packet capture on the address it names; one below it does not.
#
# 49 covers captures an operator asks for. This suite covers the one nobody
# asks for, started by the alert pipeline:
#
#   * a medium IDS alert, under `min_severity: high`, starts nothing;
#   * a critical IDS alert starts one capture, on the configured interface,
#     filtered on the alert's source address;
#   * the capture ends on its own after `duration_secs` and leaves a pcap
#     tcpdump reads, holding the source's packets and no other host's.
#
# Requires: root, kernel >= 6.18, ncat, jq, tcpdump.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool ncat
    require_tool jq
    require_tool tcpdump

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-auto-capture-$$"
    mkdir -p "$DATA_DIR" /var/lib/ebpfsentinel/captures

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-auto-capture.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs not loaded (degraded mode)" >&2
        return 1
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -f /var/lib/ebpfsentinel/captures/auto-*.pcap 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-auto-capture-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

_captures() {
    api_get /api/v1/captures | jq -c '.captures // []'
}

# _drive <port> <seconds> - connections from the namespace to the host port,
# one every half second, for as long as asked.
_drive() {
    local port="$1" until=$((SECONDS + $2))
    timeout $(($2 + 2)) ncat -lk "$EBPF_HOST_IP" "$port" >/dev/null 2>&1 &
    local listener=$!
    sleep 0.3
    while [ "$SECONDS" -lt "$until" ]; do
        send_tcp_from_ns "$EBPF_HOST_IP" "$port" "AUTO-CAPTURE-${port}" 1
        sleep 0.5
    done
    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true
}

@test "an alert below the threshold starts no capture" {
    _drive 4445 2
    wait_for_alert '.[] | select(.rule_id == "ids-capture-medium") | .id' 20 >/dev/null || {
        echo "the medium alert never fired, so the test proves nothing" >&2
        return 1
    }
    sleep 2
    [ "$(_captures | jq 'map(select(.id | startswith("auto-"))) | length')" -eq 0 ] || {
        echo "a capture started on a medium alert: $(_captures)" >&2
        return 1
    }
}

@test "a critical alert starts one capture on its source, on the configured interface" {
    # Shorter than the capture, so every later alert lands while it runs and
    # is the one the pipeline declines to start a second capture for.
    _drive 4444 4 &
    local driver=$!
    wait_for_alert '.[] | select(.rule_id == "ids-capture-critical") | .id' 20 >/dev/null || {
        kill "$driver" 2>/dev/null || true
        echo "the critical alert never fired" >&2
        return 1
    }
    local attempt capture=""
    for attempt in $(seq 1 10); do
        capture="$(_captures | jq -c 'map(select(.id | startswith("auto-"))) | .[0] // empty')"
        [ -n "$capture" ] && break
        sleep 0.5
    done
    wait "$driver" 2>/dev/null || true
    echo "$capture" > "${DATA_DIR}/capture.json"
    echo "$capture" | jq -e --arg src "$EBPF_NS_IP" --arg iface "$EBPF_VETH_HOST" '
        .filter == "host \($src)" and .interface == $iface and .duration_secs == 6
    ' >/dev/null || {
        echo "not the capture asked for: ${capture:-none}" >&2
        return 1
    }
    [ "$(_captures | jq 'map(select(.id | startswith("auto-"))) | length')" -eq 1 ]
}

@test "the capture ends on its own and holds the source's packets and no other host's" {
    local id path status="" attempt
    id="$(jq -r '.id' "${DATA_DIR}/capture.json")"
    path="$(jq -r '.output_path' "${DATA_DIR}/capture.json")"
    for attempt in $(seq 1 20); do
        status="$(_captures | jq -r --arg id "$id" '.[] | select(.id == $id) | .status')"
        [ "$status" = "completed" ] && break
        sleep 1
    done
    [ "$status" = "completed" ] || {
        echo "capture ${id} is ${status:-gone}, not completed" >&2
        return 1
    }
    [ -s "$path" ]
    local all ours
    all="$(tcpdump -nr "$path" 2>/dev/null | wc -l)"
    ours="$(tcpdump -nr "$path" "host ${EBPF_NS_IP} and tcp port 4444" 2>/dev/null | wc -l)"
    [ "$ours" -ge 1 ] && [ "$ours" -eq "$all" ] || {
        echo "pcap holds ${all} packets, ${ours} of them the source's on 4444" >&2
        tcpdump -nr "$path" 2>/dev/null | head -5 >&2
        return 1
    }
}
