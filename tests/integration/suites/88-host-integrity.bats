#!/usr/bin/env bats
# 88-host-integrity.bats - who else reads the node's traffic, who else sits on
# its network path, and whether the agent's own programs can be taken away.
#
# The suite asserts:
#
#   * A packet socket opened after the agent started is listed with the
#     process and executable holding it and raises one raw-socket-opened
#     alert; one carrying a classic filter is listed with the filter's
#     length.
#   * An XDP program another tool attaches is listed as foreign, on the
#     interface it was attached to, and none of the agent's own programs is.
#   * Where the kernel runs the BPF LSM, the guard reports itself protected
#     and a detach of the agent's XDP link from another process is refused,
#     the link staying where it was.
#   * With `bpf` masked out of the security modules, the guard reports the
#     node unprotected with a reason, the same detach succeeds, and the
#     inventory raises network-path-link-detached for it. The module list is
#     shown through a bind mount in a private mount namespace, as in 86.
#
# Requires: root, kernel >= 6.12, jq, python3, bpftool, unshare.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-integrity-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-host-integrity.yaml")"
    export PREPARED_CONFIG
}

teardown() {
    [ -f "${DATA_DIR}/holder.pid" ] && kill "$(cat "${DATA_DIR}/holder.pid")" 2>/dev/null
    rm -f "${DATA_DIR}/holder.pid"
    ip link del fp-dummy0 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

_start() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

# Wait for the inventory to have read at least twice: the first reading
# primes and raises nothing, so a socket opened before the second one would
# be taken for part of the node.
_wait_inventory_primed() {
    local first waited=0 now
    first="$(api_get /api/v1/ebpf/raw-sockets | jq -r '.scanned_at_ns')"
    while [ "$waited" -lt 20 ]; do
        now="$(api_get /api/v1/ebpf/raw-sockets | jq -r '.scanned_at_ns')"
        [ "$now" != "0" ] && [ "$now" != "$first" ] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Open a packet socket and hold it. With an argument, attach a classic
# filter of that many instructions, each accepting the whole packet.
_hold_packet_socket() {
    local instructions="${1:-0}"
    python3 - "$instructions" <<'PY' &
import ctypes, socket, struct, sys, time
n = int(sys.argv[1])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
if n:
    insns = b"".join(struct.pack("HBBI", 0x06, 0, 0, 0xFFFF) for _ in range(n))
    buf = ctypes.create_string_buffer(insns)
    prog = struct.pack("HL", n, ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, 26, prog)
time.sleep(120)
PY
    echo "$!" > "${DATA_DIR}/holder.pid"
}

_wait_socket_of() {
    local pid="$1" waited=0 entry=""
    while [ "$waited" -lt 20 ]; do
        entry="$(api_get /api/v1/ebpf/raw-sockets \
            | jq -c --argjson pid "$pid" '[.sockets[] | select(.pid == $pid)] | first // empty')"
        [ -n "$entry" ] && break
        sleep 1
        waited=$((waited + 1))
    done
    echo "$entry"
}

# The agent's XDP link: the link whose program is the firewall.
_agent_xdp_link() {
    local prog
    prog="$(bpftool -j prog show 2>/dev/null \
        | jq -r '[.[] | select(.name == "xdp_firewall") | .id] | first // empty')"
    [ -n "$prog" ] || return 1
    bpftool -j link show 2>/dev/null \
        | jq -r --argjson p "$prog" '[.[] | select(.prog_id == $p) | .id] | first // empty'
}

@test "a packet socket opened after start-up is listed with its holder and alerts once" {
    _start
    _wait_inventory_primed

    local body
    body="$(api_get /api/v1/ebpf/raw-sockets)"
    [ "$(echo "$body" | jq -r '.reading')" = "true" ]

    _hold_packet_socket
    local pid entry
    pid="$(cat "${DATA_DIR}/holder.pid")"
    entry="$(_wait_socket_of "$pid")"
    [ -n "$entry" ] || {
        echo "# pid ${pid} never listed: $(api_get /api/v1/ebpf/raw-sockets | jq -c .)" >&3
        false
    }
    [ "$(echo "$entry" | jq -r '.kind')" = "raw" ]
    [ "$(echo "$entry" | jq -r '.protocol')" = "all" ]
    [ "$(echo "$entry" | jq -r '.filter')" = "absent" ]
    [ "$(echo "$entry" | jq -r '.host_netns')" = "true" ]
    assert_contains "$(echo "$entry" | jq -r '.executable // ""')" "python3"

    run wait_for_alert '.[] | select(.rule_id == "raw-socket-opened") | .rule_id' 20 1
    [ "$status" -eq 0 ]
}

@test "a packet socket carrying a classic filter is listed with the filter's length" {
    _start
    _wait_inventory_primed

    _hold_packet_socket 3
    local pid entry
    pid="$(cat "${DATA_DIR}/holder.pid")"
    entry="$(_wait_socket_of "$pid")"
    [ -n "$entry" ]
    [ "$(echo "$entry" | jq -r '.filter')" = "classic" ] || {
        echo "# ${entry}" >&3
        false
    }
    [ "$(echo "$entry" | jq -r '.filter_instructions')" = "3" ]
}

@test "an XDP program another tool attaches is listed as foreign, and the agent's are not" {
    local obj="${EBPF_PROGRAM_DIR:-${PROJECT_ROOT}/target/bpfel-unknown-none/release}/xdp-pass"
    [ -f "$obj" ] || soft_skip "no xdp-pass object at $obj"
    _start
    _wait_inventory_primed

    ip link add fp-dummy0 type dummy
    ip link set fp-dummy0 up
    ip link set dev fp-dummy0 xdpgeneric obj "$obj" sec xdp

    local waited=0 body="" entry=""
    while [ "$waited" -lt 20 ]; do
        body="$(api_get /api/v1/ebpf/foreign-programs)"
        entry="$(echo "$body" | jq -c '[.programs[] | select(.interface == "fp-dummy0")] | first // empty')"
        [ -n "$entry" ] && break
        sleep 1
        waited=$((waited + 1))
    done
    [ -n "$entry" ] || {
        echo "# fp-dummy0 never listed: $(echo "$body" | jq -c .)" >&3
        false
    }
    [ "$(echo "$entry" | jq -r '.hook')" = "xdp" ]
    [ "$(echo "$body" | jq -r '.own_programs')" -gt 0 ]
    [ "$(echo "$body" | jq '[.programs[] | select(.name == "xdp_firewall")] | length')" = "0" ]
}

@test "with the BPF LSM active, a detach of the agent's XDP link is refused" {
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
        || env_skip "the BPF LSM is not among this host's security modules"
    _start

    local report waited=0
    while [ "$waited" -lt 30 ]; do
        report="$(api_get /api/v1/ebpf/kernel-features | jq -c '.self_protection')"
        [ "$(echo "$report" | jq -r '.protected')" = "true" ] && break
        sleep 1
        waited=$((waited + 1))
    done
    [ "$(echo "$report" | jq -r '.protected')" = "true" ] || {
        echo "# ${report}" >&3
        false
    }
    [ "$(echo "$report" | jq -r '.links')" -gt 0 ]
    [ "$(echo "$report" | jq -r '.maps')" -gt 0 ]

    local link
    link="$(_agent_xdp_link)"
    [ -n "$link" ]
    run bpftool link detach id "$link"
    [ "$status" -ne 0 ]
    [ "$(_agent_xdp_link)" = "$link" ]
}

@test "with bpf masked out of the modules, the node is unprotected and a detach alerts" {
    [ -r /sys/kernel/security/lsm ] || env_skip "securityfs is not mounted on this host"
    local agent="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$agent" ] || soft_skip "no local agent build at $agent"

    local fake="${DATA_DIR}/lsm"
    tr ',' '\n' </sys/kernel/security/lsm | grep -vx 'bpf' | paste -sd, - | tr -d '\n' >"$fake"
    chmod 640 "$PREPARED_CONFIG"
    setsid unshare --mount --propagation private sh -c \
        'mount --bind "$1" /sys/kernel/security/lsm && exec env EBPF_PROGRAM_DIR="$2" "$3" --config "$4"' \
        sh "$fake" "${EBPF_PROGRAM_DIR:-${PROJECT_ROOT}/target/bpfel-unknown-none/release}" "$agent" "$PREPARED_CONFIG" \
        </dev/null >"$AGENT_LOG_FILE" 2>&1 &
    echo "$!" > "$AGENT_PID_FILE"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    _wait_inventory_primed

    local report
    report="$(api_get /api/v1/ebpf/kernel-features | jq -c '.self_protection')"
    [ "$(echo "$report" | jq -r '.protected')" = "false" ]
    [ -n "$(echo "$report" | jq -r '.reason // empty')" ]

    local link
    link="$(_agent_xdp_link)"
    [ -n "$link" ]
    run bpftool link detach id "$link"
    [ "$status" -eq 0 ] || {
        echo "# detach refused without the guard: ${output}" >&3
        false
    }

    run wait_for_alert '.[] | select(.rule_id == "network-path-link-detached") | .rule_id' 20 1
    [ "$status" -eq 0 ]
}
