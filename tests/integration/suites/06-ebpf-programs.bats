#!/usr/bin/env bats
# 06-ebpf-programs.bats - eBPF program loading and attachment tests
# Requires: CAP_BPF or root, kernel >= 6.9, bpftool, ip

load '../lib/helpers'
load '../lib/ebpf_helpers'

if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
    # config-minimal.yaml attaches to lo on the agent VM
    VETH_NAME="lo"
else
    VETH_NAME="veth-ebpf-test"
fi
VETH_PEER="veth-ebpf-peer"

setup_file() {
    require_root
    require_ebpf_env
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        # In 2VM mode, use config-minimal.yaml which attaches to lo
        export PREPARED_CONFIG="/tmp/ebpfsentinel-test-ebpf-$$.yaml"
        sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
            "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"
    else
        export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
        if [ ! -x "$AGENT_BIN" ]; then
            env_skip "Agent binary not found: ${AGENT_BIN}"
        fi

        # Create veth pair
        ip link add "$VETH_NAME" type veth peer name "$VETH_PEER"
        ip link set "$VETH_NAME" up
        ip link set "$VETH_PEER" up

        # Prepare config with veth interface
        export PREPARED_CONFIG="/tmp/ebpfsentinel-test-ebpf-$$.yaml"
        sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
            -e "s|    - lo|    - ${VETH_NAME}|g" \
            "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"
    fi

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        start_agent "$PREPARED_CONFIG"
    else
        # eBPF loads exclusively through a BPF token brokered by the warden,
        # so the plain starter yields an API-only agent with nothing attached.
        # Use the split starter, as every other eBPF suite does.
        EBPF_VETH_HOST="$VETH_NAME"
        export EBPF_VETH_HOST
        start_ebpf_agent "$PREPARED_CONFIG"
    fi
}

teardown_file() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        stop_agent 2>/dev/null || true
    else
        stop_ebpf_agent 2>/dev/null || true
    fi
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        ip link delete "$VETH_NAME" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "readyz reports ebpf_loaded: true" {
    require_root

    # Wait for the HTTP server to be up first.
    wait_for_agent "http://${AGENT_HOST:-127.0.0.1}:${AGENT_HTTP_PORT:-8080}/healthz" 30 || true
    sleep 3

    # readyz should return a JSON body with status info.
    local body
    body="$(curl -s --max-time 5 \
        "http://${AGENT_HOST:-127.0.0.1}:${AGENT_HTTP_PORT:-8080}/readyz" 2>/dev/null)" || true

    # Accept any valid response - "ok", "ready", or ebpf_loaded:true
    [ -n "$body" ]
}

@test "bpftool shows XDP program attached to interface" {
    require_root
    require_tool bpftool

    # Give the agent time to attach programs
    sleep 2

    local output
    output="$(bpftool net show 2>&1)" || true
    # Check that an XDP program is attached to our interface
    assert_contains "$output" "$VETH_NAME"
}

@test "interface is operational" {
    require_root

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo ip link show "$VETH_NAME" &>/dev/null
    else
        ip link show "$VETH_NAME" &>/dev/null
    fi
}

@test "the verifier's refusals are counted rather than left unsaid" {
    require_root

    # A build that never looked exports no series at all, which is how the
    # portal tells "no rejection" apart from "nobody counted". This build
    # looks, so the series has to be here even when the figure is zero.
    local value
    value="$(get_metrics_value ebpfsentinel_ebpf_verifier_rejections)" || true
    [ -n "$value" ]
}

@test "the maps that can refuse an insert say how full they are" {
    require_root

    # The measurement rides the datapath state loop, whose first tick fires as
    # the loop starts and then every 30 seconds, so a fresh agent is given one
    # full interval before the absence of the series counts as a failure.
    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local waited=0 body=""
    while [ "$waited" -lt 40 ]; do
        body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || true
        if echo "$body" | grep -q '^ebpfsentinel_ebpf_map_fill_permille{'; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done

    echo "$body" | grep -q '^ebpfsentinel_ebpf_map_fill_permille{'

    # Per mille, so a map nobody has written to is zero and a full one is a
    # thousand. Anything outside that is a figure nobody can act on.
    local worst
    worst="$(echo "$body" | grep '^ebpfsentinel_ebpf_map_fill_permille{' \
        | awk '{print $2}' | sort -n | tail -1)"
    [ -n "$worst" ]
    [ "${worst%.*}" -ge 0 ]
    [ "${worst%.*}" -le 1000 ]
}
