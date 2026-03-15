#!/usr/bin/env bats
# 06-ebpf-programs.bats — eBPF program loading and attachment tests
# Requires: CAP_BPF or root, kernel >= 6.1, bpftool, ip

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
            skip "Agent binary not found: ${AGENT_BIN}"
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

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        ip link delete "$VETH_NAME" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "readyz reports ebpf_loaded: true" {
    require_root

    # Wait for eBPF programs to load (may take a moment)
    local attempts=0
    local max_attempts=30
    local ebpf_loaded="false"

    while [ "$attempts" -lt "$max_attempts" ]; do
        local body
        body="$(api_get /readyz)" || true
        ebpf_loaded="$(echo "$body" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
        if [ "$ebpf_loaded" = "true" ]; then
            break
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    [ "$ebpf_loaded" = "true" ]
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
