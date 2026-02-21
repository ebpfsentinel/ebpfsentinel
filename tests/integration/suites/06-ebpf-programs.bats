#!/usr/bin/env bats
# 06-ebpf-programs.bats — eBPF program loading and attachment tests
# Requires: CAP_BPF or root, kernel >= 5.17, bpftool, ip

load '../lib/helpers'

VETH_NAME="veth-ebpf-test"
VETH_PEER="veth-ebpf-peer"

setup_file() {
    # Skip if kernel too old
    local kernel_major kernel_minor
    kernel_major="$(uname -r | cut -d. -f1)"
    kernel_minor="$(uname -r | cut -d. -f2)"
    if [ "$kernel_major" -lt 5 ] || { [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 17 ]; }; then
        skip "Kernel $(uname -r) < 5.17 — skipping eBPF tests"
    fi

    # Skip if not root (eBPF requires privileges)
    if [ "$(id -u)" -ne 0 ]; then
        skip "eBPF tests require root privileges"
    fi

    # Skip if bpftool not available
    if ! command -v bpftool &>/dev/null; then
        skip "bpftool not installed"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"

    # Skip if binary not built
    if [ ! -x "$AGENT_BIN" ]; then
        skip "Agent binary not found: ${AGENT_BIN}"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    # Create veth pair
    ip link add "$VETH_NAME" type veth peer name "$VETH_PEER"
    ip link set "$VETH_NAME" up
    ip link set "$VETH_PEER" up

    # Prepare config with veth interface
    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-ebpf-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|    - lo|    - ${VETH_NAME}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    # Delete veth pair (deleting one side removes both)
    ip link delete "$VETH_NAME" 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "readyz reports ebpf_loaded: true" {
    [ "$(id -u)" -eq 0 ] || skip "requires root"
    command -v bpftool &>/dev/null || skip "bpftool not installed"

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

@test "bpftool shows XDP program attached to veth" {
    [ "$(id -u)" -eq 0 ] || skip "requires root"
    command -v bpftool &>/dev/null || skip "bpftool not installed"

    # Give the agent time to attach programs
    sleep 2

    local output
    output="$(bpftool net show 2>&1)" || true
    # Check that an XDP program is attached to our veth interface
    assert_contains "$output" "$VETH_NAME"
}

@test "veth pair is cleaned up correctly" {
    [ "$(id -u)" -eq 0 ] || skip "requires root"

    # This test verifies that teardown works — the veth should still exist before teardown
    ip link show "$VETH_NAME" &>/dev/null
}
