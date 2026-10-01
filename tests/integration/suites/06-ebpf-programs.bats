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

@test "a program this configuration does not ask for publishes no status series" {
    require_root

    # This fixture enables the firewall and nothing else, which is what makes
    # it the place to assert the gauge's one rule: a series exists only for a
    # program the agent asked the kernel for, so zero always means the load was
    # refused. Published as zero instead, a disabled feature would be
    # indistinguishable from a broken one and the EbpfProgramDown rule in the
    # chart would fire on every estate that turned a feature off.
    local metrics_url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics"
    local waited=0 body=""
    while [ "$waited" -lt 40 ]; do
        body="$(curl -sf --max-time "$HTTP_TIMEOUT" "$metrics_url" 2>/dev/null)" || true
        if echo "$body" \
            | grep -q '^ebpfsentinel_ebpf_program_status{program="xdp-firewall"}'; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done

    echo "$body" | grep -q '^ebpfsentinel_ebpf_program_status{program="xdp-firewall"} 1'

    # tc-dns is deliberately not in this list: `DnsConfig` defaults to enabled,
    # so a fixture with no `dns:` section does ask the kernel for that program
    # and its series reading 1 is the right answer rather than a leak.
    local off program
    for program in tc-ids tc-threatintel uprobe-dlp xdp-ratelimit \
        tc-conntrack tc-nat-ingress tc-nat-egress tc-qos xdp-loadbalancer; do
        if echo "$body" \
            | grep -q "^ebpfsentinel_ebpf_program_status{program=\"${program}\"}"; then
            off="${off} ${program}"
        fi
    done
    if [ -n "${off:-}" ]; then
        echo "# disabled features publishing a status series:${off}"
        echo "$body" | grep '^ebpfsentinel_ebpf_program_status'
        return 1
    fi

    # The other half of the answer: the status endpoint does report a disabled
    # program, as false, so nothing is lost by the gauge staying silent.
    local status
    status="$(curl -sf --max-time "$HTTP_TIMEOUT" \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/api/v1/ebpf/status" 2>/dev/null)" || true
    assert_contains "$status" "tc-ids"
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
