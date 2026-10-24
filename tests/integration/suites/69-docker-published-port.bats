#!/usr/bin/env bats
# 69-docker-published-port.bats - a port Docker publishes is filtered before Docker translates it
# Requires: root, docker, bpftool, curl, tcpdump, iptables, ip
#
# Docker publishes a container port with a DNAT rule in PREROUTING, so a
# packet to the published port is routed to the container through FORWARD
# and a DROP in the host's INPUT chain never sees it. The suite shows that
# first, then starts the agent with a deny rule naming the client and the
# published port, and proves with a capture on the Docker bridge that the
# refused packets never reach the container.
#
# Topology:
#   ebpf-test-ns (10.200.0.2) --veth--> host (10.200.0.1) --DNAT--> docker0 --> container:80
#   The agent's XDP firewall is attached to the host side of the veth.

load '../lib/helpers'
load '../lib/ebpf_helpers'

PUBLISHED_PORT=18069
SERVER_IMAGE="${DOCKER_PUBLISHED_PORT_IMAGE:-busybox:1.37}"
SERVER_CONTAINER="ebpfsentinel-published-port-$$"

# reach - prints the body the container serves when the client gets through,
# nothing otherwise.
reach() {
    ip netns exec "$EBPF_TEST_NS" \
        curl -s --max-time 3 "http://${EBPF_HOST_IP}:${PUBLISHED_PORT}/" 2>/dev/null || true
}

# captured_on_bridge <file> - number of packets from the client that a
# capture on the Docker bridge recorded while one attempt was made.
captured_on_bridge() {
    local pcap="${1:?usage: captured_on_bridge <file>}"
    tcpdump -i "$BRIDGE" -nn -U -w "$pcap" "tcp and src host ${EBPF_NS_IP}" >/dev/null 2>&1 &
    local capture=$!
    sleep 1
    reach >/dev/null
    sleep 1
    kill "$capture" 2>/dev/null || true
    wait "$capture" 2>/dev/null || true
    tcpdump -nn -r "$pcap" 2>/dev/null | wc -l
}

setup_file() {
    require_root
    require_kernel 6 12
    require_tool docker
    require_tool bpftool
    require_tool curl
    require_tool tcpdump
    require_tool iptables

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-docker-port-$$"
    export RESULTS="${BATS_FILE_TMPDIR}/results"
    mkdir -p "$DATA_DIR" "$RESULTS"

    docker info >/dev/null 2>&1 || env_skip "docker daemon not reachable"
    docker pull -q "$SERVER_IMAGE" >/dev/null 2>&1 || env_skip "cannot pull ${SERVER_IMAGE}"

    create_test_netns

    docker run -d --rm --name "$SERVER_CONTAINER" -p "${PUBLISHED_PORT}:80" "$SERVER_IMAGE" \
        sh -c 'mkdir -p /www && echo reached > /www/index.html && exec httpd -f -p 80 -h /www' \
        >/dev/null
    export BRIDGE
    BRIDGE="$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null)"
    BRIDGE="${BRIDGE:-docker0}"

    local attempt=0
    until [ "$(reach)" = "reached" ] || [ "$attempt" -ge 20 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done

    # Without the agent: the client gets through, and the bridge sees it.
    reach >"${RESULTS}/baseline-body"
    captured_on_bridge "${RESULTS}/baseline.pcap" >"${RESULTS}/baseline-captured"

    # The rule an operator writes first, in the chain they expect it in.
    iptables -I INPUT -s "$EBPF_NS_IP" -p tcp --dport "$PUBLISHED_PORT" -j DROP
    reach >"${RESULTS}/input-drop-body"
    iptables -D INPUT -s "$EBPF_NS_IP" -p tcp --dport "$PUBLISHED_PORT" -j DROP

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-docker-published-port.yaml")"
    sed -i "s|__PUBLISHED_PORT__|${PUBLISHED_PORT}|g" "$PREPARED_CONFIG"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        return 1
    }
    sleep 2

    # With the agent: nothing gets through, and nothing reaches the bridge.
    reach >"${RESULTS}/agent-body"
    captured_on_bridge "${RESULTS}/agent.pcap" >"${RESULTS}/agent-captured"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    iptables -D INPUT -s "$EBPF_NS_IP" -p tcp --dport "$PUBLISHED_PORT" -j DROP 2>/dev/null || true
    docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-docker-port-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── The problem ───────────────────────────────────────────────────

@test "without the agent the client reaches the published port" {
    [ "$(cat "${RESULTS}/baseline-body")" = "reached" ]
}

@test "without the agent the capture on the bridge sees the client" {
    # The capture method has to see traffic when there is traffic, or its
    # zero further down proves nothing.
    [ "$(cat "${RESULTS}/baseline-captured")" -ge 1 ]
}

@test "a DROP in the INPUT chain does not stop it, because Docker translated it first" {
    [ "$(cat "${RESULTS}/input-drop-body")" = "reached" ]
}

# ── The agent ─────────────────────────────────────────────────────

@test "XDP firewall is attached to the client-facing interface" {
    run bpftool net show dev "$EBPF_VETH_HOST"
    assert_contains "$output" "xdp"
}

@test "with the agent the client no longer reaches the published port" {
    [ -z "$(cat "${RESULTS}/agent-body")" ]
}

@test "with the agent nothing from the client reaches the Docker bridge" {
    [ "$(cat "${RESULTS}/agent-captured")" -eq 0 ]
}
