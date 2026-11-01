#!/usr/bin/env bats
# 76-firewall-shadow.bats - a rule in shadow mode counts what it would have
# done and decides nothing.
#
# The suite asserts:
#
#   * A shadow deny on ICMP leaves ping working, and counts the echo
#     requests as packets the live policy decided otherwise, with the flow
#     in its sample under the live verdict `allow`.
#   * A shadow allow on a port the live policy drops leaves the connection
#     refused, and counts it the other way round, under the live verdict
#     `deny`.
#   * A shadow rule nothing matches reads zero, installed.
#   * Adding a shadow rule restarts the counters and moves the moment they
#     count from.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool ncat
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 76 sends its traffic from the local namespace (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-fw-shadow-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-firewall-shadow.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-fw-shadow-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_shadow() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/firewall/shadow"
}

_reading() {
    _shadow | jq -c --arg r "$1" '.rules[] | select(.rule_id == $r)'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the rules listing names the shadow rules by their mode" {
    local listing
    listing="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/firewall/rules")"
    [ "$(jq -r '.[] | select(.id == "fw-shadow-deny-icmp") | .mode' <<<"${listing}")" = "shadow" ]
    [ "$(jq -r '.[] | select(.id == "fw-deny-tcp-range") | .mode' <<<"${listing}")" = "enforce" ]
}

@test "a shadow deny leaves ping working and counts it as changed" {
    run ip netns exec "${EBPF_TEST_NS}" ping -c 5 -W 1 -i 0.2 "${EBPF_HOST_IP}"
    echo "${output}" >&2
    [ "$status" -eq 0 ]

    local reading
    reading="$(_reading fw-shadow-deny-icmp)"
    echo "reading: ${reading}" >&2
    [ "$(jq -r '.installed' <<<"${reading}")" = "true" ]
    [ "$(jq -r '.would' <<<"${reading}")" = "deny" ]
    [ "$(jq -r '.packets' <<<"${reading}")" -ge 5 ]
    [ "$(jq -r '.changed_packets' <<<"${reading}")" -ge 5 ]
    [ "$(jq -r '.flows' <<<"${reading}")" -ge 1 ]
    [ "$(jq -r '.changed_flows' <<<"${reading}")" -ge 1 ]
    [ "$(jq -r '.sample[0].src_ip' <<<"${reading}")" = "${EBPF_NS_IP}" ]
    [ "$(jq -r '.sample[0].live_verdict' <<<"${reading}")" = "allow" ]
}

@test "a shadow allow leaves a dropped connection dropped and counts it as changed" {
    ncat -l -p 9995 --max-conns 1 &>/dev/null &
    local listener_pid=$!
    sleep 0.3
    local exit_code=0
    ip netns exec "${EBPF_TEST_NS}" \
        timeout 3 ncat -w 2 "${EBPF_HOST_IP}" 9995 </dev/null 2>&1 || exit_code=$?
    kill "${listener_pid}" 2>/dev/null || true
    wait "${listener_pid}" 2>/dev/null || true
    [ "${exit_code}" -ne 0 ]

    local reading
    reading="$(_reading fw-shadow-allow-tcp-9995)"
    echo "reading: ${reading}" >&2
    [ "$(jq -r '.would' <<<"${reading}")" = "allow" ]
    [ "$(jq -r '.changed_packets' <<<"${reading}")" -ge 1 ]
    [ "$(jq -r '.sample[0].dst_port' <<<"${reading}")" = "9995" ]
    [ "$(jq -r '.sample[0].live_verdict' <<<"${reading}")" = "deny" ]
}

@test "a shadow rule nothing matched reads zero and is installed" {
    local reading
    reading="$(_reading fw-shadow-deny-udp-1)"
    echo "reading: ${reading}" >&2
    [ "$(jq -r '.installed' <<<"${reading}")" = "true" ]
    [ "$(jq -r '.packets' <<<"${reading}")" -eq 0 ]
    [ "$(jq -r '.sample | length' <<<"${reading}")" -eq 0 ]
}

@test "adding a shadow rule restarts the counters" {
    local before after
    before="$(_shadow | jq -r '.counting_since_ns')"
    [ "${before}" -gt 0 ]

    curl -sf --max-time "${HTTP_TIMEOUT}" -X POST -H 'Content-Type: application/json' \
        -d '{"id":"fw-shadow-added","priority":8,"action":"deny","protocol":"udp","dst_port":2,"mode":"shadow"}' \
        "${BASE_URL}/api/v1/firewall/rules" >/dev/null

    after="$(_shadow | jq -r '.counting_since_ns')"
    echo "before ${before} after ${after}" >&2
    [ "${after}" -gt "${before}" ]
    [ "$(_reading fw-shadow-deny-icmp | jq -r '.packets')" -eq 0 ]
    [ "$(_reading fw-shadow-added | jq -r '.installed')" = "true" ]

    curl -sf --max-time "${HTTP_TIMEOUT}" -X DELETE \
        "${BASE_URL}/api/v1/firewall/rules/fw-shadow-added" >/dev/null
}
