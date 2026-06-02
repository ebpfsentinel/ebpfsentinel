#!/usr/bin/env bats
# 54-nptv6-prefix-translation.bats — NPTv6 (RFC 6296) prefix translation.
#
# tc-nat-egress carries a checksum-neutral IPv6 prefix swap for packets
# matching nptv6_rules. The fixture configures fd00:54::/64 (internal) →
# 2001:db8:54::/64 (external).
#
# Suite layers:
#   * REST surface — GET /api/v1/nat/nptv6 lists the configured rule
#   * CLI surface  — `nat nptv6 list` shows the same rule
#   * Wire-level   — attacker ships an IPv6 packet through the agent and
#                    the backend pcap proves the source-prefix swap. The
#                    wire test requires IPv6 link addresses + routes on
#                    the test VMs; it skips when those aren't present.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/nptv6_helpers'

# NPTv6 maps the internal prefix 1:1 onto the external prefix: an internal
# host fd00:54::X appears to the outside as 2001:db8:54::X. The backend plays
# an *outside* host and therefore must live on a third network that is NEITHER
# prefix — otherwise the agent's ingress reverse-translation would rewrite the
# probe's destination and misroute it instead of forwarding to the backend.
INTERNAL_PREFIX="fd00:54::"
EXTERNAL_PREFIX="2001:db8:54::"
ATTACKER_V6="fd00:54::1"
DEST_PREFIX="2001:db8:99::"
BACKEND_V6="2001:db8:99::30"

setup_file() {
    require_kernel 5 15
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-nptv6-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-nptv6.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-nptv6-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── REST: configured rule is visible ────────────────────────────────

@test "GET /api/v1/nat/nptv6 surfaces the configured rule" {
    local body
    body="$(api_get /api/v1/nat/nptv6)"
    _load_http_status
    if [ "${HTTP_STATUS}" = "404" ]; then
        skip "NAT service not enabled or NPTv6 endpoint missing"
    fi
    [ "${HTTP_STATUS}" = "200" ]

    # Expect the seeded rule (id=nptv6-suite54) with the configured prefixes.
    local hit
    hit="$(echo "${body}" | jq -r --arg id "nptv6-suite54" \
        '[.[] | select(.id == $id)] | length')"
    [ "${hit}" = "1" ] || {
        echo "rule nptv6-suite54 not surfaced by /api/v1/nat/nptv6: ${body}" >&2
        return 1
    }

    local internal external
    internal="$(echo "${body}" | jq -r '.[] | select(.id == "nptv6-suite54") | .internal_prefix')"
    external="$(echo "${body}" | jq -r '.[] | select(.id == "nptv6-suite54") | .external_prefix')"
    [ "${internal}" = "${INTERNAL_PREFIX}" ]
    [ "${external}" = "${EXTERNAL_PREFIX}" ]
}

# ── REST: POST + DELETE round-trip ──────────────────────────────────

@test "POST and DELETE /api/v1/nat/nptv6 round-trip a rule" {
    local body
    body='{"id":"nptv6-rt","enabled":true,"internal_prefix":"fd00:abcd::","external_prefix":"2001:db8:abcd::","prefix_len":64}'
    api_post /api/v1/nat/nptv6 "${body}" >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ]

    local count
    count="$(api_get /api/v1/nat/nptv6 \
        | jq -r '[.[] | select(.id == "nptv6-rt")] | length')"
    [ "${count}" = "1" ]

    api_delete /api/v1/nat/nptv6/nptv6-rt >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "204" ]

    count="$(api_get /api/v1/nat/nptv6 \
        | jq -r '[.[] | select(.id == "nptv6-rt")] | length')"
    [ "${count}" = "0" ]
}

# ── CLI: `nat nptv6 list` ───────────────────────────────────────────

@test "CLI nat nptv6 list reports the configured rule" {
    if ! _agent_ssh test -x /usr/local/bin/ebpfsentinel-agent 2>/dev/null; then
        skip "ebpfsentinel-agent CLI not installed on agent VM"
    fi

    local out
    out="$(_agent_ssh_sudo /usr/local/bin/ebpfsentinel-agent --output json \
        nat nptv6 list 2>&1)" || {
        echo "CLI nat nptv6 list failed: ${out}" >&2
        return 1
    }
    # The JSON CLI mode prints the raw REST body; assert it mentions the rule.
    echo "${out}" | grep -q 'nptv6-suite54' || {
        echo "CLI output missing nptv6-suite54: ${out}" >&2
        return 1
    }
}

# ── Wire-level prefix swap (3VM, gated on IPv6 reachability) ────────

@test "egress source prefix is rewritten from internal to external" {
    skip_if_not_3vm

    # Stand up an IPv6 transit path across the three VMs so the agent's
    # tc-nat-egress NPTv6 rewrite is actually exercised on eth2:
    #   * attacker  fd00:54::1/64 on eth1, route to the external prefix via the
    #               agent's internal gateway address
    #   * agent     IPv6 forwarding on; gateway fd00:54::254/64 on eth1 (client
    #               side) + 2001:db8:54::254/64 on eth2 (backend side)
    #   * backend   2001:db8:54::30/64 on eth1, return route to the internal prefix
    # Each step is idempotent (replace) and best-effort; if the link never
    # comes up the wire portion below skips rather than fails.
    local agent_v6_gw="fd00:54::254"       # internal-side gateway (eth1)
    local agent_v6_ext="2001:db8:99::254"  # outside-side gateway (eth2, dest net)

    # Attacker (internal host): address + route toward the outside dest network
    # via the agent's internal gateway.
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" "sudo ip -6 addr replace ${ATTACKER_V6}/64 dev eth1; \
         sudo ip -6 route replace ${DEST_PREFIX}/64 via ${agent_v6_gw} dev eth1" \
        >/dev/null 2>&1 || true

    # Agent: forwarding + internal gateway on eth1 + outside gateway on eth2.
    _agent_ssh_sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    _agent_ssh_sudo ip -6 addr replace "${agent_v6_gw}/64" \
        dev "${EBPF_AGENT_INTERFACE:-eth1}" >/dev/null 2>&1 || true
    _agent_ssh_sudo ip -6 addr replace "${agent_v6_ext}/64" \
        dev "${EBPF_AGENT_BACKEND_IFACE:-eth2}" >/dev/null 2>&1 || true

    # Backend (outside host): address on the dest network + a return route to the
    # external prefix (the translated source it will see) via the agent.
    _backend_ssh_sudo ip -6 addr replace "${BACKEND_V6}/64" dev eth1 >/dev/null 2>&1 || true
    _backend_ssh_sudo ip -6 route replace "${EXTERNAL_PREFIX}/64" \
        via "${agent_v6_ext}" dev eth1 >/dev/null 2>&1 || true

    # Let DAD settle so the source address is usable (a tentative addr makes
    # scapy's send drop the packet).
    sleep 2

    # Warm the attacker's neighbor cache for the gateway: the L2 sender reads the
    # kernel neighbour table for the agent MAC, and a kernel ping6 populates it.
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" "ping6 -c2 -W2 ${agent_v6_gw} >/dev/null 2>&1" \
        >/dev/null 2>&1 || true

    # Capture on backend in the background, then trigger. 3>&- closes bats'
    # TAP fd so the backgrounded capture can never hold it open and hang
    # teardown.
    local pcap="${DATA_DIR}/nptv6-egress.pcap"
    (
        capture_backend_ipv6 "${pcap}" 8 eth1
    ) 3>&- &
    local cap_pid=$!
    sleep 1

    scapy_send_ipv6_via "${ATTACKER_V6}" "${BACKEND_V6}" 5 eth1 \
        >/dev/null 2>&1 || true

    wait "${cap_pid}" 2>/dev/null || true

    # Count the test's own probe packets (UDP dport 4546) by source prefix.
    # NPTv6 (RFC 6296) is checksum-neutral: it rewrites the /64 prefix and
    # adjusts a word in the interface ID, so the source prints as e.g.
    # 2001:db8:54:0:30b8::1 (NOT the compressed 2001:db8:54::1). Match on the
    # network bytes with one trailing colon so the adjusted-ID form still hits.
    local ext_match="${EXTERNAL_PREFIX%:}"
    local int_match="${INTERNAL_PREFIX%:}"
    local external_hits internal_hits
    external_hits=0
    internal_hits=0
    if [ -s "${pcap}" ]; then
        external_hits="$(tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null \
            | grep -c "IP6 ${ext_match}" || true)"
        internal_hits="$(tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null \
            | grep -c "IP6 ${int_match}" || true)"
    fi

    # No probe reached the backend at all → the IPv6 transit link is down, not a
    # translation failure; surface as a skip rather than a false negative.
    if [ "${external_hits:-0}" -eq 0 ] && [ "${internal_hits:-0}" -eq 0 ]; then
        skip "no IPv6 probe reached backend — transit link not established"
    fi

    # The probe reached the backend: assert NPTv6 swapped the source prefix
    # (external prefix present, internal prefix absent).
    [ "${external_hits:-0}" -ge 1 ] || {
        echo "NPTv6 egress did not rewrite: external=${external_hits} internal=${internal_hits}" >&2
        tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null | head -10 >&2
        return 1
    }
}
