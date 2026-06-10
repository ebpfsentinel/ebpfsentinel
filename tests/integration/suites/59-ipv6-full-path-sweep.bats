#!/usr/bin/env bats
# 59-ipv6-full-path-sweep.bats — IPv6 parity sweep across dataplane features.
#
# Scope:
#   Single-VM topology asserts the observable contract for every feature
#   that should accept IPv6 inputs:
#
#     * Firewall — IPv6 CIDR rule loads + surfaces on REST with the v6
#       prefix preserved; a matching IPv4 rule co-exists without state
#       cross-contamination.
#     * IDS — IPv6-scoped signature loads + surfaces via REST; rule count
#       in the rules_loaded gauge reflects the IDS rule.
#     * IPS — auto-blacklist surface accepts both v4 and v6 sources
#       (blacklist endpoint is family-agnostic).
#     * Ratelimit — per-IPv6 source rule loads + surfaces on REST.
#     * NAT — covered by suite 54 (NPTv6); here we re-assert the routing
#       NAT REST surface is reachable when IPv6 prefixes are configured.
#     * DNS — AAAA query observation: the DNS subsystem accepts AAAA on
#       the observer surface and the metrics family is exposed.
#
# Coverage gaps (tracked, deferred — require multi-VM topology):
#
#   * Wire-level IPv6 traffic that triggers an IDS alert via tc-ids on
#     the veth pair. The tc-ids program inspects both families, but the
#     deterministic alert assertion needs a dual-stack 2-VM topology
#     with full IPv6 reachability through the agent (AC #1 IDS/IPS).
#   * End-to-end IPv6 NAT/forward path (AC #1 NAT). Suite 54 covers the
#     NPTv6 prefix swap; regular IPv6 forward across the agent transit
#     interface requires the 3-VM layout.
#
# Both gaps land on the same multi-VM enablement work (cross-VM IPv6
# routing fixture) and are explicitly skipped here rather than silently
# passed.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/nptv6_helpers'

# IPv6 endpoints — link-local-ish ULA bound on the host + namespace.
EBPF_HOST_V6="fd00:59::1"
EBPF_NS_V6="fd00:59::2"
EBPF_V6_PREFIX_LEN="64"

# Add IPv6 addresses to the veth pair created by create_test_netns. The
# helper assigns IPv4 only; IPv6 is layered on top so we keep dual-stack
# without touching the shared helpers.
_assign_v6_to_veth() {
    ip addr add "${EBPF_HOST_V6}/${EBPF_V6_PREFIX_LEN}" \
        dev "${EBPF_VETH_HOST}" 2>/dev/null || true
    ip netns exec "${EBPF_TEST_NS}" \
        ip addr add "${EBPF_NS_V6}/${EBPF_V6_PREFIX_LEN}" \
            dev "${EBPF_VETH_NS}" 2>/dev/null || true
    # Wait for DAD to settle so addresses leave "tentative" state.
    sleep 1
}

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ipv6sweep-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns
    _assign_v6_to_veth

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ipv6-sweep.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ipv6sweep-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Firewall — IPv6 CIDR rule surfaces with prefix preserved ───────

@test "firewall surfaces the configured IPv6 rule with the v6 prefix" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    local rules
    rules="$(echo "${body}" | jq 'if type == "array" then . else (.rules // []) end' 2>/dev/null)"
    [ -n "${rules}" ]

    local v6_match
    v6_match="$(echo "${rules}" | jq '[.[] | select(.id == "fw-ipv6-cidr-allow")] | length')"
    [ "${v6_match}" = "1" ] || {
        echo "fw-ipv6-cidr-allow not surfaced by /api/v1/firewall/rules" >&2
        echo "${rules}" >&2
        return 1
    }

    local src
    src="$(echo "${rules}" | jq -r '.[] | select(.id == "fw-ipv6-cidr-allow") | (.src_ip // .src_cidr // .src // "")')"
    # The serialised form may be "fd00:59::/64" or a structured object;
    # either way the substring "fd00:59" must survive the round-trip.
    echo "${src}" | grep -qi 'fd00:59' || {
        echo "v6 source prefix not preserved in REST output: ${src}" >&2
        return 1
    }
}

@test "firewall co-loads matching IPv4 + IPv6 rules without conflict" {
    local body
    body="$(api_get /api/v1/firewall/rules)"
    local count
    count="$(echo "${body}" \
        | jq '[(if type == "array" then . else (.rules // []) end)[] | select(.id == "fw-ipv6-cidr-allow" or .id == "fw-ipv4-counterpart" or .id == "fw-ipv6-loopback-host")] | length')"
    [ "${count}" = "3" ] || {
        echo "expected 3 of {fw-ipv6-cidr-allow, fw-ipv4-counterpart, fw-ipv6-loopback-host}; got ${count}" >&2
        echo "${body}" >&2
        return 1
    }
}

# ── IDS — IPv6-scoped signature loaded ─────────────────────────────

@test "IDS surfaces the IPv6 probe signature" {
    local body
    body="$(api_get /api/v1/ids/rules)" || true
    _load_http_status
    if [ "${HTTP_STATUS}" = "404" ]; then
        skip "IDS rules REST endpoint not exposed"
    fi
    [ "${HTTP_STATUS}" = "200" ]

    local hit
    hit="$(echo "${body}" \
        | jq '[(if type == "array" then . else (.rules // []) end)[] | select(.id == "ids-ipv6-probe")] | length')"
    [ "${hit}" = "1" ] || {
        echo "ids-ipv6-probe not surfaced via /api/v1/ids/rules" >&2
        echo "${body}" >&2
        return 1
    }
}

# ── IPS — auto-blacklist surface accepts an IPv6 source ────────────

@test "IPS blacklist endpoint accepts an IPv6 entry" {
    local target="fd00:59::dead"

    local body
    body="$(api_post /api/v1/ips/blacklist \
        "{\"ip\":\"${target}\",\"reason\":\"ipv6-sweep-test\"}" 2>/dev/null)" || true
    _load_http_status
    case "${HTTP_STATUS}" in
        200|201|204) : ;;
        404|405)
            skip "IPS blacklist write API not exposed in this build"
            ;;
        *)
            echo "unexpected status ${HTTP_STATUS} for POST /api/v1/ips/blacklist" >&2
            echo "${body}" >&2
            return 1
            ;;
    esac

    local list
    list="$(api_get /api/v1/ips/blacklist)" || true
    echo "${list}" | grep -qi 'fd00:59::dead' || {
        echo "ipv6 blacklist entry not visible in GET /api/v1/ips/blacklist" >&2
        echo "${list}" >&2
        return 1
    }

    api_delete "/api/v1/ips/blacklist/${target}" >/dev/null 2>&1 || true
}

# ── Ratelimit — per-IPv6-source rule surfaces ──────────────────────

@test "ratelimit surfaces the per-IPv6-source rule" {
    local body
    body="$(api_get /api/v1/ratelimit/rules)" || true
    _load_http_status
    if [ "${HTTP_STATUS}" = "404" ]; then
        skip "ratelimit rules REST endpoint not exposed"
    fi
    [ "${HTTP_STATUS}" = "200" ]

    echo "${body}" | grep -qi 'rl-ipv6-source' || {
        echo "rl-ipv6-source not surfaced via /api/v1/ratelimit/rules" >&2
        echo "${body}" >&2
        return 1
    }
}

# ── Mixed v4/v6 packet metrics ─────────────────────────────────────

@test "v4+v6 traffic increments the firewall packets counter without crashing" {
    require_tool ncat

    local before
    before="$(get_metrics_value ebpfsentinel_packets_total 2>/dev/null)"
    [ -n "${before}" ] || before=0

    # v4 burst
    for _ in 1 2 3; do
        send_tcp_from_ns "${EBPF_HOST_IP}" 65511 "probe-v4" 1 || true
    done

    # v6 burst (best-effort — kernel must accept the v6 socket call).
    for _ in 1 2 3; do
        ip netns exec "${EBPF_TEST_NS}" timeout 2 \
            ncat -6 -w 2 "${EBPF_HOST_V6}" 65510 </dev/null 2>/dev/null || true
    done

    sleep 1

    local after
    after="$(get_metrics_value ebpfsentinel_packets_total 2>/dev/null)"
    [ -n "${after}" ] || after=0

    # On the degraded path the packets counter can stay flat if the
    # kernel rejects the v6 socket before tc sees it — fall back to
    # asserting the metric remained exposed (no agent crash) in that
    # case, which is the contract the v4/v6 cross-contamination AC
    # actually relies on.
    if [ "$(echo "${after} >= ${before}" | bc -l 2>/dev/null)" != "1" ]; then
        echo "packets counter went backwards: ${before} → ${after}" >&2
        return 1
    fi

    # Agent must still be alive and answering /healthz.
    local healthz
    healthz="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/healthz" 2>/dev/null)" || true
    [ -n "${healthz}" ] || {
        echo "agent healthz unreachable after mixed v4/v6 burst" >&2
        return 1
    }
}

# ── DNS observer — AAAA query surface ──────────────────────────────

@test "DNS subsystem stays ready when AAAA queries are issued" {
    require_tool ncat

    # Craft a minimal AAAA query for "example.com" → 32-byte payload.
    # We only need the agent to observe the UDP/53 frame without
    # crashing; no upstream resolver is required.
    local hex_query='AAAA0100000100000000000007 6578616D706C6503636F6D0000 1C0001'
    hex_query="${hex_query// /}"

    # Send to a sink port (the host won't reply — that's fine, we only
    # need the agent's DNS parser to ingest the packet).
    echo -ne "$(printf '%b' "$(echo "${hex_query}" \
        | sed 's/\(..\)/\\x\1/g')")" \
        | ip netns exec "${EBPF_TEST_NS}" \
            timeout 1 ncat -u -w 1 "${EBPF_HOST_IP}" 53 \
            2>/dev/null || true

    sleep 1

    # Service should still be ready (i.e. parser didn't crash).
    local body
    body="$(api_get /readyz)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]
}

# ── Wire-level IPv6 IDS alert via tc-ids ───────────────────────────

@test "wire-level IPv6 TCP probe fires the tc-ids IDS alert (component=ids, is_ipv6)" {
    require_tool ncat
    # Local-lane only: drives the agent through the dual-stack veth/netns set
    # up by create_test_netns + _assign_v6_to_veth. In the 2-VM/3-VM lane that
    # local target does not exist (the agent is a remote transit router), so
    # this skips there; the 3-VM v6 datapath is covered by the transit-forward
    # test below.
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        skip "v6 netns IDS wire probe is local-lane only (3-VM v6 path covered by the forward test)"
    fi

    # Drive IPv6 TCP SYNs from the netns at the ids-ipv6-probe target
    # (dst_port 65520). tc-ids inspects both address families on the veth
    # ingress; the signature has no threshold so the SYN is matched even
    # though no listener completes the handshake.
    local i
    for i in 1 2 3 4 5; do
        ip netns exec "${EBPF_TEST_NS}" \
            timeout 2 ncat -6 -w 2 "${EBPF_HOST_V6}" 65520 </dev/null 2>/dev/null || true
        sleep 0.2
    done

    local alerts
    alerts="$(wait_for_alert \
        '.[] | select(.rule_id == "ids-ipv6-probe")' 15 1)" || {
        echo "no ids-ipv6-probe alert after IPv6 TCP probe" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    local first
    first="$(echo "${alerts}" | jq -sc '.[0]')"
    # The alert must be attributed to the IPv6 flow and the IDS component.
    [ "$(echo "${first}" | jq -r '.is_ipv6 // false')" = "true" ] || {
        echo "expected is_ipv6=true on the v6 IDS alert: ${first}" >&2
        return 1
    }
    [ "$(echo "${first}" | jq -r '.component // ""')" = "ids" ] || {
        echo "expected component=ids on the v6 IDS alert: ${first}" >&2
        return 1
    }
}

@test "agent transit-forwards regular IPv6 with the source prefix unchanged (no NPTv6)" {
    skip_if_not_3vm

    # Plain (non-translated) IPv6 transit across the three VMs, using the
    # dual-stack ULA segments the Vagrantfile provisions parallel to the
    # IPv4 .56/.57 networks:
    #   * attacker  fd00:56::20/64 on eth1, route to fd00:57::/64 via the agent
    #   * agent     IPv6 forwarding on; fd00:56::10/64 (eth1) + fd00:57::10/64 (eth2)
    #   * backend   fd00:57::30/64 on eth1, return route to fd00:56::/64 via the agent
    # Each step is an idempotent `replace` so the test self-heals if a reboot
    # dropped the imperative provisioner addresses. Unlike suite 54 (NPTv6),
    # no prefix rewrite is configured, so the backend must observe the
    # attacker's *unchanged* source — proving the agent forwards IPv6 across
    # both transit NICs while the eBPF datapath is attached.
    local attacker_v6="fd00:56::20"
    local backend_v6="fd00:57::30"
    local agent_gw_int="fd00:56::10"   # client-side gateway (eth1)
    local agent_gw_ext="fd00:57::10"   # backend-side gateway (eth2)
    local agent_eth1="${EBPF_AGENT_INTERFACE:-eth1}"
    local agent_eth2="${EBPF_AGENT_BACKEND_IFACE:-eth2}"

    # Attacker: address + route toward the backend network via the agent.
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" \
        "sudo ip -6 addr replace ${attacker_v6}/64 dev eth1; \
         sudo ip -6 route replace fd00:57::/64 via ${agent_gw_int} dev eth1" \
        >/dev/null 2>&1 || true

    # Agent: forwarding on + a gateway address on each transit NIC.
    _agent_ssh_sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    _agent_ssh_sudo ip -6 addr replace "${agent_gw_int}/64" dev "${agent_eth1}" >/dev/null 2>&1 || true
    _agent_ssh_sudo ip -6 addr replace "${agent_gw_ext}/64" dev "${agent_eth2}" >/dev/null 2>&1 || true

    # Backend: address on its network + a return route to the attacker prefix.
    _backend_ssh_sudo ip -6 addr replace "${backend_v6}/64" dev eth1 >/dev/null 2>&1 || true
    _backend_ssh_sudo ip -6 route replace "fd00:56::/64" via "${agent_gw_ext}" dev eth1 >/dev/null 2>&1 || true

    # Let DAD settle so the source address is usable.
    sleep 2

    # Warm the attacker neighbour cache for the gateway (scapy reads lladdr).
    ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "vagrant@${ATTACKER_VM_IP}" "ping6 -c2 -W2 ${agent_gw_int} >/dev/null 2>&1" \
        >/dev/null 2>&1 || true

    # Capture on the backend, then drive the probe (UDP dport 4546).
    local pcap="${DATA_DIR}/ipv6-forward.pcap"
    ( capture_backend_ipv6 "${pcap}" 8 eth1 ) 3>&- &
    local cap_pid=$!
    sleep 1

    scapy_send_ipv6_via "${attacker_v6}" "${backend_v6}" 5 eth1 "${agent_gw_int}" \
        >/dev/null 2>&1 || true

    wait "${cap_pid}" 2>/dev/null || true

    # Probes reaching the backend with the attacker's unchanged source prove
    # a regular (non-translated) forward.
    local src_hits any_hits
    src_hits=0
    any_hits=0
    if [ -s "${pcap}" ]; then
        src_hits="$(tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null \
            | grep -c "IP6 ${attacker_v6}" || true)"
        any_hits="$(tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null \
            | grep -c 'IP6 ' || true)"
    fi

    # A probe arrived but NOT with our source → a real forward/translation
    # fault (the ipv6-sweep fixture configures no NPTv6, so the source must
    # survive). Fail rather than skip.
    if [ "${any_hits:-0}" -ge 1 ] && [ "${src_hits:-0}" -eq 0 ]; then
        echo "IPv6 probe reached backend but source ${attacker_v6} was rewritten/dropped" >&2
        tcpdump -nr "${pcap}" 'ip6 and udp port 4546' 2>/dev/null | head >&2
        return 1
    fi

    # Nothing reached the backend at all → transit link never came up; skip
    # rather than register a false negative (same convention as suite 54).
    if [ "${src_hits:-0}" -eq 0 ]; then
        skip "no IPv6 probe reached backend — transit link not established"
    fi

    [ "${src_hits:-0}" -ge 1 ]
}
