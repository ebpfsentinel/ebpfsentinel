#!/usr/bin/env bats
# 22-ebpf-ddos-scenarios.bats - DDoS/scrub eBPF scenario tests
# Requires: root, kernel >= 6.12, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ddos-$$"
    mkdir -p "$DATA_DIR"

    # The synthetic databases place the test namespace in KP, the country the
    # last test blocks.
    local db
    for db in City ASN; do
        cp "${PROJECT_ROOT}/tests/fixtures/GeoLite2-${db}.mmdb" "${DATA_DIR}/" || {
            echo "missing tests/fixtures/GeoLite2-${db}.mmdb" >&2
            return 1
        }
    done

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ddos.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    # The first counter poll lands a period after start: wait for it, so
    # every "before" below is a counter and not a line not written yet.
    wait_for_ebpf_counters DDOS_METRICS 30 || return 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ddos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "DDoS scrub program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── DDoS status ──────────────────────────────────────────────────

@test "DDoS status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

@test "DDoS policies loaded from config" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/policies)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    [ "$count" -ge 2 ]
}

# _ddos_counter <action> - an xdp-ratelimit DDoS counter, 0 before its first packet.
_ddos_counter() {
    local value
    value="$(get_metrics_value ebpfsentinel_packets_total \
        "{interface=\"DDOS_METRICS\",action=\"$1\"}")" || value=""
    echo "${value:-0}"
}

# ── ICMP flood detection ─────────────────────────────────────────

@test "an ICMP flood past max_pps is dropped" {
    require_root
    require_tool hping3

    local before after
    before="$(_ddos_counter icmp_drop)"
    # 500 echo requests at about 10 000 per second against max_pps 50.
    hping3_flood_from_ns "$EBPF_HOST_IP" 0 500 u100 -1
    after="$(ebpf_counter_above DDOS_METRICS icmp_drop "$before")"

    [ "$after" -gt "$before" ] || {
        echo "the ICMP guard dropped nothing (before ${before}, after ${after})" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
}

# ── SYN flood detection ──────────────────────────────────────────

@test "SYN flood grows the DDoS connection-tracking action on /metrics" {
    require_root

    local DDOS_CONN_TRACKED_LABELS='{interface="DDOS_METRICS",action="conn_tracked"}'

    local before
    before="$(get_metrics_value ebpfsentinel_packets_total \
        "$DDOS_CONN_TRACKED_LABELS" 2>/dev/null || true)"
    [ -n "$before" ] || before=0

    for i in $(seq 1 50); do
        send_tcp_from_ns "$EBPF_HOST_IP" 8888 "CT${i}" 1 &
    done
    wait

    assert_metric_increased ebpfsentinel_packets_total "$before" 1 \
        "$DDOS_CONN_TRACKED_LABELS" || {
        dump_ebpf_counters DDOS_METRICS >&2
        dump_ebpf_counters RATELIMIT_METRICS >&2
        return 1
    }
}

# ── Attack history ───────────────────────────────────────────────

@test "DDoS attacks endpoint is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/ddos/attacks)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "DDoS attack history is accessible" {
    require_root

    local body
    body="$(api_get '/api/v1/ddos/attacks/history?limit=10')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "DDoS metrics counters present" {
    require_root

    local metrics action
    metrics="$(scrape_metrics "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics")" || true
    for action in syn_rcv icmp_drop conn_tracked rst_flood_drops fin_flood_drops ack_flood_drops; do
        echo "$metrics" | grep -q "ebpfsentinel_packets_total{interface=\"DDOS_METRICS\",action=\"${action}\"}" || {
            echo "no DDoS counter ${action} on /metrics" >&2
            return 1
        }
    done
}

# ── TCP flag flood detection ──────────────────────────────────────

@test "an RST flood past its guard is dropped" {
    require_root
    require_tool hping3

    local before after
    before="$(_ddos_counter rst_flood_drops)"
    # About 5 000 per second from one source against a guard of 100.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 600 u200 -R
    after="$(ebpf_counter_above DDOS_METRICS rst_flood_drops "$before")"

    [ "$after" -gt "$before" ] || {
        echo "the RST guard dropped nothing (before ${before}, after ${after})" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
}

@test "a FIN flood past its guard is dropped" {
    require_root
    require_tool hping3

    local before after
    before="$(_ddos_counter fin_flood_drops)"
    # About 5 000 per second from one source against a guard of 100.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 600 u200 -F
    after="$(ebpf_counter_above DDOS_METRICS fin_flood_drops "$before")"

    [ "$after" -gt "$before" ] || {
        echo "the FIN guard dropped nothing (before ${before}, after ${after})" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
}

@test "an ACK flood past its guard is dropped" {
    require_root
    require_tool hping3

    local before after
    before="$(_ddos_counter ack_flood_drops)"
    # About 5 000 per second from one source against a guard of 100.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 600 u200 -A
    after="$(ebpf_counter_above DDOS_METRICS ack_flood_drops "$before")"

    [ "$after" -gt "$before" ] || {
        echo "the ACK guard dropped nothing (before ${before}, after ${after})" >&2
        dump_ebpf_counters DDOS_METRICS >&2
        return 1
    }
}

# ── Policy CRUD ───────────────────────────────────────────────────

@test "DDoS policy CRUD - create" {
    require_root

    local policy='{"id":"test-policy","attack_type":"syn_flood","detection_threshold_pps":100,"mitigation_action":"block"}'
    local body
    body="$(api_post /api/v1/ddos/policies "$policy")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id
    id="$(echo "$body" | jq -r '.id // empty' 2>/dev/null)" || true
    [ "$id" = "test-policy" ]
}

@test "DDoS policy CRUD - delete" {
    require_root

    api_delete /api/v1/ddos/policies/test-policy >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

@test "DDoS attack history endpoint returns entries" {
    require_root

    sleep 2
    local body
    body="$(api_get /api/v1/ddos/attacks/history)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    # The history answers newest first, which is how every caller reads it:
    # a listing cut by `limit` must keep the most recent floods rather than
    # the oldest ones the ring still holds.
    echo "${body}" | jq -e '
        [ .[] | .start_time_ns ] as $t
        | ($t | length) < 2 or ([ range(1; $t | length) | $t[.-1] >= $t[.] ] | all)
    ' >/dev/null || {
        echo "attack history is not ordered newest first: ${body}" >&2
        return 1
    }
}

# ── Real crafted-packet flood tools (nping / t50) ─────────────────
#
# The hping3 tests above assert each guard's own drop counter; these two
# drive the XDP ratelimit/scrub datapath with other flood generators and
# assert the observed-packet counter grows.

# _ddos_packet_metric - sum the agent's observed-packet counters
# (ebpfsentinel_packets_total across every interface/action) so a before/after
# delta proves the flood really crossed the datapath. This family is a
# monotonic per-packet counter, unlike the ddos_* gauges which can fall as
# attacks age out - mixing those in makes the delta non-monotonic and flaky.
_ddos_packet_metric() {
    local metrics
    metrics="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || {
        echo 0
        return
    }
    echo "$metrics" \
        | awk '/^ebpfsentinel_packets_total[ {]/ {sum += $NF}
               END { if (sum == "") print 0; else print sum }'
}

# _wait_metric_grows <before> [tries] - poll the packet metric until it
# exceeds <before>, echoing the observed value. The userspace metric is
# refreshed from the eBPF maps on a heartbeat, not synchronously with each
# packet, so a flood's packets can take a good few seconds to surface; poll
# generously so a flood that really landed is never missed on timing alone.
_wait_metric_grows() {
    local before="${1:?usage: _wait_metric_grows <before> [tries]}"
    local tries="${2:-20}"
    local now
    for _ in $(seq 1 "$tries"); do
        now="$(_ddos_packet_metric)"
        if [ "${now:-0}" -gt "${before:-0}" ]; then
            echo "$now"
            return 0
        fi
        sleep 1
    done
    echo "${now:-0}"
    return 1
}

@test "real nping crafted TCP-flag flood grows the DDoS packet counter" {
    require_root
    require_tool nping

    local before
    before="$(_ddos_packet_metric)"

    # nping ships with nmap. Drive a SYN port-sweep flood across a wide
    # destination-port range: sweeping the destination port makes every packet
    # a distinct flow, a real attack pattern the firewall sees packet-for-packet.
    # The DDoS counter only advances once the observed rate crosses the
    # detector's pps floor, so push a high --rate; --count is rounds-per-port,
    # so a few dozen rounds over ~1000 ports is a short, high-pps burst (not the
    # multi-minute marathon a large per-port count would produce).
    ip netns exec "$EBPF_TEST_NS" \
        nping --tcp -p 8000-8999 --flags syn \
        --count 30 --rate 100000 "$EBPF_HOST_IP" >/dev/null 2>&1 || true

    local after
    after="$(_wait_metric_grows "$before")" || {
        echo "packet counter did not grow under nping flood: ${before} -> ${after}" >&2
        return 1
    }
}

@test "real t50 multi-protocol flood grows the DDoS packet counter" {
    require_root
    require_tool t50

    local before
    before="$(_ddos_packet_metric)"

    # t50 is a raw multi-protocol flooder; --threshold bounds the burst so it
    # terminates instead of running forever like --flood. Send a large burst so
    # its contribution is unmistakable against the running packet total even
    # after the preceding nping flood.
    ip netns exec "$EBPF_TEST_NS" \
        t50 "$EBPF_HOST_IP" --protocol TCP --dport 8888 --threshold 20000 \
        >/dev/null 2>&1 || true

    local after
    after="$(_wait_metric_grows "$before")" || {
        echo "packet counter did not grow under t50 flood: ${before} -> ${after}" >&2
        return 1
    }
}

# ── Country block ────────────────────────────────────────────────
#
# Last on purpose: the block drops the whole test namespace at the firewall
# until the attack expires, five minutes after the flood stops, and the agent
# is stopped long before that. Its tables are not pinned, so nothing outlives
# the suite.

@test "a SYN flood under a block policy cuts its source country off" {
    require_root
    require_tool hping3

    local policy='{"id":"ddos-test-syn-country","attack_type":"syn_flood","detection_threshold_pps":100,"mitigation_action":"block","auto_block_duration_secs":60,"enabled":true}'
    api_post /api/v1/ddos/policies "$policy" >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ] || {
        echo "the block policy was refused: ${HTTP_STATUS}" >&2
        return 1
    }

    # The country is blocked when an attack becomes active. A SYN flood the
    # earlier floods left active would not become active again, so wait for
    # it to settle first: thirty quiet seconds take it out of active.
    local i active=1
    for i in $(seq 1 60); do
        active="$(api_get /api/v1/ddos/attacks 2>/dev/null \
            | jq '[.[] | select(.attack_type == "syn_flood" and .status == "active")] | length' 2>/dev/null)"
        [ "${active:-1}" = "0" ] && break
        sleep 1
    done
    [ "${active:-1}" = "0" ] || {
        echo "a SYN flood attack is still active after a minute" >&2
        api_get /api/v1/ddos/attacks >&2 || true
        return 1
    }

    # About 2000 SYN a second for two seconds, far past the 100 pps line,
    # keeps the attack above it for the three seconds that make it active.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 4000 u500 -S

    wait_for_metric ebpfsentinel_ddos_mitigations_total 1 15 \
        '{attack_type="block_country"}' >/dev/null || {
        echo "no country block counted after the SYN flood" >&2
        scrape_metrics | grep '^ebpfsentinel_ddos_' >&2 || true
        api_get /api/v1/ddos/attacks >&2 || true
        return 1
    }
}
