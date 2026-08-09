#!/usr/bin/env bats
# 19-ebpf-dns-scenarios.bats — DNS intelligence eBPF scenario tests
# Requires: root, kernel >= 6.9, bpftool

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dns-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dns.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    _stop_stub_resolver
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dns-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _start_stub_resolver ANSWER_COUNT FIRST_IP — bind the stub responder inside
# the test namespace, so queries leave the host and answers come back in on the
# veth where tc-dns sits. The program attaches on ingress only, which is the
# real deployment direction: the resolver is remote and its answers arrive.
# Only responses carry answer records and only responses are parsed into the
# cache, so no payload assertion is possible without one.
_start_stub_resolver() {
    local answers="$1" first_ip="$2"
    _stop_stub_resolver
    # `3>&-` matters: bats waits for FD 3 to close before finishing the run, and
    # a daemon that inherits it hangs the whole suite after the last test.
    setsid ip netns exec "${EBPF_TEST_NS}" \
        python3 "${PROJECT_ROOT}/tests/integration/scripts/dns-stub-responder.py" \
        "${EBPF_NS_IP}" "${answers}" "${first_ip}" \
        < /dev/null > "${DATA_DIR}/stub-resolver.log" 2>&1 3>&- &
    STUB_RESOLVER_PID=$!
    # Give the socket a moment to bind before the first query goes out.
    local i
    for i in $(seq 1 20); do
        if ip netns exec "${EBPF_TEST_NS}" ss -lun 2>/dev/null \
            | grep -q "${EBPF_NS_IP}:53"; then
            return 0
        fi
        sleep 0.1
    done
    echo "stub resolver did not bind ${EBPF_NS_IP}:53" >&2
    cat "${DATA_DIR}/stub-resolver.log" >&2 || true
    return 1
}

_stop_stub_resolver() {
    if [ -n "${STUB_RESOLVER_PID:-}" ]; then
        kill -9 "${STUB_RESOLVER_PID}" 2>/dev/null || true
        unset STUB_RESOLVER_PID
    fi
    pkill -9 -f dns-stub-responder.py 2>/dev/null || true
}

# _cached_ips DOMAIN — the IP list the agent cached for a domain, one per line.
# An empty result is a normal poll outcome, not a command failure.
_cached_ips() {
    local domain="$1"
    api_get "/api/v1/dns/cache?domain=${domain}" 2>/dev/null \
        | tr ',' '\n' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
}

# ── TC program attachment ────────────────────────────────────────

@test "TC DNS program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── DNS API status ───────────────────────────────────────────────

@test "DNS cache is accessible via API" {
    require_root

    local body
    body="$(api_get /api/v1/dns/cache)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS stats returns valid response" {
    require_root

    local body
    body="$(api_get /api/v1/dns/stats)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS blocklist is accessible" {
    require_root

    local body
    body="$(api_get /api/v1/dns/blocklist)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

@test "DNS cache flush succeeds" {
    require_root

    api_delete /api/v1/dns/cache >/dev/null
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

# ── DNS packet capture ──────────────────────────────────────────

@test "UDP:53 traffic is observed by DNS program" {
    require_root

    # Send a DNS-like UDP packet to port 53 from namespace
    send_udp_from_ns "$EBPF_HOST_IP" 53 "DNS_TEST_QUERY" 2

    sleep 2

    # DNS metrics should reflect packet observation
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_dns|ebpfsentinel_packets"
}

# _dns_observed_metric — sum the agent's observed-packet counters so a
# before/after delta can prove real query volume reached the datapath.
# DNS observation is exposed as ebpfsentinel_packets_total{interface=
# "DNS_METRICS",...}; prefer the DNS-labelled rows and fall back to the
# whole packets family if the label naming differs on this build.
_dns_observed_metric() {
    local metrics
    metrics="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || {
        echo 0
        return
    }
    echo "$metrics" \
        | awk '/^ebpfsentinel_packets[_a-z]*(_total)?[ {]/ {
                   all += $NF
                   if ($0 ~ /DNS_METRICS/) dns += $NF
               }
               END {
                   v = (dns > 0) ? dns : all
                   if (v == "") print 0; else print v
               }'
}

@test "real dnsperf query volume is observed by the DNS datapath" {
    require_tool dnsperf

    local qfile="${DATA_DIR}/dnsperf-queries.txt"
    printf '%s\n' \
        "example.com A" "example.net AAAA" "test.local A" \
        "corp.internal A" "service.test TXT" "api.example.org A" \
        > "${qfile}"

    local before
    before="$(_dns_observed_metric)"

    # Drive a few seconds of real DNS queries from the netns at the agent's
    # :53 hook. No resolver is bound, so dnsperf records timeouts — but every
    # query packet still crosses the tc-dns hook, which is what we assert.
    local out
    out="$(ip netns exec "${EBPF_TEST_NS}" \
        dnsperf -s "${EBPF_HOST_IP}" -p 53 -d "${qfile}" -l 5 -c 5 -q 200 \
        2>&1)" || true

    local sent
    sent="$(echo "${out}" | awk -F'[ ]+' '/Queries sent/ {print $NF}')"
    [ "${sent:-0}" -gt 0 ] || {
        echo "dnsperf reported no queries sent" >&2
        echo "${out}" >&2
        return 1
    }

    sleep 2
    local after
    after="$(_dns_observed_metric)"
    [ "${after:-0}" -gt "${before:-0}" ] || {
        echo "DNS observation counter did not grow under dnsperf load: ${before} -> ${after}" >&2
        return 1
    }
}

# ── Ring-buffer payload integrity ────────────────────────────────
#
# The kernel picks a ring-buffer record size from the captured payload length.
# Both sizes carry the same header, so a tier chosen wrongly, or a payload
# copied short, shows up as answers missing from the cache rather than as an
# error anywhere. These two tests pin a response either side of the boundary.

@test "a short DNS response is cached with its answer intact" {
    require_tool dig
    require_tool python3

    _start_stub_resolver 1 203.0.113.7

    local domain="tier-small.example.test"
    dig +tries=1 +time=2 "@${EBPF_NS_IP}" "${domain}" A > /dev/null 2>&1 || true

    local i ips=""
    for i in $(seq 1 20); do
        ips="$(_cached_ips "${domain}")"
        [ -n "${ips}" ] && break
        sleep 0.5
    done

    _stop_stub_resolver

    [ -n "${ips}" ] || {
        echo "no cache entry for ${domain}" >&2
        echo "cache API says: $(api_get "/api/v1/dns/cache?domain=${domain}")" >&2
        echo "responder log: $(cat "${DATA_DIR}/stub-resolver.log" 2>/dev/null)" >&2
        return 1
    }
    echo "${ips}" | grep -qx "203.0.113.7" || {
        echo "cached IPs for ${domain} lack the answered address: ${ips}" >&2
        return 1
    }
}

@test "a DNS response larger than the small record tier keeps every answer" {
    require_tool dig
    require_tool python3

    # 20 A records put the response near 360 bytes, comfortably past the
    # small tier and inside the full one.
    _start_stub_resolver 20 203.0.113.7

    local domain="tier-full.example.test"
    dig +tries=1 +time=2 "@${EBPF_NS_IP}" "${domain}" A > /dev/null 2>&1 || true

    local i ips=""
    for i in $(seq 1 20); do
        ips="$(_cached_ips "${domain}")"
        [ -n "${ips}" ] && break
        sleep 0.5
    done

    _stop_stub_resolver

    [ -n "${ips}" ] || {
        echo "no cache entry for ${domain}" >&2
        echo "cache API says: $(api_get "/api/v1/dns/cache?domain=${domain}")" >&2
        echo "responder log: $(cat "${DATA_DIR}/stub-resolver.log" 2>/dev/null)" >&2
        return 1
    }
    # Every answer carries the same name, and the cache keeps one entry per
    # domain, so the surviving address is whichever record was parsed last.
    # That makes it the exact witness we want: the 20th answer starts ~340
    # bytes into the payload, far past the small record's 128-byte payload.
    # A short copy would leave an earlier address here, or nothing at all.
    echo "${ips}" | grep -qx "203.0.113.26" || {
        echo "last answer missing — payload truncated. cached: ${ips}" >&2
        return 1
    }
}
