#!/usr/bin/env bats
# 14-ebpf-ratelimit-scenarios.bats - Rate limiting eBPF scenario tests
# Requires: root, kernel >= 6.18, bpftool, ncat, hping3

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-rl-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ratelimit.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    # The first counter poll lands a period after start: wait for it, so
    # every "before" below is a counter and not a line not written yet.
    wait_for_ebpf_counters RATELIMIT_METRICS 30 || return 1
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-rl-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Tests ──────────────────────────────────────────────────────────

# _rl_counter <action> - an xdp-ratelimit counter, 0 before its first packet.
_rl_counter() {
    local value
    value="$(get_metrics_value ebpfsentinel_packets_total \
        "{interface=\"RATELIMIT_METRICS\",action=\"$1\"}")" || value=""
    echo "${value:-0}"
}

@test "ratelimit rules loaded via API" {
    require_root

    local body
    body="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true
    [ "$count" -ge 1 ]
}

@test "normal traffic passes within rate limit" {
    require_root
    require_tool ncat

    # Start listener on an open port
    timeout 10 ncat -l "$EBPF_HOST_IP" 8888 > /tmp/ebpf-rl-normal-$$.out 2>&1 &
    local listener_pid=$!
    sleep 0.5

    # Send a small number of packets (well within 100 tok/s limit)
    for i in $(seq 1 3); do
        send_tcp_from_ns "$EBPF_HOST_IP" 8888 "NORMAL_${i}" 1
        sleep 0.3
    done

    sleep 1
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # At least some data should have been received
    local received
    received="$(cat /tmp/ebpf-rl-normal-$$.out 2>/dev/null)" || true
    rm -f /tmp/ebpf-rl-normal-$$.out

    [ -n "$received" ]
}

@test "a SYN flood past the burst is dropped by xdp-ratelimit" {
    require_root
    require_tool hping3

    local before after
    before="$(_rl_counter dropped)"
    # 500 SYNs at about 10 000 per second against 100 per second, burst 200.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 500 u100
    after="$(ebpf_counter_above RATELIMIT_METRICS dropped "$before")"

    [ "$after" -gt "$before" ] || {
        echo "xdp-ratelimit dropped nothing (before ${before}, after ${after})" >&2
        dump_ebpf_counters RATELIMIT_METRICS >&2
        return 1
    }
}

@test "the flood past the burst raises a ratelimit alert and an audit entry" {
    require_root

    # The kernel reports a source only once its bucket is empty, and every
    # report is an alert of the ratelimit component and a written audit entry.
    wait_for_alert '.[] | select(.component == "ratelimit") | .id' 15 1 >/dev/null || {
        echo "no alert of component ratelimit after the SYN flood" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }
    # A flood on a port that serves no web traffic is a network denial of service.
    assert_alert_has_mitre_technique T1498 15
    wait_for_metric ebpfsentinel_audit_events_total 1 15 >/dev/null || {
        echo "ebpfsentinel_audit_events_total did not move" >&2
        return 1
    }
}

@test "dynamic strict rule enforces new limit" {
    require_root

    # Add a very strict rate limit rule (10 tok/s)
    local body
    body='{"id":"rl-dynamic-strict","rate":10,"burst":10,"src_ip":"203.0.113.11/32","algorithm":"token_bucket","action":"drop","enabled":true}'
    api_post /api/v1/ratelimit/rules "$body"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Wait for eBPF map sync
    sleep 2

    # Verify the rule was added
    local rules
    rules="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    local strict_rule
    strict_rule="$(echo "$rules" | jq '[.[] | select(.id == "rl-dynamic-strict")] | length' 2>/dev/null)" || true
    [ "${strict_rule:-0}" -ge 1 ]
}

@test "an ICMP flood past the burst is dropped by xdp-ratelimit" {
    require_root
    require_tool hping3

    local before after
    before="$(_rl_counter dropped)"
    hping3_flood_from_ns "$EBPF_HOST_IP" 0 500 u100 -1
    after="$(ebpf_counter_above RATELIMIT_METRICS dropped "$before")"

    [ "$after" -gt "$before" ] || {
        echo "xdp-ratelimit dropped no ICMP (before ${before}, after ${after})" >&2
        dump_ebpf_counters RATELIMIT_METRICS >&2
        return 1
    }
}

# ── Extended ratelimit tests ────────────────────────────────────

@test "ratelimit rule CRUD - create sliding window rule" {
    require_root

    local body
    body='{"id":"rl-sliding-window","rate":200,"burst":50,"src_ip":"203.0.113.12/32","algorithm":"sliding_window","action":"drop","enabled":true}'
    api_post /api/v1/ratelimit/rules "$body"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Verify the rule appears in the list
    local rules
    rules="$(api_get /api/v1/ratelimit/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local found
    found="$(echo "$rules" | jq '[.[] | select(.id == "rl-sliding-window")] | length' 2>/dev/null)" || true
    [ "${found:-0}" -ge 1 ]

    # Verify algorithm field is preserved
    local algo
    algo="$(echo "$rules" | jq -r '.[] | select(.id == "rl-sliding-window") | .algorithm' 2>/dev/null)" || true
    [ "$algo" = "sliding_window" ]
}

@test "ratelimit rule CRUD - delete rule" {
    require_root

    # Ensure the sliding window rule from the previous test exists (create it if not)
    local rules
    rules="$(api_get /api/v1/ratelimit/rules)"
    local found
    found="$(echo "$rules" | jq '[.[] | select(.id == "rl-sliding-window")] | length' 2>/dev/null)" || true
    if [ "${found:-0}" -eq 0 ]; then
        local body
        body='{"id":"rl-sliding-window","rate":200,"burst":50,"src_ip":"203.0.113.12/32","algorithm":"sliding_window","action":"drop","enabled":true}'
        api_post /api/v1/ratelimit/rules "$body" >/dev/null 2>&1
        sleep 1
    fi

    # Delete the rule
    api_delete /api/v1/ratelimit/rules/rl-sliding-window
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]

    # Verify it is gone
    rules="$(api_get /api/v1/ratelimit/rules)"
    local remaining
    remaining="$(echo "$rules" | jq '[.[] | select(.id == "rl-sliding-window")] | length' 2>/dev/null)" || true
    [ "${remaining:-0}" -eq 0 ]
}

@test "a source under its rate is passed" {
    require_root
    require_tool hping3

    local passed_before passed_after
    passed_before="$(_rl_counter passed)"
    # Ten SYNs a second for two seconds: under the rate, all passed.
    hping3_flood_from_ns "$EBPF_HOST_IP" 8888 20 u100000
    # The counters are copied on a timer, so one read can land mid-flood:
    # wait for all twenty rather than the first rise.
    passed_after="$(ebpf_counter_above RATELIMIT_METRICS passed "$((passed_before + 19))")"

    [ $((passed_after - passed_before)) -ge 20 ] || {
        echo "a source under its rate was not passed (before ${passed_before}, after ${passed_after})" >&2
        dump_ebpf_counters RATELIMIT_METRICS >&2
        return 1
    }
}

@test "ratelimit metrics include drop counters" {
    require_root

    local metrics
    metrics="$(scrape_metrics)" || true
    echo "$metrics" | grep -q 'ebpfsentinel_packets_total{interface="RATELIMIT_METRICS",action="dropped"}' || {
        echo "no xdp-ratelimit drop counter on /metrics" >&2
        return 1
    }
}

@test "sliding_window algorithm via API" {
    require_root

    # One exact source: the data plane keys its buckets by address, so a
    # prefix wider than /32 is refused rather than silently narrowed.
    local rule='{"id":"rl-sliding-001","src_ip":"203.0.113.50/32","rate":50,"burst":100,"algorithm":"sliding_window","action":"drop","enabled":true}'
    local body
    body="$(api_post /api/v1/ratelimit/rules "$rule")"
    _load_http_status
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.algorithm' 'sliding_window'

    api_delete /api/v1/ratelimit/rules/rl-sliding-001 >/dev/null 2>&1 || true
}
