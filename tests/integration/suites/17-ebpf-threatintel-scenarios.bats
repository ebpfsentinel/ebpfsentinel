#!/usr/bin/env bats
# 17-ebpf-threatintel-scenarios.bats - Threat intel on live traffic
#
# Two feeds (plaintext and CSV with a column mapping) are served from
# TEST-NET-3 on a dummy interface. Both name the test namespace's address,
# plus addresses of their own. Asserts:
#
#   * both feeds load, the CSV one through its column mapping
#   * the address named by both feeds is held once
#   * in block mode, traffic from that address is dropped by tc-threatintel,
#     counted, and raised as a threatintel alert
#   * a reload keeps the agent answering and the indicators loaded
#
# Requires: root, kernel >= 6.18, bpftool, ncat, python3

load '../lib/helpers'
load '../lib/ebpf_helpers'

TI_SRV_IP="203.0.113.21"
TI_SRV_IFACE="ebpfsent-ti0"
TI_SRV_PORT=18889

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ti-$$"
    mkdir -p "$DATA_DIR/feeds"

    create_test_netns

    cat > "$DATA_DIR/feeds/plain.txt" <<FEED
# suite plaintext feed
${EBPF_NS_IP}
198.51.100.7
198.51.100.8
FEED
    cat > "$DATA_DIR/feeds/feed.csv" <<FEED
address,score,kind
${EBPF_NS_IP},90,c2
198.51.100.9,80,scanner
FEED

    ip link add "$TI_SRV_IFACE" type dummy 2>/dev/null || true
    ip addr add "${TI_SRV_IP}/32" dev "$TI_SRV_IFACE" 2>/dev/null || true
    ip link set "$TI_SRV_IFACE" up
    # 3>&- keeps bats' TAP descriptor out of the server.
    python3 -m http.server "$TI_SRV_PORT" --bind "$TI_SRV_IP" \
        --directory "$DATA_DIR/feeds" >"$DATA_DIR/http.log" 2>&1 3>&- &
    echo $! > "$DATA_DIR/http.pid"
    local i
    for i in $(seq 1 25); do
        curl -sf --max-time 1 "http://${TI_SRV_IP}:${TI_SRV_PORT}/plain.txt" >/dev/null && break
        sleep 0.2
    done

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-threatintel.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    # The first counter poll lands a period after start: wait for it, so
    # every "before" below is a counter and not a line not written yet.
    wait_for_ebpf_counters THREATINTEL_METRICS 30 || return 1

    # Both feeds fetched: four distinct addresses across them, one named by both.
    for i in $(seq 1 30); do
        [ "$(api_get /api/v1/threatintel/iocs | jq 'length' 2>/dev/null)" = "4" ] && break
        sleep 1
    done
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    [ -f "${DATA_DIR:-}/http.pid" ] && kill "$(cat "$DATA_DIR/http.pid")" 2>/dev/null || true
    ip link del "$TI_SRV_IFACE" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ti-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _ti_counter <action> - a tc-threatintel counter, 0 before its first packet.
_ti_counter() {
    local value
    value="$(get_metrics_value ebpfsentinel_packets_total \
        "{interface=\"THREATINTEL_METRICS\",action=\"$1\"}")" || value=""
    echo "${value:-0}"
}

@test "TC threatintel program attached to interface" {
    require_root
    require_tool bpftool

    local output
    output="$(bpftool net show dev "$EBPF_VETH_HOST" 2>&1)" || true
    assert_contains "$output" "tc_threatintel"
}

@test "status reports block mode, two feeds and four indicators" {
    local body
    body="$(api_get /api/v1/threatintel/status)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    assert_json_field "$body" '.enabled' 'true'
    assert_json_field "$body" '.mode' 'block'
    assert_json_field "$body" '.feed_count' '2'
    assert_json_field "$body" '.ioc_count' '4'
}

@test "both feeds are listed with their format" {
    local body
    body="$(api_get /api/v1/threatintel/feeds)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(echo "$body" | jq -r '[.[] | "\(.id):\(.format)"] | sort | join(" ")')" = "ti-csv:csv ti-plain:plaintext" ] || {
        echo "feeds: $body" >&2
        return 1
    }
    [ "$(echo "$body" | jq '[.[] | select(.last_fetched == null)] | length')" -eq 0 ] || {
        echo "a feed was never fetched: $body" >&2
        return 1
    }
}

@test "the CSV feed loads through its column mapping" {
    local body
    body="$(api_get /api/v1/threatintel/iocs)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    local csv_only
    csv_only="$(echo "$body" | jq -r '.[] | select(.ip == "198.51.100.9") | .confidence')"
    [ "$csv_only" = "80" ] || {
        echo "198.51.100.9 from the CSV feed: '${csv_only}' in $body" >&2
        return 1
    }
}

@test "an address named by both feeds is held once" {
    local body total unique
    body="$(api_get /api/v1/threatintel/iocs)"
    total="$(echo "$body" | jq 'length')"
    unique="$(echo "$body" | jq '[.[].ip] | unique | length')"
    [ "$total" -eq 4 ] && [ "$unique" -eq 4 ] || {
        echo "total=${total} unique=${unique}: $body" >&2
        return 1
    }
    [ "$(echo "$body" | jq --arg ip "$EBPF_NS_IP" '[.[] | select(.ip == $ip)] | length')" -eq 1 ]
}

@test "traffic from a listed address is dropped, counted and alerted" {
    require_root

    local dropped_before
    dropped_before="$(_ti_counter dropped)"

    ncat -l -p 7123 --keep-open -e /bin/cat &>/dev/null 3>&- &
    local listener=$!
    sleep 0.3

    local reply rc=0
    reply="$(echo PING | ip netns exec "$EBPF_TEST_NS" \
        timeout 4 ncat -w 2 "$EBPF_HOST_IP" 7123 2>/dev/null)" || rc=$?
    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true

    [ -z "$reply" ] || {
        echo "a listed address reached the listener (reply '${reply}')" >&2
        return 1
    }
    local dropped_after
    dropped_after="$(ebpf_counter_above THREATINTEL_METRICS dropped "$dropped_before")"
    [ "$dropped_after" -gt "$dropped_before" ] || {
        echo "tc-threatintel dropped nothing (before ${dropped_before}, after ${dropped_after}, ncat rc ${rc})" >&2
        dump_ebpf_counters THREATINTEL_METRICS >&2
        return 1
    }
    # An alert carries its addresses as the kernel saw them: four 32-bit
    # words, an IPv4 address in the first one, most significant octet first.
    local a b c d ns_word
    IFS=. read -r a b c d <<<"$EBPF_NS_IP"
    ns_word=$(( (a << 24) | (b << 16) | (c << 8) | d ))
    wait_for_alert ".[] | select(.component == \"threatintel\" and .is_ipv6 == false and .src_addr[0] == ${ns_word}) | .id" 15 1 >/dev/null || {
        echo "no threatintel alert names ${EBPF_NS_IP}" >&2
        api_get /api/v1/alerts >&2
        return 1
    }
}

@test "a reload keeps the agent answering and the indicators loaded" {
    api_post /api/v1/config/reload '{}' --max-time 30
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "reload answered ${HTTP_STATUS}" >&2
        return 1
    }
    local i count=""
    for i in $(seq 1 15); do
        count="$(api_get /api/v1/threatintel/status | jq -r '.ioc_count' 2>/dev/null)" || count=""
        [ "$count" = "4" ] && break
        sleep 1
    done
    [ "$count" = "4" ] || {
        echo "indicators after reload: ${count}" >&2
        return 1
    }
}

@test "the feed counters say what each feed loaded, what matched and how long the load took" {
    local metrics
    metrics="$(scrape_metrics)"
    _ti_series() {
        echo "$metrics" | awk -v s="$1" -v n="$2" 'index($0, s) == 1 && $NF >= n { ok = 1 } END { exit !ok }' || {
            echo "no ${1} at ${2} or more" >&2
            echo "$metrics" | grep '^ebpfsentinel_threatintel_' >&2
            return 1
        }
    }
    # Both feeds loaded indicators, each stamped with the time it was read.
    _ti_series 'ebpfsentinel_threatintel_feed_indicators{feed="ti-plain"}' 1
    _ti_series 'ebpfsentinel_threatintel_feed_indicators{feed="ti-csv"}' 1
    _ti_series 'ebpfsentinel_threatintel_feed_last_refresh_timestamp_seconds{feed="ti-plain"}' 1700000000
    _ti_series 'ebpfsentinel_threatintel_feed_last_refresh_timestamp_seconds{feed="ti-csv"}' 1700000000
    # The listed address that was dropped matched one feed.
    _ti_series 'ebpfsentinel_threatintel_matches_total{feed="' 1
    # The map was loaded at start and again on the reload, with indicators.
    _ti_series 'ebpfsentinel_threatintel_reload_duration_seconds_count ' 1
    _ti_series 'ebpfsentinel_threatintel_reload_indicators ' 1
}

@test "alerts emitted by this suite carry a MITRE technique mapping" {
    assert_alert_has_any_mitre_technique 15
}
