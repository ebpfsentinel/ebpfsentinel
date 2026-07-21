#!/usr/bin/env bats
# 16-rest-api-extended.bats — Extended domain REST API endpoints
# Covers: IDS, DLP, Conntrack, NAT, Routing, Aliases, Load Balancer, Operations

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-full.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── IDS ───────────────────────────────────────────────────────────

@test "IDS: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/ids/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "IDS: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/ids/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── DLP ───────────────────────────────────────────────────────────

@test "DLP: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/dlp/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "DLP: GET patterns returns 200" {
    local body
    body="$(api_get /api/v1/dlp/patterns)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Conntrack ─────────────────────────────────────────────────────

@test "Conntrack: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/conntrack/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "Conntrack: GET connections returns 200" {
    local body
    body="$(api_get /api/v1/conntrack/connections)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Conntrack: POST flush returns 200" {
    local body
    body="$(api_post /api/v1/conntrack/flush '{}')"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Conntrack: GET events opens an SSE stream" {
    # The event stream is only wired when the kernel exposes
    # /proc/net/nf_conntrack (see startup: nf_ct_available).
    if [ ! -r /proc/net/nf_conntrack ]; then
        env_skip "/proc/net/nf_conntrack unavailable — event stream not wired"
    fi

    local headers
    headers="$(curl -sI -H 'Accept: text/event-stream' \
        --max-time 3 "${BASE_URL}/api/v1/conntrack/events" 2>&1 || true)"
    assert_contains "$headers" "text/event-stream"
}

# ── NAT ───────────────────────────────────────────────────────────

@test "NAT: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/nat/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "NAT: GET rules returns 200" {
    local body
    body="$(api_get /api/v1/nat/rules)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Routing ───────────────────────────────────────────────────────

@test "Routing: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/routing/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "Routing: GET gateways returns 200" {
    local body
    body="$(api_get /api/v1/routing/gateways)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── Aliases ───────────────────────────────────────────────────────

@test "Aliases: GET status returns 200" {
    local body
    body="$(api_get /api/v1/aliases/status)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Aliases: status counts the fixture aliases" {
    local body count
    body="$(api_get /api/v1/aliases/status)"
    assert_http_status "200" "$HTTP_STATUS"
    count="$(echo "$body" | jq -r '.alias_count // 0')"
    [ "${count:-0}" -ge 2 ] || {
        echo "expected >= 2 aliases from config-full.yaml; got ${count}: ${body}" >&2
        return 1
    }
}

@test "Aliases: PUT content loads IPs into an External alias" {
    local body loaded
    body="$(api_put /api/v1/aliases/it-alias-external/content \
        '{"ips":["203.0.113.10/32","198.51.100.0/24"]}')"
    assert_http_status "200" "$HTTP_STATUS"
    loaded="$(echo "$body" | jq -r '.ips_loaded // 0')"
    [ "${loaded}" = "2" ] || {
        echo "expected ips_loaded=2; got ${loaded}: ${body}" >&2
        return 1
    }
    assert_json_field "$body" '.alias' 'it-alias-external'
}

@test "Aliases: PUT content on a non-External alias returns 400" {
    api_put /api/v1/aliases/it-alias-ipset/content '{"ips":["203.0.113.11/32"]}' >/dev/null
    assert_http_status "400" "$HTTP_STATUS"
}

@test "Aliases: PUT content on an unknown alias returns 400" {
    api_put /api/v1/aliases/no-such-alias/content '{"ips":["203.0.113.12/32"]}' >/dev/null
    assert_http_status "400" "$HTTP_STATUS"
}

@test "Aliases: PUT content with an invalid CIDR returns 400" {
    api_put /api/v1/aliases/it-alias-external/content '{"ips":["not-an-ip"]}' >/dev/null
    assert_http_status "400" "$HTTP_STATUS"
}

# ── Load Balancer ─────────────────────────────────────────────────

@test "LB: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/lb/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

@test "LB: GET services returns 200 (empty)" {
    local body
    body="$(api_get /api/v1/lb/services)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" '.' '0'
}

@test "LB: POST creates service and returns 201" {
    local svc='{"id":"it-lb-001","name":"web-svc","protocol":"tcp","listen_port":8080,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.0.0.1","port":8081,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    assert_http_status "201" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-lb-001'
    assert_json_field "$body" '.protocol' 'tcp'
    assert_json_field "$body" '.algorithm' 'round_robin'
}

@test "LB: GET service by id returns 200 with backends" {
    local body
    body="$(api_get /api/v1/lb/services/it-lb-001)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.id' 'it-lb-001'
    assert_json_array_length "$body" '.backends' '1'
}

@test "LB: DELETE service returns 204" {
    api_delete /api/v1/lb/services/it-lb-001 >/dev/null
    assert_http_status "204" "$HTTP_STATUS"
}

@test "LB: DELETE nonexistent service returns 404" {
    api_delete /api/v1/lb/services/no-such-svc >/dev/null 2>&1 || true
    assert_http_status "404" "$HTTP_STATUS"
}

@test "LB: POST with invalid protocol returns 400" {
    local svc='{"id":"it-lb-bad","name":"bad","protocol":"invalid","listen_port":80,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: POST with zero listen_port returns 400" {
    local svc='{"id":"it-lb-bad2","name":"bad","protocol":"tcp","listen_port":0,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: POST with empty backends returns 400" {
    local svc='{"id":"it-lb-bad3","name":"bad","protocol":"tcp","listen_port":80,"backends":[]}'
    api_post /api/v1/lb/services "$svc" >/dev/null 2>&1 || true
    assert_http_status "400" "$HTTP_STATUS"
}

@test "LB: list is empty after deletion" {
    local body
    body="$(api_get /api/v1/lb/services)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_array_length "$body" '.' '0'
}

# ── Operations ────────────────────────────────────────────────────

@test "Ops: GET config returns 200" {
    local body
    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Ops: GET ebpf status returns 200" {
    local body
    body="$(api_get /api/v1/ebpf/status)"
    assert_http_status "200" "$HTTP_STATUS"
}

@test "Ops: POST config reload returns 200" {
    local body
    # The handler validates the on-disk config, then waits up to 8 s for the
    # reload task to finish before answering, so the default 5 s client
    # timeout is shorter than the endpoint's own contract. Measured cold on
    # the VM: 16.3 s first call, 4.6 s second, 0.02 s warm.
    body="$(api_post /api/v1/config/reload '{}' --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── IPS extended ──────────────────────────────────────────────────

@test "IPS: GET domain-blocks returns 200" {
    local body
    body="$(api_get /api/v1/ips/domain-blocks)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── MITRE ATT&CK coverage ─────────────────────────────────────────

@test "MITRE: GET coverage returns 200 with a non-empty technique matrix" {
    local body total techniques
    body="$(api_get /api/v1/mitre/coverage)"
    assert_http_status "200" "$HTTP_STATUS"

    total="$(echo "$body" | jq -r '.total_techniques // 0')"
    techniques="$(echo "$body" | jq -r '.techniques | length')"
    [ "${total:-0}" -ge 1 ] || {
        echo "expected total_techniques >= 1: ${body}" >&2
        return 1
    }
    [ "${techniques:-0}" -eq "${total}" ] || {
        echo "techniques array (${techniques}) disagrees with total (${total})" >&2
        return 1
    }

    # Every entry must carry a T-prefixed technique id and a tactic.
    local bad
    bad="$(echo "$body" | jq -r '
        [.techniques[]
         | select((.technique_id | test("^T1[0-9]{3}")) and (.tactic | length > 0) | not)]
        | length')"
    [ "${bad:-0}" -eq 0 ] || {
        echo "malformed technique entries: ${body}" >&2
        return 1
    }
}

@test "MITRE: coverage groups techniques by tactic consistently" {
    local body tactics
    body="$(api_get /api/v1/mitre/coverage)"
    assert_http_status "200" "$HTTP_STATUS"

    tactics="$(echo "$body" | jq -r '.by_tactic | length')"
    [ "${tactics:-0}" -ge 1 ] || {
        echo "expected at least one tactic bucket: ${body}" >&2
        return 1
    }

    # Each bucket's covered_techniques must equal the number of technique
    # entries carrying that tactic, and the buckets must sum to the total.
    local mismatch
    mismatch="$(echo "$body" | jq -r '
        . as $r
        | [ $r.by_tactic[]
            | . as $b
            | select($b.covered_techniques
                     != ([ $r.techniques[] | select(.tactic == $b.tactic) ] | length)) ]
        | length')"
    [ "${mismatch:-1}" -eq 0 ] || {
        echo "by_tactic counts disagree with techniques: ${body}" >&2
        return 1
    }

    echo "$body" | jq -e '([.by_tactic[].covered_techniques] | add) == .total_techniques' >/dev/null || {
        echo "by_tactic does not sum to total_techniques: ${body}" >&2
        return 1
    }

    # The IDS component is always active in this fixture, so at least one
    # entry must be attributed to it.
    echo "$body" | jq -e '[.techniques[] | select(.component == "ids")] | length >= 1' >/dev/null || {
        echo "no ids-attributed technique in coverage matrix: ${body}" >&2
        return 1
    }
}
