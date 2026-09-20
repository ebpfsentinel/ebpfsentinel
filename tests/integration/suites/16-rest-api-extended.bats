#!/usr/bin/env bats
# 16-rest-api-extended.bats - Extended domain REST API endpoints
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
    # The stream is wired when the agent can read the kernel conntrack table by
    # either source, which is the rule its own startup applies: the proc file
    # when the kernel was built with CONFIG_NF_CONNTRACK_PROCFS, and otherwise a
    # `conntrack -L` that succeeds. Asking only for the proc file asked for a
    # deprecated interface distributions are dropping - it is unset on the
    # kernel these VMs run - so this test skipped on a host where the feature
    # was live. The question is put to the agent's own host, which is a machine
    # of its own on the two- and three-machine lanes.
    if ! _agent_ssh_sudo test -r /proc/net/nf_conntrack &&
        ! _agent_ssh_sudo conntrack -L >/dev/null 2>&1; then
        env_skip "kernel conntrack table unreadable by either source - event stream not wired"
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

# ── Writing one section back ──────────────────────────────────────

@test "Ops: PUT config section writes a section back and reloads" {
    # What a configuration screen does: render one section, let somebody
    # edit it, put the same document back. The fixture turns the route on
    # with `agent.config_writes: allowed`; it is refused everywhere else.
    local body
    body="$(api_put /api/v1/config/conntrack \
        '{"yaml":"conntrack:\n  enabled: true\n"}' --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"

    # The answer is the reload's, because a section written and not applied
    # is a file nobody is running.
    echo "$body" | jq -e '.status != null and .message != null' >/dev/null || {
        echo "PUT config section did not answer a reload: ${body}" >&2
        return 1
    }

    # The merge replaced one section and left the rest of the document
    # alone, which is what the running configuration says afterwards.
    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e '.conntrack.enabled == true and .firewall.enabled == true
                          and (.firewall.rules | length) >= 1' >/dev/null || {
        echo "the rest of the configuration did not survive the write: ${body}" >&2
        return 1
    }
}

@test "Ops: PUT config section refuses a document that is not YAML" {
    local body
    body="$(api_put /api/v1/config/conntrack '{"yaml":"conntrack: [unterminated"}')"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "INVALID_YAML"' >/dev/null || {
        echo "expected INVALID_YAML: ${body}" >&2
        return 1
    }
}

@test "Ops: PUT config section refuses a document that does not carry the section" {
    # A screen that posted the wrong key would otherwise write a section
    # nobody edited, or nothing at all with a 200 on it.
    local body
    body="$(api_put /api/v1/config/conntrack '{"yaml":"nat:\n  enabled: true\n"}')"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "SECTION_MISSING"' >/dev/null || {
        echo "expected SECTION_MISSING: ${body}" >&2
        return 1
    }
}

@test "Ops: PUT config section refuses a section name outside the shape it allows" {
    # The name is spliced into a walk down the document and echoed back in
    # errors, so it is held to a shape rather than trusted. A name this long
    # is refused before anything is read.
    local body long
    long="$(printf 'x%.0s' {1..65})"
    body="$(api_put "/api/v1/config/${long}" '{"yaml":"conntrack:\n  enabled: true\n"}')"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "INVALID_SECTION"' >/dev/null || {
        echo "expected INVALID_SECTION: ${body}" >&2
        return 1
    }
}

@test "Ops: PUT config section refuses a configuration the agent would not boot on" {
    # The merged document is validated by the same loader the agent boots
    # with, and a rejected edit leaves the file exactly as it was - which
    # the reload right after proves, since it re-reads that file.
    local body
    body="$(api_put /api/v1/config/conntrack \
        '{"yaml":"conntrack:\n  enabled: not-a-boolean\n"}' --max-time 30)"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "INVALID_CONFIG"' >/dev/null || {
        echo "expected INVALID_CONFIG: ${body}" >&2
        return 1
    }

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
