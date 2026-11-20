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
    prepare_full_config "$PREPARED_CONFIG"

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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id"))' >/dev/null
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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("data_type"))' >/dev/null
}

# ── Conntrack ─────────────────────────────────────────────────────

@test "Conntrack: GET status returns 200 with enabled field" {
    local body
    body="$(api_get /api/v1/conntrack/status)"
    assert_http_status "200" "$HTTP_STATUS"
    assert_json_field "$body" '.enabled' 'true'
}

# The listing, the flush and the event stream read the kernel table, which
# this lane's unprivileged agent cannot read. They are asserted in suite 18,
# on the datapath lane, where a root agent tracks a flow the test opens.

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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("direction"))' >/dev/null
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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("id") and has("gateway_ip"))' >/dev/null
}

# ── Aliases ───────────────────────────────────────────────────────

@test "Aliases: GET status returns 200" {
    local body
    body="$(api_get /api/v1/aliases/status)"
    assert_http_status "200"
    echo "$body" | jq -e '.alias_count | type == "number"' >/dev/null
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
    # The kernel set holds IPv4 hosts only: the /24 is matched in userspace
    # and the answer says so instead of counting it as loaded.
    echo "$body" | jq -e '.kernel_set_entries == 1 or .kernel_set_entries == 0' >/dev/null || {
        echo "expected kernel_set_entries to count the one host at most: ${body}" >&2
        return 1
    }
}

@test "Aliases: PUT content on a non-External alias returns 400" {
    local body
    body="$(api_put /api/v1/aliases/it-alias-ipset/content '{"ips":["203.0.113.11/32"]}')"
    assert_http_status "400"
    assert_error_body "$body"
}

@test "Aliases: PUT content on an unknown alias returns 400" {
    local body
    body="$(api_put /api/v1/aliases/no-such-alias/content '{"ips":["203.0.113.12/32"]}')"
    assert_http_status "400"
    assert_error_body "$body"
}

@test "Aliases: PUT content with an invalid CIDR returns 400" {
    local body
    body="$(api_put /api/v1/aliases/it-alias-external/content '{"ips":["not-an-ip"]}')"
    assert_http_status "400"
    assert_error_body "$body"
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
    local listing
    listing="$(api_get /api/v1/lb/services)"
    echo "$listing" | jq -e --arg id "it-lb-001" 'type == "array" and (map(.id) | index($id) | not)' >/dev/null || {
        echo "it-lb-001 still listed after delete: $listing" >&2; return 1; }
}

@test "LB: DELETE nonexistent service returns 404" {
    local body
    body="$(api_delete /api/v1/lb/services/no-such-svc)"
    assert_http_status "404"
    assert_error_body "$body"
}

@test "LB: POST with invalid protocol returns 400" {
    local svc='{"id":"it-lb-bad","name":"bad","protocol":"invalid","listen_port":80,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    assert_http_status "400"
    assert_error_body "$body"
}

@test "LB: POST with zero listen_port returns 400" {
    local svc='{"id":"it-lb-bad2","name":"bad","protocol":"tcp","listen_port":0,"backends":[{"id":"be-1","addr":"10.0.0.1","port":80,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    assert_http_status "400"
    assert_error_body "$body"
}

@test "LB: POST with empty backends returns 400" {
    local svc='{"id":"it-lb-bad3","name":"bad","protocol":"tcp","listen_port":80,"backends":[]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    assert_http_status "400"
    assert_error_body "$body"
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
    assert_http_status "200"
    echo "$body" | jq -e 'type == "object" and length > 0' >/dev/null
}

@test "Ops: GET config serves what config-full.yaml set, its secrets masked" {
    # Read before any PUT below rewrites a section.
    local body
    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e '
        .agent.on_exit == "detach"
        and .agent.xdp_mode == "generic"
        and .agent.event_workers == 2
        and .agent.api_rate_limit.read_per_minute == 6000
        and .firewall.schedules["it-office-hours"].entries[0].time == "08:00-18:00"
        and (.firewall.rules | map(select(.id == "fw-test-tcp-shape")) | .[0].schedule) == "it-office-hours"
        and .ratelimit.max_buckets == 65536
        and (.auto_response.policies | length) == 2
        and .alerting.routes[0].event_types == ["firewall", "ids"]
        and .response.kill_process.signal == 15
        and .loadbalancer.max_backends == 1024
        and .alerting.smtp.password == "***"
        and .threatintel.crowdsec.bouncer_key == "***"
        and .threatintel.crowdsec.report.password == "***"
        and .threatintel.feeds[0].auth_header == "***"' >/dev/null || {
        echo "the served configuration differs from config-full.yaml: ${body}" >&2
        return 1
    }
    if echo "$body" | grep -q 'it-relay-password\|it-bouncer-key\|it-machine-password\|it-feed-token'; then
        echo "a secret from config-full.yaml is served: ${body}" >&2
        return 1
    fi
}

@test "Ops: GET ebpf status returns 200" {
    local body
    body="$(api_get /api/v1/ebpf/status)"
    assert_http_status "200"
    echo "$body" | jq -e '.programs | type == "array"' >/dev/null
}

@test "Ops: POST config reload returns 200" {
    local body
    # The handler validates the on-disk config, then waits up to 8 s for the
    # reload task to finish before answering, so the default 5 s client
    # timeout is shorter than the endpoint's own contract. Measured cold on
    # the VM: 16.3 s first call, 4.6 s second, 0.02 s warm.
    body="$(api_post /api/v1/config/reload '{}' --max-time 30)"
    assert_http_status "200"
    echo "$body" | jq -e '(.status == "ok" or .status == "pending") and (.message | type == "string")' >/dev/null
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

@test "Ops: PUT config section refuses a rule start-up refuses, and the rules stay" {
    # The file parses, and start-up still refuses it: a rule scoped to an
    # interface the agent does not watch. Before the write ran the start-up
    # checks it landed, the reload refused it in a log line, and the answer
    # was a 200 over an agent running the previous rules.
    local body
    body="$(api_put /api/v1/config/firewall.rules \
        '{"yaml":"firewall:\n  rules:\n    - id: it-eth9\n      priority: 10\n      action: deny\n      scope:\n        interface: it-absent9\n"}' \
        --max-time 30)"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "INVALID_CONFIG"' >/dev/null || {
        echo "expected INVALID_CONFIG: ${body}" >&2
        return 1
    }

    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e '[.firewall.rules[].id] | index("fw-test-001") != null
                          and index("it-eth9") == null' >/dev/null || {
        echo "the refused write changed the running rules: ${body}" >&2
        return 1
    }
}

@test "Ops: PUT config section names what waits for a restart" {
    # Alerting is read once at start: the write lands, the reload applies
    # the rest, and the answer says this block is not running yet.
    local body
    body="$(api_put /api/v1/config/alerting.dedup_window_secs \
        '{"yaml":"alerting:\n  dedup_window_secs: 61\n"}' --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e '.status != "ok" or (.pending_restart | index("alerting") != null)' \
        >/dev/null || {
        echo "expected pending_restart to name alerting: ${body}" >&2
        return 1
    }
}

@test "Ops: GET config masks a feed URL and the mask round-trips" {
    # A feed URL carries its token in the path or the query; the served
    # configuration shows the scheme and host only. Sent back as served, the
    # write keeps the URL on disk; sent back with another host, it is
    # refused rather than written as asterisks.
    local body
    body="$(api_put /api/v1/config/threatintel.feeds \
        '{"yaml":"threatintel:\n  feeds:\n    - id: it-feed\n      name: it-feed\n      url: https://feeds.example.com/list.txt?token=it-secret\n      enabled: false\n"}' \
        --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"

    body="$(api_get /api/v1/config)"
    assert_http_status "200" "$HTTP_STATUS"
    echo "$body" | jq -e '.threatintel.feeds[0].url == "https://feeds.example.com/***"' \
        >/dev/null || {
        echo "the feed URL is not masked: ${body}" >&2
        return 1
    }
    if echo "$body" | grep -q 'it-secret'; then
        echo "the feed token is served: ${body}" >&2
        return 1
    fi

    body="$(api_put /api/v1/config/threatintel.feeds \
        '{"yaml":"threatintel:\n  feeds:\n    - id: it-feed\n      name: it-feed\n      url: https://feeds.example.com/***\n      enabled: false\n"}' \
        --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"

    body="$(api_put /api/v1/config/threatintel.feeds \
        '{"yaml":"threatintel:\n  feeds:\n    - id: it-feed\n      name: it-feed\n      url: https://elsewhere.example.com/***\n      enabled: false\n"}' \
        --max-time 30)"
    assert_http_status "400" "$HTTP_STATUS"
    echo "$body" | jq -e '.error.code == "UNRESOLVED_MASK"' >/dev/null || {
        echo "expected UNRESOLVED_MASK: ${body}" >&2
        return 1
    }

    # Leave the fixture as it was for the tests after this one.
    body="$(api_put /api/v1/config/threatintel.feeds \
        '{"yaml":"threatintel:\n  feeds: []\n"}' --max-time 30)"
    assert_http_status "200" "$HTTP_STATUS"
}

# ── IPS extended ──────────────────────────────────────────────────

@test "IPS: GET domain-blocks returns 200" {
    local body
    body="$(api_get /api/v1/ips/domain-blocks)"
    assert_http_status "200"
    echo "$body" | jq -e 'type == "array" and all(.[]; has("domain") and has("ip"))' >/dev/null
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
