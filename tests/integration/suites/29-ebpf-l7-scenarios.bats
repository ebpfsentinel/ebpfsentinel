#!/usr/bin/env bats
# 29-ebpf-l7-scenarios.bats - L7 inspection eBPF scenario tests
# Requires: root, kernel >= 6.18, bpftool, ncat

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/wire_helpers'

setup_file() {
    require_root
    require_kernel 6 18
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-l7-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-l7.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-l7-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program state ────────────────────────────────────────────────

@test "L7 program processing active" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .rules | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 1 ]
}

# ── HTTP path enforcement ────────────────────────────────────────

# An L7 deny judges a copy of the payload: the segment that carried it has
# already been forwarded, so the server receives the matching request. What the
# deny refuses is the rest of the connection: once the verdict is written,
# tc-ids drops every packet of it both ways. A listener on the agent side
# completes the handshake, without which no payload segment is ever written.

# _http_exchange <port> <path> [wait] - one HTTP/1.1 request on a fresh
# connection from the attacking side; prints "answered" when the server's
# answer arrives within <wait> seconds, "silent" when nothing does, "closed"
# when the connection ends with no answer.
_http_exchange() {
    local port="$1" path="$2" wait="${3:-4}"
    wire_client timeout "$((wait + 5))" python3 -c '
import socket, sys
host, port, path, wait = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
s = socket.create_connection((host, port), timeout=wait)
s.sendall(("GET %s HTTP/1.1\r\nHost: testhost\r\n\r\n" % path).encode())
try:
    print("answered" if s.recv(4096) else "closed")
except socket.timeout:
    print("silent")
' "$EBPF_HOST_IP" "$port" "$path" "$wait" 2>/dev/null || echo "error"
}

_l7_refusals() {
    local value
    value="$(get_metrics_value ebpfsentinel_l7_flow_refusals_total '{outcome="refused"}')" || true
    echo "${value:-0}"
}

@test "L7 HTTP path deny on /admin raises its rule's alert and counts a deny" {
    require_root
    require_tool ncat

    local deny_before
    deny_before="$(l7_counter deny)"

    wire_start_listener 8888
    send_tcp_from_ns "$EBPF_HOST_IP" 8888 $'GET /admin HTTP/1.1\r\nHost: testhost\r\n\r\n' 3
    wire_stop_listeners

    local deny_after
    deny_after="$(wait_l7_counter_above deny "$deny_before" 15)"
    [ "${deny_after%.*}" -gt "${deny_before%.*}" ] || {
        echo "the L7 deny counter did not move after GET /admin: ${deny_before} -> ${deny_after}" >&2
        return 1
    }

    wait_for_alert \
        '.[] | select(.rule_id == "l7-test-deny-admin" and .component == "l7")' \
        15 1 >/dev/null || {
        echo "no l7-test-deny-admin alert after GET /admin" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }
    # Port 8888 is no web port, so the deny maps to the generic protocol technique.
    assert_alert_has_mitre_technique T1071 15
}

@test "L7 HTTP path deny refuses the connection: the answer never arrives" {
    require_root
    require_tool ncat
    require_tool python3

    wait_for_ebpf_counters IDS_METRICS 25
    local dropped_before refused_before
    dropped_before="$(ebpf_counter IDS_METRICS l7_flow_dropped)"
    dropped_before="${dropped_before:-0}"
    refused_before="$(_l7_refusals)"

    wire_start_listener 8888 "${FIXTURE_DIR}/l7-late-http-responder.sh"

    # The same responder answers an allowed path on its own connection, so a
    # silence below is the refusal, not a server that never answers.
    local allowed
    allowed="$(_http_exchange 8888 /api/health 4)"
    [ "$allowed" = "answered" ] || {
        wire_stop_listeners
        echo "the responder did not answer an allowed request: ${allowed}" >&2
        return 1
    }

    local denied
    denied="$(_http_exchange 8888 /admin 4)"
    wire_stop_listeners
    [ "$denied" != "answered" ] || {
        echo "GET /admin was denied but its answer reached the client" >&2
        return 1
    }

    local refused_after
    refused_after="$(_l7_refusals)"
    [ "${refused_after%.*}" -gt "${refused_before%.*}" ] || {
        echo "no refusal written for GET /admin: ${refused_before} -> ${refused_after}" >&2
        scrape_metrics | grep l7_flow_refusals >&2 || true
        return 1
    }

    # The server's late answer and its retransmissions are dropped by tc-ids.
    local dropped_after
    dropped_after="$(ebpf_counter_above IDS_METRICS l7_flow_dropped "${dropped_before%.*}" 25)"
    [ "${dropped_after%.*}" -gt "${dropped_before%.*}" ] || {
        echo "tc-ids dropped no packet of the refused connection: ${dropped_before} -> ${dropped_after}" >&2
        dump_ebpf_counters IDS_METRICS >&2
        return 1
    }
}

# ── gRPC over cleartext HTTP/2 ───────────────────────────────────

# grpcurl (Go's HTTP/2 stack) Huffman-codes the :path header, so the method
# name never appears in the clear on the wire: the rule matches only if the
# agent decodes HPACK. The call goes to the agent's own gRPC port, listed in
# l7.ports by the fixture; the agent answers Unimplemented at once, often
# before the verdict lands, so what is asserted is the decision, the refusal,
# and the packets of the connection dropped after it.

@test "L7 gRPC deny reads a Huffman-coded path and refuses the connection" {
    require_root
    require_tool grpcurl

    wait_for_ebpf_counters IDS_METRICS 25
    local dropped_before refused_before
    dropped_before="$(ebpf_counter IDS_METRICS l7_flow_dropped)"
    dropped_before="${dropped_before:-0}"
    refused_before="$(_l7_refusals)"

    # An allowed call on its own connection is answered.
    local health
    health="$(wire_client grpcurl -plaintext -max-time 5 \
        -import-path "${FIXTURE_DIR}" -proto health.proto \
        "${EBPF_HOST_IP}:50051" grpc.health.v1.Health/Check 2>&1)" || true
    assert_contains "$health" "SERVING"

    wire_client grpcurl -plaintext -max-time 5 \
        -import-path "${FIXTURE_DIR}" -proto l7-admin.proto -d '{"name":"alice"}' \
        "${EBPF_HOST_IP}:50051" admin.AdminService/DeleteUser >/dev/null 2>&1 || true

    wait_for_alert \
        '.[] | select(.rule_id == "l7-test-deny-grpc-admin" and .component == "l7")' \
        15 1 >/dev/null || {
        echo "no l7-test-deny-grpc-admin alert after the DeleteUser call" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    local refused_after
    refused_after="$(_l7_refusals)"
    [ "${refused_after%.*}" -gt "${refused_before%.*}" ] || {
        echo "no refusal written for the DeleteUser call: ${refused_before} -> ${refused_after}" >&2
        return 1
    }

    # Whatever crossed before the verdict, the client's goodbye and the
    # server's retransmissions after it are dropped.
    local dropped_after
    dropped_after="$(ebpf_counter_above IDS_METRICS l7_flow_dropped "${dropped_before%.*}" 25)"
    [ "${dropped_after%.*}" -gt "${dropped_before%.*}" ] || {
        echo "tc-ids dropped no packet of the refused gRPC connection: ${dropped_before} -> ${dropped_after}" >&2
        dump_ebpf_counters IDS_METRICS >&2
        return 1
    }

    # The refusal is per connection: a new one is judged again and answered.
    health="$(wire_client grpcurl -plaintext -max-time 5 \
        -import-path "${FIXTURE_DIR}" -proto health.proto \
        "${EBPF_HOST_IP}:50051" grpc.health.v1.Health/Check 2>&1)" || true
    assert_contains "$health" "SERVING"
}

@test "L7 HTTP path allow on /api is judged allow and counts no deny" {
    require_root
    require_tool ncat

    local deny_before allow_before
    deny_before="$(l7_counter deny)"
    allow_before="$(l7_counter allow)"

    wire_start_listener 8888
    send_tcp_from_ns "$EBPF_HOST_IP" 8888 $'GET /api/health HTTP/1.1\r\nHost: testhost\r\n\r\n' 3
    wire_stop_listeners

    # The allow decision is counted as the payload is judged; once it moved,
    # the same payload had its whole chance to be counted as a deny.
    local allow_after
    allow_after="$(wait_l7_counter_above allow "$allow_before" 15)"
    [ "${allow_after%.*}" -gt "${allow_before%.*}" ] || {
        echo "GET /api/health was never judged by the allow rule: ${allow_before} -> ${allow_after}" >&2
        return 1
    }

    local deny_after
    deny_after="$(l7_counter deny)"
    [ "${deny_after%.*}" -eq "${deny_before%.*}" ] || {
        echo "an allowed path was counted as a deny: ${deny_before} -> ${deny_after}" >&2
        return 1
    }
}

# ── TLS SNI enforcement ──────────────────────────────────────────

# A real ClientHello carries the SNI; the X25519 group alone keeps the hello
# in one segment, since the fixture runs without stream reassembly and a
# hello carrying a post-quantum key share would span two.
_send_client_hello() {
    local servername="$1"
    wire_client timeout 3 openssl s_client \
        -connect "${EBPF_HOST_IP}:8443" \
        -servername "${servername}" \
        -groups X25519 \
        </dev/null >/dev/null 2>&1 || true
}

@test "L7 TLS SNI deny on bad.malware.com raises its rule's alert and counts a deny" {
    require_root
    require_tool ncat
    require_tool openssl

    local deny_before
    deny_before="$(l7_counter deny)"

    wire_start_listener 8443
    _send_client_hello "bad.malware.com"
    wire_stop_listeners

    local deny_after
    deny_after="$(wait_l7_counter_above deny "$deny_before" 15)"
    [ "${deny_after%.*}" -gt "${deny_before%.*}" ] || {
        echo "the L7 deny counter did not move after a hello for bad.malware.com: ${deny_before} -> ${deny_after}" >&2
        return 1
    }

    wait_for_alert \
        '.[] | select(.rule_id == "l7-test-deny-malware-sni" and .component == "l7")' \
        15 1 >/dev/null || {
        echo "no l7-test-deny-malware-sni alert after a hello for bad.malware.com" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }
}

# ── Rule CRUD ────────────────────────────────────────────────────

@test "L7 rule CRUD - create HTTP rule" {
    require_root

    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"test-crud-http-rule","protocol":"http","action":"log","priority":50,"path":"/test-crud","enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local rule_id
    rule_id="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    [ -n "$rule_id" ]
    [ "$rule_id" != "null" ]

    # Store for next test (export so the delete test can use it if run in same process)
    export L7_CRUD_RULE_ID="$rule_id"
}

@test "L7 rule CRUD - delete HTTP rule" {
    require_root

    # Re-create if the previous test's export did not carry over
    if [ -z "${L7_CRUD_RULE_ID:-}" ] || [ "$L7_CRUD_RULE_ID" = "null" ]; then
        local create_body
        create_body="$(api_post /api/v1/firewall/l7-rules \
            '{"id":"test-crud-http-rule-del","protocol":"http","action":"log","priority":51,"path":"/test-crud-del","enabled":true}')"
        _load_http_status
        L7_CRUD_RULE_ID="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    fi

    [ -n "$L7_CRUD_RULE_ID" ]
    [ "$L7_CRUD_RULE_ID" != "null" ]

    local delete_body
    delete_body="$(api_delete "/api/v1/firewall/l7-rules/${L7_CRUD_RULE_ID}")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]
}

# ── Rule ordering ────────────────────────────────────────────────

@test "L7 rule priority ordering" {
    require_root

    # Create two rules with distinct priorities
    local body_low body_high
    body_low="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"priority-low","protocol":"http","action":"log","priority":90,"path":"/low-prio","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_low
    id_low="$(echo "$body_low" | jq -r '.id // .rule_id' 2>/dev/null)" || true

    body_high="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"priority-high","protocol":"http","action":"log","priority":5,"path":"/high-prio","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id_high
    id_high="$(echo "$body_high" | jq -r '.id // .rule_id' 2>/dev/null)" || true

    # Fetch rules and verify both are present
    local list_body
    list_body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local rules
    rules="$(echo "$list_body" | jq 'if type == "array" then . else .rules end' 2>/dev/null)" || true
    local count
    count="$(echo "$rules" | jq 'length' 2>/dev/null)" || true
    [ "${count:-0}" -ge 2 ]

    # The engine evaluates in the order it serves: the high-priority rule
    # (priority=5), created last, must come before the low-priority one
    # (priority=90) as returned, and the whole listing must be in ascending
    # priority without any client-side sort.
    echo "$rules" | jq -e --arg low "$id_low" --arg high "$id_high" '
        (map(.id) | index($high)) < (map(.id) | index($low))
        and ([.[].priority] == ([.[].priority] | sort))
    ' >/dev/null || {
        echo "the server does not list the rules in priority order: ${rules}" >&2
        return 1
    }

    # Clean up
    api_delete "/api/v1/firewall/l7-rules/${id_low}" >/dev/null 2>&1 || true
    api_delete "/api/v1/firewall/l7-rules/${id_high}" >/dev/null 2>&1 || true
}

@test "L7 rule naming a port alias is served with the port it resolved to" {
    require_root

    # A rule declared against an alias carries no criterion until the alias
    # service has loaded, and a rule with no criterion matches everything.
    # The listing must therefore answer the literal the alias stood for, and
    # keep the alias name so the configuration line that wrote it is findable.
    local list_body rule
    list_body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    rule="$(echo "$list_body" \
        | jq -c 'if type == "array" then . else .rules end
                 | .[] | select(.id == "l7-test-alias-port")')"
    [ -n "${rule}" ] || {
        echo "the alias-named rule is not in the listing: ${list_body}" >&2
        return 1
    }

    echo "${rule}" | jq -e '
        .dst_port == "8890" and .dst_port_alias == "l7-test-alias-ports"
    ' >/dev/null || {
        echo "the alias was not resolved into a criterion: ${rule}" >&2
        return 1
    }
}

# ── Multi-protocol status ────────────────────────────────────────

@test "L7 status with multiple protocols" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    # Config has HTTP and TLS rules - verify at least 2 are present (from fixture)
    local count
    count="$(echo "$body" | jq 'if type == "array" then length else .rules | length end' 2>/dev/null)" || true
    [ "${count:-0}" -ge 2 ]
}

# ── Metrics ──────────────────────────────────────────────────────

@test "L7 metrics present in Prometheus" {
    require_root

    local metrics
    metrics="$(scrape_metrics "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics")" || true

    [ -n "$metrics" ]
    echo "$metrics" | grep -qE 'ebpfsentinel_rules_loaded\{[^}]*component="l7"|ebpfsentinel_packets_total\{[^}]*interface="l7"'
}

# ── gRPC service filtering ──────────────────────────────────────

@test "L7 gRPC service rule via API" {
    require_root

    # Create a gRPC-specific L7 rule
    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"grpc-deny-admin","protocol":"grpc","action":"deny","priority":10,"service":"admin.AdminService","enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local rule_id
    rule_id="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    [ -n "$rule_id" ]
    [ "$rule_id" != "null" ]

    # Verify the rule appears in the list with correct protocol
    local list_body
    list_body="$(api_get /api/v1/firewall/l7-rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local grpc_rule
    grpc_rule="$(echo "$list_body" | jq "[if type == \"array\" then .[] else .rules[] end | select(.id == \"$rule_id\" or .rule_id == \"$rule_id\")] | length" 2>/dev/null)" || grpc_rule=0
    [ "${grpc_rule:-0}" -ge 1 ]

    # Clean up
    api_delete "/api/v1/firewall/l7-rules/${rule_id}" >/dev/null 2>&1 || true
}

# ── SMTP protocol rule ──────────────────────────────────────────

@test "L7 SMTP protocol rule create" {
    require_root

    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"smtp-alert","protocol":"smtp","action":"log","priority":30,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local rule_id
    rule_id="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    [ -n "$rule_id" ]
    [ "$rule_id" != "null" ]

    # Verify the protocol field is stored as smtp
    local protocol
    protocol="$(echo "$create_body" | jq -r '.matcher.protocol // .protocol' 2>/dev/null)" || true
    [ "$protocol" = "smtp" ]

    # Clean up
    api_delete "/api/v1/firewall/l7-rules/${rule_id}" >/dev/null 2>&1 || true
}

# ── FTP protocol rule ───────────────────────────────────────────

@test "L7 FTP protocol rule create" {
    require_root

    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"ftp-deny","protocol":"ftp","action":"deny","priority":25,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local rule_id
    rule_id="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    [ -n "$rule_id" ]
    [ "$rule_id" != "null" ]

    local protocol
    protocol="$(echo "$create_body" | jq -r '.matcher.protocol // .protocol' 2>/dev/null)" || true
    [ "$protocol" = "ftp" ]

    # Clean up
    api_delete "/api/v1/firewall/l7-rules/${rule_id}" >/dev/null 2>&1 || true
}

# ── SMB protocol rule ───────────────────────────────────────────

@test "L7 SMB protocol rule create" {
    require_root

    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"smb-alert","protocol":"smb","action":"log","priority":35,"enabled":true}')"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local rule_id
    rule_id="$(echo "$create_body" | jq -r '.id // .rule_id' 2>/dev/null)" || true
    [ -n "$rule_id" ]
    [ "$rule_id" != "null" ]

    local protocol
    protocol="$(echo "$create_body" | jq -r '.matcher.protocol // .protocol' 2>/dev/null)" || true
    [ "$protocol" = "smb" ]

    # Clean up
    api_delete "/api/v1/firewall/l7-rules/${rule_id}" >/dev/null 2>&1 || true
}

# ── TLS SNI allow ───────────────────────────────────────────────

@test "L7 TLS SNI outside every deny rule is inspected and counts no deny" {
    require_root
    require_tool ncat
    require_tool openssl

    local deny_before tls_before
    deny_before="$(l7_counter deny)"
    tls_before="$(l7_counter tls)"

    wire_start_listener 8443
    _send_client_hello "allowed.example.com"
    wire_stop_listeners

    # No rule names allowed.example.com, so the hello is counted under its
    # protocol; once it is, it had its whole chance to be counted as a deny.
    local tls_after
    tls_after="$(wait_l7_counter_above tls "$tls_before" 15)"
    [ "${tls_after%.*}" -gt "${tls_before%.*}" ] || {
        echo "the hello for allowed.example.com was never inspected: ${tls_before} -> ${tls_after}" >&2
        return 1
    }

    local deny_after
    deny_after="$(l7_counter deny)"
    [ "${deny_after%.*}" -eq "${deny_before%.*}" ] || {
        echo "a trusted SNI was counted as a deny: ${deny_before} -> ${deny_after}" >&2
        return 1
    }
}

# ── HTTP path deny on a rule created at runtime ─────────────────

@test "L7 HTTP path deny /wp-admin created via API raises its alert" {
    require_root
    require_tool ncat

    local create_body
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"deny-wp-admin","protocol":"http","action":"deny","priority":8,"path":"/wp-admin","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local deny_before
    deny_before="$(l7_counter deny)"

    wire_start_listener 8889
    send_tcp_from_ns "$EBPF_HOST_IP" 8889 $'GET /wp-admin HTTP/1.1\r\nHost: testhost\r\n\r\n' 3
    wire_stop_listeners

    local deny_after alert_found=0
    deny_after="$(wait_l7_counter_above deny "$deny_before" 15)"
    wait_for_alert \
        '.[] | select(.rule_id == "deny-wp-admin" and .component == "l7")' \
        15 1 >/dev/null && alert_found=1

    api_delete /api/v1/firewall/l7-rules/deny-wp-admin >/dev/null 2>&1 || true

    [ "${deny_after%.*}" -gt "${deny_before%.*}" ] || {
        echo "the L7 deny counter did not move after GET /wp-admin: ${deny_before} -> ${deny_after}" >&2
        return 1
    }
    [ "$alert_found" -eq 1 ] || {
        echo "no deny-wp-admin alert after GET /wp-admin" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }
}

# ── L7 metrics counter increments ──────────────────────────────

@test "L7 metrics counter increases after traffic" {
    require_root
    require_tool ncat

    # Neither path matches a rule on 8890 (the alias rule there names
    # /aliased), so both requests are counted under their protocol.
    local before
    before="$(l7_counter http)"

    wire_start_listener 8890
    send_tcp_from_ns "$EBPF_HOST_IP" 8890 $'GET /metrics-test HTTP/1.1\r\nHost: testhost\r\n\r\n' 3
    send_tcp_from_ns "$EBPF_HOST_IP" 8890 $'GET /metrics-test2 HTTP/1.1\r\nHost: testhost\r\n\r\n' 3
    wire_stop_listeners

    local after
    after="$(wait_l7_counter_above http "$((${before%.*} + 1))" 15)"
    [ "${after%.*}" -ge "$((${before%.*} + 2))" ] || {
        echo "two inspected requests did not move the L7 http counter by two: ${before} -> ${after}" >&2
        return 1
    }
}

# ── L7 rule update (via recreate) ───────────────────────────────

@test "L7 rule update via recreate" {
    require_root

    # Create a rule
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"update-test-rule","protocol":"http","action":"log","priority":60,"path":"/update-test","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # L7 rules are immutable; an "update" is delete + recreate under the
    # same id with the new fields. Recreate with a new priority and action.
    api_delete /api/v1/firewall/l7-rules/update-test-rule >/dev/null 2>&1 || true

    local update_body
    update_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"update-test-rule","protocol":"http","action":"deny","priority":15,"path":"/update-test","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Verify the new values took effect
    local new_priority
    new_priority="$(echo "$update_body" | jq -r '.priority' 2>/dev/null)" || true
    [ "$new_priority" = "15" ]

    # Clean up
    api_delete /api/v1/firewall/l7-rules/update-test-rule >/dev/null 2>&1 || true
}

# ── L7 rule disable/enable (via recreate) ───────────────────────

@test "L7 rule disable and re-enable via recreate" {
    require_root

    # Create an enabled rule
    create_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"toggle-rule","protocol":"http","action":"log","priority":70,"path":"/toggle","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Disable: recreate the rule with enabled:false (rules are immutable).
    api_delete /api/v1/firewall/l7-rules/toggle-rule >/dev/null 2>&1 || true
    local disable_body
    disable_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"toggle-rule","protocol":"http","action":"log","priority":70,"path":"/toggle","enabled":false}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    local enabled
    enabled="$(echo "$disable_body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "false" ]

    # Re-enable: recreate with enabled:true.
    api_delete /api/v1/firewall/l7-rules/toggle-rule >/dev/null 2>&1 || true
    local enable_body
    enable_body="$(api_post /api/v1/firewall/l7-rules \
        '{"id":"toggle-rule","protocol":"http","action":"log","priority":70,"path":"/toggle","enabled":true}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    enabled="$(echo "$enable_body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]

    # Clean up
    api_delete /api/v1/firewall/l7-rules/toggle-rule >/dev/null 2>&1 || true
}
