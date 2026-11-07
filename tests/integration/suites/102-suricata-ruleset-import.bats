#!/usr/bin/env bats
# 102-suricata-ruleset-import.bats - a Suricata ruleset compiled into
# detection rules, its report, and the alert one of its rules raises.
#
# The suite asserts:
#
#   * The import report names the ruleset file, counts its three enabled
#     rules, two of them compiled and one refused for `flowbits`, and the
#     refused share it computed from them.
#   * The compiled rules are detection rules the IDS lists, under the
#     `suricata-<sid>` identifier.
#   * A connection whose payload carries the rule's content raises an
#     alert under that identifier, and one to the same port without the
#     content raises nothing.
#   * The refused rule raises nothing for traffic it would have matched.
#
# Requires: root, kernel >= 6.12, ncat, jq

load '../lib/helpers'
load '../lib/ebpf_helpers'

CONTENT_SID=9100001
SECOND_SID=9100003
REFUSED_SID=9100002

setup_file() {
    require_kernel 6 12
    require_tool ncat
    require_tool jq
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-suricata-$$"
    mkdir -p "$DATA_DIR"

    # The ruleset is read when the configuration is loaded, so it is on
    # disk before the agent starts.
    cat >"${DATA_DIR}/suite.rules" <<RULES
# Two rules the compiler takes: a content match on a lab port, and one
# with a second content on another port.
alert tcp any any -> any 4445 (msg:"suite ruleset probe"; flow:established,to_server; content:"SURICATA_PROBE"; nocase; classtype:misc-activity; sid:${CONTENT_SID}; rev:1;)
alert tcp any any -> any 4447 (msg:"suite ruleset second"; flow:established,to_server; content:"alpha"; content:"omega"; distance:0; classtype:misc-activity; sid:${SECOND_SID}; rev:1;)
# State carried between rules is not compiled, and is reported as refused.
alert tcp any any -> any 4446 (msg:"suite ruleset flowbits"; flow:established,to_server; flowbits:isset,suite.seen; content:"FLOWBITS_PROBE"; classtype:misc-activity; sid:${REFUSED_SID}; rev:1;)
RULES
    chmod 644 "${DATA_DIR}/suite.rules"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-suricata-import.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-suricata-none}"
}

# _send <port> <payload> - one connection from the namespace carrying the
# payload, to a listener on the host.
_send() {
    local port="$1" payload="$2"
    timeout 10 ncat -l "$EBPF_HOST_IP" "$port" >/dev/null 2>&1 &
    local listener=$!
    sleep 0.5
    send_tcp_from_ns "$EBPF_HOST_IP" "$port" "$payload" 3
    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true
}

# _alerts_for <rule_id> - how many alerts the store holds for the rule.
_alerts_for() {
    api_get "/api/v1/alerts?limit=1000" \
        | jq --arg r "$1" '[.alerts[] | select(.rule_id == $r)] | length'
}

@test "the import report counts the ruleset's compiled and refused rules" {
    local body
    body="$(api_get /api/v1/ids/suricata/report)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "report: ${HTTP_STATUS} ${body}" >&2; return 1; }

    echo "$body" | jq -e --arg src "${DATA_DIR}/suite.rules" '
        (.rulesets | length) == 1
        and (.rulesets[0].source | endswith("suite.rules"))
        and .rulesets[0].total == 3
        and .rulesets[0].compiled == 2
        and ([.rulesets[0].refused_by_keyword[] | select(.keyword == "flowbits")][0].count) == 1
        and (.rulesets[0].refused_share > 0.3 and .rulesets[0].refused_share < 0.4)
    ' >/dev/null || { echo "report: ${body}" >&2; return 1; }
}

@test "the compiled rules are IDS rules under their sid" {
    local body
    body="$(api_get /api/v1/ids/rules)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    local ids
    ids="$(echo "$body" | jq -r '(if type == "array" then . else (.rules // []) end)[] | .id')"
    echo "$ids" | grep -qx "suricata-${CONTENT_SID}" || { echo "rules: ${ids}" >&2; return 1; }
    echo "$ids" | grep -qx "suricata-${SECOND_SID}"
    ! echo "$ids" | grep -qx "suricata-${REFUSED_SID}"
}

@test "a payload carrying the content raises an alert under the rule's sid" {
    _send 4445 "GET /x HTTP/1.0 suricata_probe here"
    wait_for_alert "[.[] | select(.rule_id == \"suricata-${CONTENT_SID}\")] | first" 15 1 || {
        echo "no alert for suricata-${CONTENT_SID}:" >&2
        api_get "/api/v1/alerts?limit=20" | jq -c '.alerts[] | {rule_id, dst_port}' >&2
        return 1
    }
}

@test "the same port without the content raises nothing" {
    local before after
    before="$(_alerts_for "suricata-${SECOND_SID}")"
    # Only the first of the two contents: the rule needs both.
    _send 4447 "alpha and nothing else"
    sleep 4
    after="$(_alerts_for "suricata-${SECOND_SID}")"
    [ "$after" -eq "$before" ] || { echo "suricata-${SECOND_SID}: ${before} -> ${after}" >&2; return 1; }

    # Both contents, in order: now it fires.
    _send 4447 "alpha then omega"
    wait_for_alert "[.[] | select(.rule_id == \"suricata-${SECOND_SID}\")] | first" 15 1
}

@test "the refused rule raises nothing for the traffic it names" {
    _send 4446 "FLOWBITS_PROBE"
    sleep 4
    [ "$(_alerts_for "suricata-${REFUSED_SID}")" -eq 0 ]
}
