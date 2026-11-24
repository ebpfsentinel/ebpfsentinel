#!/usr/bin/env bats
# 155-suricata-sets-and-reputation.bats - Suricata rules reading the sets
# and reputation lists the configuration names, loaded by a running agent.
#
# The suite asserts:
#
#   * The import report counts the five enabled rules, four compiled and
#     one refused for an `iprep` category no list declares.
#   * A DNS query for a name in the set raises the `dataset:isset` rule, and
#     one whose reputation in the second set is above the bar raises the
#     `datarep` rule; a query for a name in neither raises neither.
#   * A connection from an address the reputation list scores above the
#     bar raises the `iprep:src` rule, and the `iprep:dst` rule on the same
#     traffic stays silent, the destination being unlisted.
#
# The sets and lists are written from the lab's own addresses before the
# agent starts, because the configuration reads them at load.
#
# Requires: root, kernel >= 6.18, ncat, dig, jq

load '../lib/helpers'
load '../lib/ebpf_helpers'

DATASET_SID=9155001
DATAREP_SID=9155002
IPREP_SRC_SID=9155003
IPREP_DST_SID=9155004
REFUSED_SID=9155005

setup_file() {
    require_kernel 6 18
    require_tool ncat
    require_tool dig
    require_tool jq
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-suricata-sets-$$"
    mkdir -p "$DATA_DIR"

    # A string set holds base64 values, one per line; a reputation set adds
    # `,score` after each.
    {
        printf '%s\n' "$(printf 'bad.example' | base64)"
    } >"${DATA_DIR}/names.lst"
    {
        printf '%s,30\n' "$(printf 'bad.example' | base64)"
        printf '%s,5\n' "$(printf 'good.example' | base64)"
    } >"${DATA_DIR}/reps.lst"

    # Categories by number and short name, then an address, its category
    # and its score. The namespace end is listed and the host end is not.
    printf '1,BadHosts,Known bad hosts\n' >"${DATA_DIR}/categories.txt"
    printf '%s,1,80\n' "$EBPF_NS_IP" >"${DATA_DIR}/reputation.list"

    cat >"${DATA_DIR}/suite.rules" <<RULES
alert dns any any -> any 53 (msg:"suite dataset"; dns.query; dataset:isset,suite_names; classtype:misc-activity; sid:${DATASET_SID}; rev:1;)
alert dns any any -> any 53 (msg:"suite datarep"; dns.query; datarep:suite_reps, >, 20; classtype:misc-activity; sid:${DATAREP_SID}; rev:1;)
alert tcp any any -> any 4448 (msg:"suite iprep source"; content:"IPREP_PROBE"; iprep:src,BadHosts,>,50; classtype:misc-activity; sid:${IPREP_SRC_SID}; rev:1;)
alert tcp any any -> any 4448 (msg:"suite iprep destination"; content:"IPREP_PROBE"; iprep:dst,BadHosts,>,50; classtype:misc-activity; sid:${IPREP_DST_SID}; rev:1;)
# No list declares this category, so the rule is refused.
alert tcp any any -> any 4448 (msg:"suite iprep unknown"; content:"IPREP_PROBE"; iprep:src,Nobody,>,1; classtype:misc-activity; sid:${REFUSED_SID}; rev:1;)
RULES
    chmod 644 "${DATA_DIR}"/*

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-suricata-sets.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-suricata-sets-none}"
}

# _query <name> - one DNS query from the namespace to the host. Nothing
# answers it; the rules read the query.
_query() {
    ip netns exec "$EBPF_TEST_NS" \
        dig +tries=1 +time=1 "@${EBPF_HOST_IP}" -p 53 "$1" A >/dev/null 2>&1 || true
}

# _alerts_for <sid> - how many alerts the store holds for the rule.
_alerts_for() {
    api_get "/api/v1/alerts?limit=1000" \
        | jq --arg r "suricata-$1" '[.alerts[] | select(.rule_id == $r)] | length'
}

@test "the import report counts the compiled rules and the refused iprep" {
    local body
    body="$(api_get /api/v1/ids/suricata/report)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "report: ${HTTP_STATUS} ${body}" >&2; return 1; }

    echo "$body" | jq -e '
        (.rulesets | length) == 1
        and .rulesets[0].total == 5
        and .rulesets[0].compiled == 4
        and ([.rulesets[0].refused_by_keyword[] | select(.keyword == "iprep")][0].count) == 1
    ' >/dev/null || { echo "report: ${body}" >&2; return 1; }
}

@test "a name in neither set raises neither set rule" {
    _query good.example
    sleep 4
    [ "$(_alerts_for "$DATASET_SID")" -eq 0 ]
    [ "$(_alerts_for "$DATAREP_SID")" -eq 0 ]
}

@test "a name in the set raises the dataset rule" {
    _query bad.example
    wait_for_alert "[.[] | select(.rule_id == \"suricata-${DATASET_SID}\")] | first" 15 1 || {
        echo "no alert for suricata-${DATASET_SID}:" >&2
        api_get "/api/v1/alerts?limit=20" | jq -c '.alerts[] | {rule_id, dst_port}' >&2
        return 1
    }
}

@test "a name scored above the bar raises the datarep rule" {
    _query bad.example
    wait_for_alert "[.[] | select(.rule_id == \"suricata-${DATAREP_SID}\")] | first" 15 1 || {
        echo "no alert for suricata-${DATAREP_SID}:" >&2
        api_get "/api/v1/alerts?limit=20" | jq -c '.alerts[] | {rule_id, dst_port}' >&2
        return 1
    }
}

@test "a listed source raises the iprep source rule and not the destination one" {
    timeout 10 ncat -l "$EBPF_HOST_IP" 4448 >/dev/null 2>&1 &
    local listener=$!
    sleep 0.5
    send_tcp_from_ns "$EBPF_HOST_IP" 4448 "IPREP_PROBE" 3
    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true

    wait_for_alert "[.[] | select(.rule_id == \"suricata-${IPREP_SRC_SID}\")] | first" 15 1 || {
        echo "no alert for suricata-${IPREP_SRC_SID}:" >&2
        api_get "/api/v1/alerts?limit=20" | jq -c '.alerts[] | {rule_id, dst_port}' >&2
        return 1
    }
    [ "$(_alerts_for "$IPREP_DST_SID")" -eq 0 ]
    [ "$(_alerts_for "$REFUSED_SID")" -eq 0 ]
}
