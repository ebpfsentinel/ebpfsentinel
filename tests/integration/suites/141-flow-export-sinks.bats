#!/usr/bin/env bats
# 141-flow-export-sinks.bats - a connection on the wire leaves as a flow record
# in every format the export page promises.
#
# The unit tests encode records they build themselves. This suite starts from a
# TCP connection the kernel tracked and reads what a collector receives:
#
#   * IPFIX over UDP: the template set comes first, and the data record decoded
#     with it carries the connection's five-tuple, packet and octet counts in
#     both directions, an end reason and the configured observation domain;
#   * RFC 5424 syslog over TCP, octet counted: the envelope carries facility
#     and severity, the configured hostname and the `flow` message id, and the
#     message is the same five-tuple as key=value pairs;
#   * CEF over UDP: the header names the vendor, product and agent version, the
#     message id is `CEF`, and the extension holds the same five-tuple;
#   * JSON lines on disk hold the same flow;
#   * the status route counts what each sink sent and reports every sink
#     healthy.
#
# The flow source is the kernel connection table, which records nothing until
# something registers a netfilter hook that asks for it; the suite installs a
# table of its own with one `ct state` rule and removes it after.
#
# Requires: root, kernel >= 6.12, python3, ncat, nft, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

IPFIX_PORT=18190
SYSLOG_PORT=18191
CEF_PORT=18192
SERVICE_PORT=18193
NFT_TABLE="ebpfsentinel_flow_suite"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool python3
    require_tool ncat
    require_tool nft
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-flow-export-$$"
    mkdir -p "$DATA_DIR"
    export FLOW_LOG="${DATA_DIR}/collector.jsonl"

    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" input '{ type filter hook input priority 0; policy accept; }'
    nft add rule inet "$NFT_TABLE" input ct state new counter accept

    setsid python3 "${BATS_TEST_DIRNAME}/../scripts/flow-collector.py" \
        --ipfix-port "$IPFIX_PORT" --syslog-port "$SYSLOG_PORT" --cef-port "$CEF_PORT" \
        --log "$FLOW_LOG" </dev/null >>"${DATA_DIR}/collector.stderr" 2>&1 &
    export COLLECTOR_PID="$!"
    local attempt
    for attempt in $(seq 1 30); do
        (exec 3<>"/dev/tcp/127.0.0.1/${SYSLOG_PORT}") 2>/dev/null && break
        sleep 0.2
    done

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-flow-export.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs not loaded (degraded mode)" >&2
        return 1
    }

    # One connection the export is asked to describe: a request out of the
    # namespace and an answer back, so both directions carry packets.
    timeout 20 ncat -lk "$EBPF_HOST_IP" "$SERVICE_PORT" -c 'head -c 64; printf "FLOW-ANSWER\n"' \
        >/dev/null 2>&1 &
    export SERVICE_PID="$!"
    sleep 0.5
    send_tcp_from_ns "$EBPF_HOST_IP" "$SERVICE_PORT" "FLOW-EXPORT-SUITE-REQUEST-PADDED-TO-SIXTY-FOUR-BYTES-0123456789A" 3
}

teardown_file() {
    kill "${SERVICE_PID:-0}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    kill "${COLLECTOR_PID:-0}" 2>/dev/null || true
    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-flow-export-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _received <channel> [jq filter] - the collector's records for one channel.
_received() {
    jq -c --arg ch "$1" "select(.channel == \$ch) | ${2:-.}" "$FLOW_LOG" 2>/dev/null
}

# _ours <channel> - records of the suite's connection, keyed the way the
# format writes the five-tuple.
_ours() {
    case "$1" in
        ipfix)
            _received ipfix "select(.fields[\"12\"] == \"${EBPF_HOST_IP}\" and .fields[\"11\"] == ${SERVICE_PORT})"
            ;;
        *)
            _received "$1" "select(.kv.dst == \"${EBPF_HOST_IP}\" and .kv.dpt == \"${SERVICE_PORT}\")"
            ;;
    esac
}

# _wait_for_flow <channel> - the suite's connection reached that collector.
_wait_for_flow() {
    local attempt
    for attempt in $(seq 1 30); do
        [ -n "$(_ours "$1")" ] && return 0
        sleep 1
    done
    echo "no ${1} record of the connection; the collector got:" >&2
    tail -5 "$FLOW_LOG" >&2
    api_get "/api/v1/flows/export" >&2
    return 1
}

@test "IPFIX: the template set arrives before any data record" {
    _wait_for_flow ipfix
    jq -se '
        (map(.channel) | index("ipfix-template")) as $t
        | (map(.channel) | index("ipfix")) as $d
        | $t != null and $d != null and $t < $d
    ' "$FLOW_LOG" >/dev/null || {
        echo "order of arrival: $(jq -r .channel "$FLOW_LOG" | uniq -c | head -5)" >&2
        return 1
    }
    [ -z "$(_received ipfix-error)" ] || {
        _received ipfix-error >&2
        return 1
    }
    _received ipfix-template | jq -se 'map(.template) | index(256) != null' >/dev/null
}

@test "IPFIX: the record carries the five-tuple, both directions' counters and an end reason" {
    _wait_for_flow ipfix
    _ours ipfix | head -1 | jq -e --arg src "$EBPF_NS_IP" '
        .domain == 41 and .template == 256
        and .fields["8"] == $src and .fields["4"] == 6 and .fields["7"] > 0
        and .fields["2"] >= 3 and .fields["1"] > 64
        and .reverse["2"] >= 2 and .reverse["1"] > 0
        and .fields["153"] >= .fields["152"]
        and (.fields["136"] | IN(1, 2, 3))
    ' >/dev/null || {
        echo "not the connection as the kernel saw it: $(_ours ipfix | head -1)" >&2
        return 1
    }
}

@test "syslog: an RFC 5424 envelope, octet counted over TCP, around the five-tuple" {
    _wait_for_flow syslog
    [ -z "$(_received syslog-error)" ]
    _ours syslog | head -1 | jq -e --arg src "$EBPF_NS_IP" '
        .pri == 134 and .version == 1 and .hostname == "flow-suite"
        and .app == "ebpfsentinel" and .msgid == "flow" and .sd == "-"
        and (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$"))
        and .kv.src == $src and .kv.proto == "tcp"
        and (.kv.flowPackets | tonumber) >= 3 and (.kv.out | tonumber) > 64
        and (.kv.flowEndReason | length) > 0
    ' >/dev/null || {
        echo "syslog got: $(_ours syslog | head -1)" >&2
        return 1
    }
}

@test "CEF: the header names the sender and the extension holds the same flow" {
    _wait_for_flow cef
    local version
    version="$(api_get "/api/v1/agent/status" | jq -r '.version // empty')"
    _ours cef | head -1 | jq -e --arg src "$EBPF_NS_IP" --arg v "${version}" '
        .msgid == "CEF" and .hostname == "flow-suite"
        and .cef.version == "CEF:0" and .cef.vendor == "eBPFsentinel"
        and .cef.product == "Agent" and .cef.signature == "flow"
        and .cef.name == "network flow" and .cef.severity == "1"
        and ($v == "" or .cef.device_version == $v)
        and .kv.src == $src and .kv.proto == "tcp" and (.kv.spt | tonumber) > 0
    ' >/dev/null || {
        echo "CEF got: $(_ours cef | head -1)" >&2
        return 1
    }
}

@test "the three collectors and the file describe one connection" {
    _wait_for_flow ipfix
    _wait_for_flow syslog
    _wait_for_flow cef
    local ipfix_port syslog_port cef_port
    ipfix_port="$(_ours ipfix | head -1 | jq -r '.fields["7"]')"
    syslog_port="$(_ours syslog | head -1 | jq -r '.kv.spt')"
    cef_port="$(_ours cef | head -1 | jq -r '.kv.spt')"
    [ "$ipfix_port" = "$syslog_port" ] && [ "$syslog_port" = "$cef_port" ] || {
        echo "source ports differ: ipfix ${ipfix_port} syslog ${syslog_port} cef ${cef_port}" >&2
        return 1
    }
    jq -e -s --arg dst "$EBPF_HOST_IP" --argjson sport "$ipfix_port" --argjson dport "$SERVICE_PORT" '
        any(.[]; ."destination.address" == $dst and (."source.port" | tonumber) == $sport
            and (."destination.port" | tonumber) == $dport)
    ' "${DATA_DIR}/flows.jsonl" >/dev/null || {
        echo "the JSON lines file does not hold the flow: $(tail -2 "${DATA_DIR}/flows.jsonl" 2>/dev/null)" >&2
        return 1
    }
}

@test "the status route counts what every sink sent and reports each healthy" {
    _wait_for_flow ipfix
    local status
    status="$(api_get "/api/v1/flows/export")"
    echo "$status" | jq -e '
        .enabled == true and .exported >= 1 and .queue_drops == 0
        and .idle_timeout_secs == 2
        and (.sinks | length) == 4
        and all(.sinks[]; .healthy == true and .records_sent >= 1 and .records_failed == 0)
    ' >/dev/null || {
        echo "status: ${status}" >&2
        return 1
    }
}
