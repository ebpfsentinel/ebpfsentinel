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
#     healthy;
#   * with sampling at two, about half the flows of a six hundred connection
#     burst are left out and counted so; while the only sink is stuck on a
#     connect that gets no answer, the bounded queue drops and counts rather
#     than holding the reader of kernel events, the connect gives up after
#     its timeout and the sink says so, and readings the burst made the
#     collector miss are counted too.
#
# The flow source is the kernel connection table, which records nothing until
# something registers a netfilter hook that asks for it; the suite installs a
# table of its own with one `ct state` rule and removes it after.
#
# Requires: root, kernel >= 6.18, python3, ncat, nft, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

IPFIX_PORT=18190
SYSLOG_PORT=18191
CEF_PORT=18192
SERVICE_PORT=18193
NFT_TABLE="ebpfsentinel_flow_suite"

setup_file() {
    require_root
    require_kernel 6 18
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
    # A collector left behind by an interrupted run holds the ports and
    # writes to a file that no longer exists; this one then dies at bind.
    kill -0 "$COLLECTOR_PID" 2>/dev/null || {
        echo "the flow collector did not start:" >&2
        cat "${DATA_DIR}/collector.stderr" >&2
        return 1
    }

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

@test "the scrape agrees with the status route: sent by every sink, none failed or dropped" {
    _wait_for_flow ipfix
    local metrics
    metrics="$(scrape_metrics)"
    # Four sinks delivered, each counted under its own name.
    [ "$(echo "$metrics" | awk '/^ebpfsentinel_flows_exported_total\{sink="/ && $2 >= 1' | wc -l)" -eq 4 ] || {
        echo "$metrics" | grep -E '^ebpfsentinel_flow' >&2
        return 1
    }
    # A failure or a drop opens its series: on a healthy run neither exists.
    [ "$(echo "$metrics" | grep -c '^ebpfsentinel_flow_export_failures_total{')" -eq 0 ]
    [ "$(echo "$metrics" | grep -c '^ebpfsentinel_flows_dropped_total{')" -eq 0 ]
}

# The last test restarts the agent on a second configuration, so it runs after
# every reading of the first one.
@test "sampling leaves flows out and counts them; a full queue drops and counts rather than waits" {
    stop_ebpf_agent
    # One sink, plain TCP, towards a port whose SYN never gets an answer: the
    # dispatcher waits on the connect, so the queue fills behind it.
    local blackhole=18194
    nft add chain inet "$NFT_TABLE" output '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet "$NFT_TABLE" output tcp dport "$blackhole" drop
    local config="${DATA_DIR}/sampled.yaml"
    python3 - "$PREPARED_CONFIG" "$config" "$blackhole" <<'PY'
import sys
source, target, port = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(source).read()
# Every sink of the first configuration goes; one stuck sink replaces them.
head, rest = text.split("  ipfix:\n", 1)
tail = rest[rest.index("\n# "):]
block = f"""  sampling: 2
  queue_depth: 64
  batch_size: 1
  syslog:
    enabled: true
    targets:
      - address: "127.0.0.1:{port}"
        transport: tcp
    facility: 16
    hostname: flow-suite
"""
open(target, "w").write(head + block + tail)
PY
    start_ebpf_agent "$config"
    wait_for_ebpf_loaded 30

    # Six hundred short connections, each its own five-tuple, on a port of
    # their own so nothing left from the first configuration answers them.
    local burst_port=18195
    setsid python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1024)
while True:
    c, _ = s.accept(); c.close()
' "$EBPF_HOST_IP" "$burst_port" </dev/null >/dev/null 2>&1 &
    local listener="$!" attempt
    for attempt in $(seq 1 30); do
        ss -ltn "sport = :${burst_port}" | grep -q LISTEN && break
        sleep 0.2
    done
    ip netns exec "$EBPF_TEST_NS" python3 -c '
import socket, sys
opened = 0
for _ in range(600):
    try:
        socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
        opened += 1
    except OSError:
        pass
if opened < 500:
    sys.exit(f"only {opened} of 600 connections opened")
' "$EBPF_HOST_IP" "$burst_port"
    kill "$listener" 2>/dev/null || true

    # The burst outruns the conntrack event channel: what the collector missed
    # is counted under conntrack_lag, so seen plus missed accounts for every
    # connection, and nothing is lost without a number.
    local status metrics lag queue_full seen
    for attempt in $(seq 1 30); do
        sleep 1
        status="$(api_get "/api/v1/flows/export")"
        metrics="$(scrape_metrics)"
        lag="$(echo "$metrics" | awk '/^ebpfsentinel_flows_dropped_total\{reason="conntrack_lag"\}/ {print int($2)}')"
        seen="$(echo "$status" | jq -r '.observed')"
        [ $(( seen + ${lag:-0} )) -ge 600 ] && echo "$status" | jq -e '.queue_drops >= 1' >/dev/null && break
    done
    queue_full="$(echo "$metrics" | awk '/^ebpfsentinel_flows_dropped_total\{reason="queue_full"\}/ {print int($2)}')"
    # One flow in four is kept, decided by a hash of the five-tuple: of what
    # was seen, between three in five and nine in ten are left out.
    echo "$status" | jq -e '
        .sampling == 2 and .queue_depth == 64 and .observed >= 100
        and .sampled_out * 10 >= .observed * 3 and .sampled_out * 10 <= .observed * 7
        and .queue_drops >= 1
        and any(.sinks[]; .healthy == false and .records_failed >= 1
            and (.detail | test("no answer within")))
    ' >/dev/null || {
        echo "status: ${status}" >&2
        return 1
    }
    [ $(( seen + ${lag:-0} )) -ge 600 ] || {
        echo "seen ${seen} plus missed ${lag:-0} does not account for 600 connections" >&2
        return 1
    }
    [ "$(echo "$status" | jq -r '.queue_drops')" = "${queue_full:-0}" ] || {
        echo "status route counts $(echo "$status" | jq -r '.queue_drops') queue drops, the scrape ${queue_full:-0}" >&2
        return 1
    }
}
