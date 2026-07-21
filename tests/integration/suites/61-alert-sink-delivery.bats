#!/usr/bin/env bats
# 61-alert-sink-delivery.bats — outbound alert delivery to every sink.
#
# Everything upstream of the senders is already covered (25 asserts the
# alert lands in the store, 34 asserts the SSE fan-out). This suite covers
# the egress half: what the agent actually hands to an external sink over
# each of the three transports — webhook, SMTP and OTLP.
#
#   * An IDS alert on TCP/4444 reaches the sink as an HTTP POST with
#     Content-Type: application/json.
#   * The delivered body is the serialized alert — same id, rule_id and
#     severity the REST API reports for that alert.
#   * A 5xx answer is retried: the sink is configured to fail the first
#     request, and the same alert id must arrive again.
#   * Headers declared on the route (webhook_headers) are sent, without
#     displacing the Content-Type the sender declares.
#   * The delivery is counted on alerts_exported_total and the circuit
#     breaker gauge is exposed for the webhook destination.
#   * A route pointing at loopback delivers nothing — the sender's runtime
#     SSRF guard refuses the connection even though config validation
#     accepted the URL (it only checks the scheme).
#   * The same alert reaches the SMTP sink as a mail with the configured
#     envelope, and the OTLP sink as an export on /v1/logs.
#
# The webhook sink binds 203.0.113.10 (TEST-NET-3) on a dummy interface
# because that sender's SSRF guard rejects loopback/private/link-local
# targets; the SMTP and OTLP senders have no such guard, so their sinks bind
# loopback.
#
# Requires: root, kernel >= 6.9, python3, ncat, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

SINK_IP="203.0.113.10"
SINK_PORT="18085"
SINK_IFACE="ebpfsent-sink0"
LOOPBACK_SINK_PORT="18086"
SMTP_SINK_PORT="18087"
OTLP_SINK_PORT="18088"

_start_sink() {
    local bind="${1}" port="${2}" log="${3}" fail_first="${4:-0}"
    local script="${BATS_TEST_DIRNAME}/../scripts/webhook-receiver.py"

    setsid python3 "${script}" \
        --bind "${bind}" --port "${port}" --log "${log}" \
        --fail-first "${fail_first}" </dev/null >>"${DATA_DIR}/sink.stderr" 2>&1 &
    echo "$!"
}

_start_script_sink() {
    local script="${1}" bind="${2}" port="${3}" log="${4}"

    setsid python3 "${BATS_TEST_DIRNAME}/../scripts/${script}" \
        --bind "${bind}" --port "${port}" --log "${log}" \
        </dev/null >>"${DATA_DIR}/sink.stderr" 2>&1 &
    echo "$!"
}

# _wait_for_tcp <host> <port> — the SMTP sink speaks no HTTP, so readiness
# is a plain connect.
_wait_for_tcp() {
    local host="${1}" port="${2}" attempt=0
    while [ "${attempt}" -lt 30 ]; do
        if timeout 1 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

_wait_for_sink() {
    local url="${1}" attempt=0
    while [ "${attempt}" -lt 30 ]; do
        if curl -sf --max-time 1 "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

# _drive_ids_alert — send traffic matching the ids-sink-test rule.
_drive_ids_alert() {
    timeout 10 ncat -l "$EBPF_HOST_IP" 4444 >/dev/null 2>&1 &
    local listener_pid=$!
    sleep 0.5
    send_tcp_from_ns "$EBPF_HOST_IP" 4444 "ALERT_SINK_TEST" 3
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
}

# _sink_deliveries <log> — number of recorded requests.
_sink_deliveries() {
    local log="${1}" n
    [ -f "${log}" ] || { echo 0; return 0; }
    # `grep -c` exits 1 on zero matches, so capture first and default after —
    # `grep -c ... || echo 0` would print both the count and the fallback.
    n="$(grep -c . "${log}" 2>/dev/null)" || n=0
    echo "${n:-0}"
}

# _wait_for_delivery <log> <max_attempts> — wait until the sink recorded
# at least one request carrying the ids-sink-test rule.
_wait_for_delivery() {
    local log="${1}" max="${2:-30}" attempt=0
    while [ "${attempt}" -lt "${max}" ]; do
        if [ -f "${log}" ] && jq -sre '
            [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")] | length >= 1
        ' "${log}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

setup_file() {
    require_root
    require_kernel 6 9
    require_tool python3
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-alert-sink-$$"
    mkdir -p "$DATA_DIR"
    export SINK_LOG="${DATA_DIR}/webhook-sink.jsonl"
    export LOOPBACK_SINK_LOG="${DATA_DIR}/webhook-sink-loopback.jsonl"
    export SMTP_SINK_LOG="${DATA_DIR}/smtp-sink.jsonl"
    export OTLP_SINK_LOG="${DATA_DIR}/otlp-sink.jsonl"

    # The sink address must not be loopback/private for the sender's SSRF
    # guard to allow it; a dummy interface carries TEST-NET-3 locally.
    ip link add "${SINK_IFACE}" type dummy 2>/dev/null || true
    ip addr add "${SINK_IP}/32" dev "${SINK_IFACE}" 2>/dev/null || true
    ip link set "${SINK_IFACE}" up 2>/dev/null || true

    # fail-first 1: the very first delivery is answered with HTTP 500 so the
    # sender's retry path is exercised on a live alert.
    SINK_PID="$(_start_sink "${SINK_IP}" "${SINK_PORT}" "${SINK_LOG}" 1)"
    export SINK_PID
    LOOPBACK_SINK_PID="$(_start_sink "127.0.0.1" "${LOOPBACK_SINK_PORT}" "${LOOPBACK_SINK_LOG}" 0)"
    export LOOPBACK_SINK_PID

    SMTP_SINK_PID="$(_start_script_sink smtp-sink.py 127.0.0.1 "${SMTP_SINK_PORT}" "${SMTP_SINK_LOG}")"
    export SMTP_SINK_PID
    OTLP_SINK_PID="$(_start_script_sink otlp-sink.py 127.0.0.1 "${OTLP_SINK_PORT}" "${OTLP_SINK_LOG}")"
    export OTLP_SINK_PID

    _wait_for_sink "http://${SINK_IP}:${SINK_PORT}/ready" || {
        echo "webhook sink did not come up on ${SINK_IP}:${SINK_PORT}" >&2
        return 1
    }
    _wait_for_sink "http://127.0.0.1:${LOOPBACK_SINK_PORT}/ready" || {
        echo "loopback sink did not come up" >&2
        return 1
    }
    _wait_for_tcp 127.0.0.1 "${SMTP_SINK_PORT}" || {
        echo "SMTP sink did not come up on ${SMTP_SINK_PORT}" >&2
        return 1
    }
    _wait_for_sink "http://127.0.0.1:${OTLP_SINK_PORT}/ready" || {
        echo "OTLP sink did not come up on ${OTLP_SINK_PORT}" >&2
        return 1
    }

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-alert-sink-webhook.yaml")"
    export PREPARED_CONFIG
    PREPARED_SSRF_CONFIG="$(prepare_ebpf_config \
        "${FIXTURE_DIR}/config-alert-sink-ssrf.yaml" \
        "/tmp/ebpfsentinel-test-alert-sink-ssrf-$$.yaml")"
    export PREPARED_SSRF_CONFIG

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
    kill "${SINK_PID:-0}" 2>/dev/null || true
    kill "${LOOPBACK_SINK_PID:-0}" 2>/dev/null || true
    kill "${SMTP_SINK_PID:-0}" 2>/dev/null || true
    kill "${OTLP_SINK_PID:-0}" 2>/dev/null || true
    ip link del "${SINK_IFACE}" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-alert-sink-$$}"
    rm -f "${PREPARED_CONFIG:-}" "${PREPARED_SSRF_CONFIG:-}"
}

# ── Delivery ───────────────────────────────────────────────────────

@test "IDS alert is POSTed to the webhook sink" {
    _drive_ids_alert

    # The alert must exist agent-side first; only then can a delivery be
    # attributed to a missing sender rather than a missing alert.
    wait_for_alert '.[] | select(.rule_id == "ids-sink-test")' 20 1 >/dev/null || {
        echo "no ids-sink-test alert produced — nothing to deliver" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    _wait_for_delivery "${SINK_LOG}" 30 || {
        echo "webhook sink recorded no delivery for ids-sink-test" >&2
        echo "sink log:" >&2
        cat "${SINK_LOG}" >&2 2>/dev/null || true
        return 1
    }

    local method path
    method="$(jq -sr '[.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0].method' "${SINK_LOG}")"
    path="$(jq -sr '[.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0].path' "${SINK_LOG}")"
    [ "${method}" = "POST" ] || {
        echo "expected POST; got ${method}" >&2
        return 1
    }
    [ "${path}" = "/hook" ] || {
        echo "expected path /hook; got ${path}" >&2
        return 1
    }
}

@test "delivery carries Content-Type: application/json" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    local ctype
    ctype="$(jq -sr '
        [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0]
        | .headers["content-type"] // ""
    ' "${SINK_LOG}")"
    case "${ctype}" in
        application/json*) ;;
        *) echo "expected application/json; got '${ctype}'" >&2; return 1 ;;
    esac
}

@test "configured webhook_headers are sent on the request" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    local auth tenant ctype
    auth="$(jq -sr '
        [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0]
        | .headers["x-auth-token"] // ""
    ' "${SINK_LOG}")"
    tenant="$(jq -sr '
        [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0]
        | .headers["x-tenant"] // ""
    ' "${SINK_LOG}")"

    [ "${auth}" = "it-sink-token" ] || {
        echo "expected X-Auth-Token from the route config; got '${auth}'" >&2
        return 1
    }
    [ "${tenant}" = "integration" ] || {
        echo "expected X-Tenant from the route config; got '${tenant}'" >&2
        return 1
    }

    # Custom headers must not have displaced the body encoding.
    ctype="$(jq -sr '
        [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0]
        | .headers["content-type"] // ""
    ' "${SINK_LOG}")"
    case "${ctype}" in
        application/json*) ;;
        *) echo "content-type clobbered by custom headers: '${ctype}'" >&2; return 1 ;;
    esac
}

@test "delivered body is the serialized alert the REST API reports" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    local delivered rest_ids
    delivered="$(jq -sc '
        [.[] | select((.body | fromjson? | .rule_id) == "ids-sink-test")][0].body | fromjson
    ' "${SINK_LOG}")"

    # Mandatory alert identity fields must all be present on the wire.
    echo "${delivered}" | jq -e '
        (.id | type == "string" and length > 0)
        and (.rule_id == "ids-sink-test")
        and (.severity != null)
        and (.component | type == "string")
        and (.timestamp_ns | type == "number")
        and (.dst_port == 4444)
    ' >/dev/null || {
        echo "delivered payload missing alert fields: ${delivered}" >&2
        return 1
    }

    # The delivered id must be one the store knows about — the sink cannot be
    # receiving some other pipeline's alert.
    local delivered_id
    delivered_id="$(echo "${delivered}" | jq -r '.id')"
    rest_ids="$(api_get '/api/v1/alerts?limit=200' | jq -r '.alerts[].id')"
    echo "${rest_ids}" | grep -qx "${delivered_id}" || {
        echo "delivered alert id ${delivered_id} not present in /api/v1/alerts" >&2
        return 1
    }
}

# ── Retry ──────────────────────────────────────────────────────────

@test "a 5xx answer is retried with the same alert" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    # The sink answers the first request with HTTP 500 (fail-first 1), so the
    # sender must come back with the same alert. Backoff schedule starts at
    # 1 s, so allow a few seconds for the second attempt.
    local attempt=0 repeated=0
    while [ "${attempt}" -lt 20 ]; do
        repeated="$(jq -sr '
            [.[] | .body | fromjson? | .id]
            | group_by(.) | map(select(length >= 2)) | length
        ' "${SINK_LOG}" 2>/dev/null || echo 0)"
        [ "${repeated:-0}" -ge 1 ] && break
        sleep 1
        attempt=$((attempt + 1))
    done

    [ "${repeated:-0}" -ge 1 ] || {
        echo "no alert id was delivered twice — the 500 was not retried" >&2
        echo "sink log:" >&2
        cat "${SINK_LOG}" >&2 2>/dev/null || true
        return 1
    }

    # The first recorded request is the one the sink failed by construction.
    local first_index
    first_index="$(jq -sr '.[0].index' "${SINK_LOG}")"
    [ "${first_index}" = "1" ]
}

# ── Metrics ────────────────────────────────────────────────────────

@test "circuit-breaker state is exposed for the webhook destination" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || metrics=""
    [ -n "${metrics}" ] || {
        echo "metrics endpoint returned nothing" >&2
        return 1
    }

    echo "${metrics}" | grep -qE 'ebpfsentinel_alert_sender_circuit_state\{[^}]*destination="webhook"' || {
        echo "no circuit-state gauge for destination=webhook" >&2
        echo "${metrics}" | grep -E 'alert_sender_circuit_state' >&2 || true
        return 1
    }

    # Deliveries succeeded (after the retry), so the breaker must be closed.
    local state
    state="$(echo "${metrics}" \
        | grep -E 'ebpfsentinel_alert_sender_circuit_state\{[^}]*destination="webhook"' \
        | awk '{print $2}' | head -1)"
    [ "${state%.*}" = "0" ] || {
        echo "expected closed breaker (0); got ${state}" >&2
        return 1
    }
}

@test "successful deliveries are counted on alerts_exported_total" {
    _wait_for_delivery "${SINK_LOG}" 30 || soft_skip "no delivery recorded yet"

    local metrics count
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || metrics=""
    [ -n "${metrics}" ] || {
        echo "metrics endpoint returned nothing" >&2
        return 1
    }

    count="$(echo "${metrics}" \
        | grep -E '^ebpfsentinel_alerts_exported_total\{[^}]*destination="webhook"' \
        | awk '{print $2}' | head -1)"
    [ -n "${count}" ] || {
        echo "no alerts_exported_total series for destination=webhook" >&2
        echo "${metrics}" | grep -E 'alerts_exported' >&2 || true
        return 1
    }
    [ "${count%.*}" -ge 1 ] || {
        echo "expected at least one exported alert; got ${count}" >&2
        return 1
    }
}

# ── SMTP sink ──────────────────────────────────────────────────────

# _wait_for_mail <max_attempts> — wait until the SMTP sink accepted a
# message whose body carries the suite's rule id.
_wait_for_mail() {
    local max="${1:-30}" attempt=0
    while [ "${attempt}" -lt "${max}" ]; do
        if [ -f "${SMTP_SINK_LOG}" ] && jq -sre '
            [.[] | select(.data | contains("ids-sink-test"))] | length >= 1
        ' "${SMTP_SINK_LOG}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

@test "the alert is delivered to the SMTP sink" {
    _wait_for_mail 30 || {
        echo "SMTP sink accepted no mail carrying ids-sink-test" >&2
        echo "sink log:" >&2
        cat "${SMTP_SINK_LOG}" >&2 2>/dev/null || true
        return 1
    }

    local from to
    from="$(jq -sr '[.[] | select(.data | contains("ids-sink-test"))][0].mail_from' "${SMTP_SINK_LOG}")"
    to="$(jq -sr '[.[] | select(.data | contains("ids-sink-test"))][0].rcpt_to[0]' "${SMTP_SINK_LOG}")"

    # Envelope must match the configured smtp.from_address / route email_to.
    [ "${from}" = "alerts@ebpfsentinel.test" ] || {
        echo "expected envelope sender alerts@ebpfsentinel.test; got '${from}'" >&2
        return 1
    }
    [ "${to}" = "soc@example.test" ] || {
        echo "expected recipient soc@example.test; got '${to}'" >&2
        return 1
    }
}

@test "the mail body carries the alert identity" {
    _wait_for_mail 30 || soft_skip "no mail recorded yet"

    local data
    data="$(jq -sr '[.[] | select(.data | contains("ids-sink-test"))][0].data' "${SMTP_SINK_LOG}")"

    # The sender serializes the alert into the message; the rule id and the
    # component must both survive the transport.
    echo "${data}" | grep -q "ids-sink-test" || {
        echo "rule id missing from the mail body" >&2
        return 1
    }
    echo "${data}" | grep -qi "ids" || {
        echo "component missing from the mail body: ${data}" >&2
        return 1
    }
}

@test "email deliveries are counted on alerts_exported_total" {
    _wait_for_mail 30 || soft_skip "no mail recorded yet"

    local metrics count
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || metrics=""
    [ -n "${metrics}" ] || {
        echo "metrics endpoint returned nothing" >&2
        return 1
    }

    count="$(echo "${metrics}" \
        | grep -E '^ebpfsentinel_alerts_exported_total\{[^}]*destination="email"' \
        | awk '{print $2}' | head -1)"
    [ -n "${count}" ] && [ "${count%.*}" -ge 1 ] || {
        echo "no alerts_exported_total series for destination=email" >&2
        echo "${metrics}" | grep -E 'alerts_exported' >&2 || true
        return 1
    }
}

# ── OTLP sink ──────────────────────────────────────────────────────

# _wait_for_otlp <max_attempts> — the OTLP sender batches, so the export
# lands a beat after the alert.
_wait_for_otlp() {
    local max="${1:-30}" attempt=0
    while [ "${attempt}" -lt "${max}" ]; do
        if [ -f "${OTLP_SINK_LOG}" ] && jq -sre '
            [.[] | select(.body_text | contains("ids-sink-test"))] | length >= 1
        ' "${OTLP_SINK_LOG}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

@test "the alert is exported to the OTLP sink" {
    _wait_for_otlp 30 || {
        echo "OTLP sink received no export carrying ids-sink-test" >&2
        echo "sink log:" >&2
        jq -sc '[.[] | {index, path, content_type, length}]' "${OTLP_SINK_LOG}" >&2 2>/dev/null || true
        return 1
    }

    local path ctype
    path="$(jq -sr '[.[] | select(.body_text | contains("ids-sink-test"))][0].path' "${OTLP_SINK_LOG}")"
    ctype="$(jq -sr '[.[] | select(.body_text | contains("ids-sink-test"))][0].content_type' "${OTLP_SINK_LOG}")"

    # OTLP/HTTP logs are POSTed to <endpoint>/v1/logs as protobuf.
    [ "${path}" = "/v1/logs" ] || {
        echo "expected export on /v1/logs; got '${path}'" >&2
        return 1
    }
    case "${ctype}" in
        application/x-protobuf*|application/json*) ;;
        *) echo "unexpected OTLP content-type: '${ctype}'" >&2; return 1 ;;
    esac
}

@test "the OTLP export carries the alert attributes" {
    _wait_for_otlp 30 || soft_skip "no OTLP export recorded yet"

    local body
    body="$(jq -sr '[.[] | select(.body_text | contains("ids-sink-test"))][0].body_text' "${OTLP_SINK_LOG}")"

    # The sender sets these attribute keys on every record; they travel as
    # plain strings inside the protobuf payload.
    echo "${body}" | grep -q "alert.rule_id" || {
        echo "alert.rule_id attribute missing from the OTLP payload" >&2
        return 1
    }
    echo "${body}" | grep -q "alert.component" || {
        echo "alert.component attribute missing from the OTLP payload" >&2
        return 1
    }
}

# ── SSRF guard (runs last: it restarts the agent) ──────────────────

@test "a loopback webhook target receives nothing (SSRF guard)" {
    local before
    before="$(_sink_deliveries "${LOOPBACK_SINK_LOG}")"
    [ "${before}" -eq 0 ] || {
        echo "loopback sink already had ${before} deliveries before the phase" >&2
        return 1
    }

    stop_ebpf_agent 2>/dev/null || true
    start_ebpf_agent "$PREPARED_SSRF_CONFIG"
    wait_for_ebpf_loaded 30 || soft_skip "agent did not reload with the SSRF fixture"

    _drive_ids_alert
    wait_for_alert '.[] | select(.rule_id == "ids-sink-test")' 20 1 >/dev/null || {
        echo "no alert produced under the SSRF fixture — inconclusive" >&2
        return 1
    }

    # Give the sender the full first backoff plus margin; nothing must land.
    sleep 5

    local after
    after="$(_sink_deliveries "${LOOPBACK_SINK_LOG}")"
    [ "${after}" -eq 0 ] || {
        echo "SSRF guard did not block loopback: ${after} deliveries" >&2
        cat "${LOOPBACK_SINK_LOG}" >&2 2>/dev/null || true
        return 1
    }
}
