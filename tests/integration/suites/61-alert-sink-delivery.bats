#!/usr/bin/env bats
# 61-alert-sink-delivery.bats — outbound alert delivery to a webhook sink.
#
# Everything upstream of the senders is already covered (25 asserts the
# alert lands in the store, 34 asserts the SSE fan-out). This suite covers
# the egress half: what the agent actually POSTs to an external sink.
#
#   * An IDS alert on TCP/4444 reaches the sink as an HTTP POST with
#     Content-Type: application/json.
#   * The delivered body is the serialized alert — same id, rule_id and
#     severity the REST API reports for that alert.
#   * A 5xx answer is retried: the sink is configured to fail the first
#     request, and the same alert id must arrive again.
#   * The circuit-breaker gauge is exposed for the webhook destination.
#   * A route pointing at loopback delivers nothing — the sender's runtime
#     SSRF guard refuses the connection even though config validation
#     accepted the URL (it only checks the scheme).
#
# The sink binds 203.0.113.10 (TEST-NET-3) on a dummy interface because the
# SSRF guard rejects loopback/private/link-local targets.
#
# Requires: root, kernel >= 6.9, python3, ncat, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

SINK_IP="203.0.113.10"
SINK_PORT="18085"
SINK_IFACE="ebpfsent-sink0"
LOOPBACK_SINK_PORT="18086"

_start_sink() {
    local bind="${1}" port="${2}" log="${3}" fail_first="${4:-0}"
    local script="${BATS_TEST_DIRNAME}/../scripts/webhook-receiver.py"

    setsid python3 "${script}" \
        --bind "${bind}" --port "${port}" --log "${log}" \
        --fail-first "${fail_first}" </dev/null >>"${DATA_DIR}/sink.stderr" 2>&1 &
    echo "$!"
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
    local log="${1}"
    [ -f "${log}" ] || { echo 0; return 0; }
    grep -c . "${log}" 2>/dev/null || echo 0
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

    _wait_for_sink "http://${SINK_IP}:${SINK_PORT}/ready" || {
        echo "webhook sink did not come up on ${SINK_IP}:${SINK_PORT}" >&2
        return 1
    }
    _wait_for_sink "http://127.0.0.1:${LOOPBACK_SINK_PORT}/ready" || {
        echo "loopback sink did not come up" >&2
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
    _wait_for_delivery "${SINK_LOG}" 30 || skip "no delivery recorded yet"

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

@test "delivered body is the serialized alert the REST API reports" {
    _wait_for_delivery "${SINK_LOG}" 30 || skip "no delivery recorded yet"

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
    _wait_for_delivery "${SINK_LOG}" 30 || skip "no delivery recorded yet"

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
    _wait_for_delivery "${SINK_LOG}" 30 || skip "no delivery recorded yet"

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
    wait_for_ebpf_loaded 30 || skip "agent did not reload with the SSRF fixture"

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
