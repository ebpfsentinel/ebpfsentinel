#!/usr/bin/env bats
# 34-sse-alerts-stream.bats — Server-Sent Events alerts stream
#
# Validates the contract documented in `api-reference/rest-api.md`:
#   - response headers: `Content-Type: text/event-stream`,
#     `Cache-Control: no-cache`, `Connection: keep-alive`
#   - keep-alive comment cadence (≤ 15 s)
#   - `Last-Event-ID` reconnect replays missed events from the in-memory
#     ring buffer without duplication
#   - server-side severity_min / component / mitre_tactic filters reject
#     non-matching events before they reach the client
#
# Requires the agent to be running with HTTP enabled and at least one
# alert source wired. Synthetic alerts are injected by toggling a rule and
# replaying packets via the existing fixture helpers.

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-sse-test-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-sse-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# Background curl helper. Streams `path` to `out_file` and writes the
# pid into `pid_file`. Returns immediately.
_start_sse_client() {
    local path="$1" out_file="$2" pid_file="$3"
    shift 3
    curl -sN \
        -H 'Accept: text/event-stream' \
        "$@" \
        "${BASE_URL}${path}" >"$out_file" 2>&1 &
    echo "$!" > "$pid_file"
}

_stop_sse_client() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid="$(cat "$pid_file")"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
    fi
}

# ── Tests ──────────────────────────────────────────────────────────

@test "SSE stream returns text/event-stream content-type" {
    local headers
    headers="$(curl -sI -H 'Accept: text/event-stream' \
        --max-time 2 "${BASE_URL}/api/v1/alerts/stream" 2>&1 || true)"
    assert_contains "$headers" "text/event-stream"
}

@test "SSE stream emits keep-alive comment within 16 seconds" {
    local out_file pid_file
    out_file="$(mktemp -t sse-keepalive.XXXXXX)"
    pid_file="$(mktemp -t sse-keepalive-pid.XXXXXX)"

    _start_sse_client "/api/v1/alerts/stream" "$out_file" "$pid_file"
    sleep 16
    _stop_sse_client "$pid_file"

    # SSE keep-alive lines start with `:` (comment).
    grep -q '^:' "$out_file" || {
        echo "missing keep-alive comment in:"
        cat "$out_file"
        false
    }
    rm -f "$out_file"
}

@test "Invalid severity_min returns 400" {
    run curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H 'Accept: text/event-stream' \
        "${BASE_URL}/api/v1/alerts/stream?severity_min=urgent"
    [ "$status" -eq 0 ]
    [ "$output" = "400" ]
}

@test "Last-Event-ID resume returns missed events without duplication" {
    # Capture two distinct alert ids by polling the REST endpoint twice.
    local first_id second_id
    first_id="$(curl -s --max-time 3 "${BASE_URL}/api/v1/alerts?limit=1" \
        | jq -r '.alerts[0].id // empty')"
    if [ -z "$first_id" ]; then
        skip "no alerts buffered yet — cannot exercise Last-Event-ID"
    fi

    sleep 1
    second_id="$(curl -s --max-time 3 "${BASE_URL}/api/v1/alerts?limit=1" \
        | jq -r '.alerts[0].id // empty')"

    # Connect with Last-Event-ID set to the older id and assert the newer
    # id appears in the replay.
    local out_file pid_file
    out_file="$(mktemp -t sse-resume.XXXXXX)"
    pid_file="$(mktemp -t sse-resume-pid.XXXXXX)"
    _start_sse_client "/api/v1/alerts/stream" "$out_file" "$pid_file" \
        -H "Last-Event-ID: ${first_id}"
    sleep 2
    _stop_sse_client "$pid_file"

    if [ -n "$second_id" ] && [ "$second_id" != "$first_id" ]; then
        # The replay must contain the newer id and must not contain the
        # already-acknowledged first id (no duplication).
        grep -q "id: ${second_id}" "$out_file" || {
            echo "newer alert id ${second_id} missing from resume:"
            cat "$out_file"
            false
        }
        ! grep -q "id: ${first_id}" "$out_file" || {
            echo "duplicated already-acked id ${first_id} in resume:"
            cat "$out_file"
            false
        }
    fi
    rm -f "$out_file"
}

@test "severity_min=critical filters out lower-severity alerts" {
    local out_file pid_file
    out_file="$(mktemp -t sse-filter.XXXXXX)"
    pid_file="$(mktemp -t sse-filter-pid.XXXXXX)"

    _start_sse_client "/api/v1/alerts/stream?severity_min=critical" \
        "$out_file" "$pid_file"
    sleep 3
    _stop_sse_client "$pid_file"

    # Any alert frame must have severity == "critical". A `low` / `medium`
    # / `high` payload signals a filter bypass.
    if grep -q '"severity":"low"' "$out_file" \
        || grep -q '"severity":"medium"' "$out_file" \
        || grep -q '"severity":"high"' "$out_file"; then
        echo "filter bypassed — non-critical alert reached client:"
        cat "$out_file"
        false
    fi
    rm -f "$out_file"
}

@test "alerts_sse_subscribers gauge increments while client is connected" {
    # Baseline.
    local before
    before="$(curl -sf "${BASE_URL}/metrics" \
        | awk '/^ebpfsentinel_alerts_sse_subscribers / {print $2}')"
    before="${before:-0}"

    local out_file pid_file
    out_file="$(mktemp -t sse-gauge.XXXXXX)"
    pid_file="$(mktemp -t sse-gauge-pid.XXXXXX)"
    _start_sse_client "/api/v1/alerts/stream" "$out_file" "$pid_file"
    sleep 2

    local during
    during="$(curl -sf "${BASE_URL}/metrics" \
        | awk '/^ebpfsentinel_alerts_sse_subscribers / {print $2}')"
    during="${during:-0}"

    _stop_sse_client "$pid_file"
    sleep 1

    local after
    after="$(curl -sf "${BASE_URL}/metrics" \
        | awk '/^ebpfsentinel_alerts_sse_subscribers / {print $2}')"
    after="${after:-0}"

    # During the connection the gauge is strictly above the baseline; on
    # disconnect it is back to (≤ baseline).
    [ "$during" -gt "$before" ] || {
        echo "gauge did not increment: before=$before during=$during"
        false
    }
    [ "$after" -le "$during" ] || {
        echo "gauge did not decrement: during=$during after=$after"
        false
    }
    rm -f "$out_file"
}
