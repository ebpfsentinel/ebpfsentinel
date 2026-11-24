#!/usr/bin/env bats
# 150-dlp-whole-record.bats - the DLP probes read a whole TLS record.
#
# The suite asserts:
#
#   * The kernel-features route answers `dlp_whole_record`, active or with
#     its cause and reason, and the start-up log says which of the two reads
#     the probes run.
#   * Where it is active, a secret 12,000 bytes into one `SSL_write` raises
#     a DLP alert: the bounded copy stops at 4,096 bytes and would not see it.
#   * A secret inside the first 4,096 bytes raises one whichever read runs.
#   * `dlp.record_bytes` outside 4096..=16384 stops the agent, naming the key
#     and the range, and a reload that changes it names it in
#     `pending_restart`.
#
# Requires: root, kernel >= 6.18, bpftool, jq, openssl, curl linked against
# OpenSSL (the probes attach to libssl).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/uprobe_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool jq
    require_tool openssl
    require_tool curl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dlp-record-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dlp-record.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }
    wait_for_uprobe_link ssl_write 20

    openssl req -x509 -newkey rsa:2048 -keyout "$DATA_DIR/tls.key" \
        -out "$DATA_DIR/tls.crt" -days 1 -nodes -subj '/CN=localhost' 2>/dev/null
    nohup openssl s_server -accept 9445 -cert "$DATA_DIR/tls.crt" \
        -key "$DATA_DIR/tls.key" -www >/dev/null 2>&1 &
    echo $! >"$DATA_DIR/tls_server.pid"
    sleep 1
}

teardown_file() {
    [ -f "${DATA_DIR}/tls_server.pid" ] && kill "$(cat "$DATA_DIR/tls_server.pid")" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dlp-record-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# The kernel-features entry for the whole-record read.
_capability() {
    api_get /api/v1/ebpf/kernel-features | jq -c '.capabilities[] | select(.id == "dlp_whole_record")'
}

# Count DLP alerts currently held by the agent.
_dlp_alerts() {
    local body
    body="$(api_get /api/v1/alerts)"
    echo "${body}" | jq '[(.alerts // .)[] | select(.component == "dlp")] | length' 2>/dev/null || echo 0
}

# POST a body of `size` bytes whose secret sits `offset` bytes in, in one
# request curl hands to SSL_write as one buffer.
_post_with_secret_at() {
    local offset="$1" size="$2" secret="$3" file="$DATA_DIR/body-$1"
    {
        head -c "$offset" /dev/zero | tr '\0' 'a'
        printf '%s' "$secret"
        head -c "$((size - offset - ${#secret}))" /dev/zero | tr '\0' 'b'
    } >"$file"
    curl -sk --max-time 3 -H 'Expect:' --data-binary @"$file" \
        https://127.0.0.1:9445/ >/dev/null 2>&1 || true
}

# Wait until the DLP alert count passes `before`.
_wait_for_more_alerts_than() {
    local before="$1" waited=0
    until [ "$(_dlp_alerts)" -gt "$before" ]; do
        [ "$waited" -lt 15 ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

@test "the kernel-features route answers dlp_whole_record, active or saying why not" {
    local entry
    entry="$(_capability)"
    [ -n "$entry" ] || {
        api_get /api/v1/ebpf/kernel-features >&2
        return 1
    }
    echo "$entry" | jq -e '.active == true or (((.cause // "") != "") and ((.reason // "") != ""))' >/dev/null
    echo "$entry" | jq -e '(.fallback // "") | contains("4,096")' >/dev/null

    # The start-up log says which read runs, and agrees with the route.
    if echo "$entry" | jq -e '.active == true' >/dev/null; then
        grep -q 'DLP probes read whole TLS records' "$AGENT_LOG_FILE"
    else
        grep -q 'DLP probes copy at most 4,096 bytes' "$AGENT_LOG_FILE"
    fi
}

@test "a secret 12,000 bytes into one write raises an alert from the whole record" {
    _capability | jq -e '.active == true' >/dev/null \
        || env_skip "this kernel runs the bounded copy: $(_capability | jq -r '.reason // empty')"

    local before
    before="$(_dlp_alerts)"
    _post_with_secret_at 12000 14000 " AKIAIOSFODNN7EXAMPLE "
    _wait_for_more_alerts_than "$before" || {
        echo "no DLP alert for a secret past the bounded copy (${before} before)" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

@test "a secret inside the first 4,096 bytes raises an alert whichever read runs" {
    local before
    before="$(_dlp_alerts)"
    _post_with_secret_at 1000 14000 " ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij "
    _wait_for_more_alerts_than "$before" || {
        echo "no DLP alert for a secret inside the bounded copy (${before} before)" >&2
        return 1
    }
}

@test "a reload that changes dlp.record_bytes names it in pending_restart" {
    sed -i 's/^  record_bytes: 16384$/  record_bytes: 8192/' "$PREPARED_CONFIG"
    local body
    body="$(api_post /api/v1/config/reload '{}' --max-time 30)"
    sed -i 's/^  record_bytes: 8192$/  record_bytes: 16384/' "$PREPARED_CONFIG"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    echo "$body" | jq -e '.pending_restart | index("dlp.record_bytes") != null' >/dev/null || {
        echo "expected pending_restart to name dlp.record_bytes: ${body}" >&2
        return 1
    }
}

@test "a record size outside 4096..=16384 stops the agent, naming the key and the range" {
    local agent="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$agent" ] || soft_skip "no local agent build at $agent"

    local bad="$DATA_DIR/bad-record.yaml" size
    for size in 4095 16385; do
        sed "s/^  record_bytes: 16384$/  record_bytes: ${size}/" "$PREPARED_CONFIG" >"$bad"
        sed -i 's/^  http_port: 8080$/  http_port: 18080/' "$bad"
        run timeout 20 "$agent" --config "$bad"
        [ "$status" -ne 0 ]
        [[ "$output" == *"dlp.record_bytes"* ]]
        [[ "$output" == *"4096..=16384"* ]]
    done
}
