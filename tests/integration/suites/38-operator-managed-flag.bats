#!/usr/bin/env bats
# 38-operator-managed-flag.bats — agent identity + operator-managed config.
#
# Validates the contract documented in `api-reference/rest-api.md`:
#   - `GET /api/v1/agent/identity` returns the management metadata.
#   - Default `operator_managed` is `false`, `operator_endpoint` is absent.
#   - Toggling the YAML and triggering a config reload flips the flag
#     without an agent restart.
#   - `operator_endpoint` is surfaced when set.
#   - Invalid `operator_endpoint` rejects the reload.

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-mgmt-test-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-mgmt-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# Append a `management:` block (and overwrite an existing one) at the
# bottom of the running config file.
_set_management() {
    local managed="$1" endpoint="${2:-}"
    # Drop any previous management: block.
    sed -i '/^management:/,$d' "$PREPARED_CONFIG"
    {
        printf '\nmanagement:\n  operator_managed: %s\n' "$managed"
        if [ -n "$endpoint" ]; then
            printf '  operator_endpoint: %s\n' "$endpoint"
        fi
    } >> "$PREPARED_CONFIG"
    chmod 640 "$PREPARED_CONFIG"
}

_reload_config() {
    curl -sf -X POST --max-time 5 "${BASE_URL}/api/v1/config/reload" >/dev/null \
        || sleep 2  # file watcher fallback
}

# ── Tests ──────────────────────────────────────────────────────────

@test "default identity reports operator_managed=false and no endpoint" {
    local body
    body="$(curl -sf --max-time 3 "${BASE_URL}/api/v1/agent/identity")"
    [ -n "$body" ]
    [ "$(jq -r '.operator_managed' <<<"$body")" = "false" ]
    # operator_endpoint is omitted when unset (skip_serializing_if = None).
    [ "$(jq -r '.operator_endpoint // "absent"' <<<"$body")" = "absent" ]
    [ -n "$(jq -r '.version' <<<"$body")" ]
    [ -n "$(jq -r '.hostname' <<<"$body")" ]
}

@test "toggling operator_managed=true is reflected after reload" {
    _set_management "true" "https://operator.example.com:9443/ui"
    _reload_config

    local body
    body="$(curl -sf --max-time 3 "${BASE_URL}/api/v1/agent/identity")"
    [ "$(jq -r '.operator_managed' <<<"$body")" = "true" ]
    [ "$(jq -r '.operator_endpoint' <<<"$body")" = "https://operator.example.com:9443/ui" ]
}

@test "toggling back to operator_managed=false drops the endpoint field" {
    _set_management "false"
    _reload_config

    local body
    body="$(curl -sf --max-time 3 "${BASE_URL}/api/v1/agent/identity")"
    [ "$(jq -r '.operator_managed' <<<"$body")" = "false" ]
    [ "$(jq -r '.operator_endpoint // "absent"' <<<"$body")" = "absent" ]
}

@test "invalid operator_endpoint URL rejects the reload" {
    _set_management "true" "not-a-valid-url"
    local status
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -X POST "${BASE_URL}/api/v1/config/reload")"
    # Reload is rejected (4xx/5xx) and the previous valid config is kept.
    [ "$status" -ge "400" ]

    local body
    body="$(curl -sf --max-time 3 "${BASE_URL}/api/v1/agent/identity")"
    # Either the previous (false / absent) state is preserved, or — if a
    # file-watcher fallback re-applied the bad config — the gate refused
    # to flip the flag. Both are acceptable; what is NOT acceptable is
    # advertising the malformed URL.
    [ "$(jq -r '.operator_endpoint // "absent"' <<<"$body")" != "not-a-valid-url" ]
}

@test "agent identity CLI prints both fields in JSON mode" {
    _set_management "true" "https://operator.example.com"
    _reload_config

    local out
    out="$("$AGENT_BIN" identity --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" --output json 2>&1)"
    [ -n "$out" ]
    [ "$(jq -r '.operator_managed' <<<"$out")" = "true" ]
    [ "$(jq -r '.operator_endpoint' <<<"$out")" = "https://operator.example.com" ]
}
