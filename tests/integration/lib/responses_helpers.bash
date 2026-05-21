#!/usr/bin/env bash
# responses_helpers.bash — Response engine + audit helpers for suite 52.
#
# The agent's response engine is in-memory: actions live in a HashMap
# keyed by response id. Manual entries land via POST /api/v1/responses/manual
# and are listed via GET /api/v1/responses. Each create/revoke also lands
# an entry in the audit log (component=responses) which we read back via
# GET /api/v1/audit/logs.
#
# This file is intentionally REST-first: the CLI commands are exercised
# end-to-end inside suite 52, but every assertion the suite makes is
# expressed in terms of the same /api/v1 surface.

# create_response <action> <target> <ttl> [rate_pps]
#
# Posts a manual response action. <action> matches the agent's ResponseAction
# vocabulary (block_ip, throttle_ip, …). Echoes the response id on stdout
# when the API returns 201. Non-zero exit + stderr explanation otherwise.
create_response() {
    local action="${1:?usage: create_response <action> <target> <ttl> [rate_pps]}"
    local target="${2:?usage: create_response <action> <target> <ttl> [rate_pps]}"
    local ttl="${3:?usage: create_response <action> <target> <ttl> [rate_pps]}"
    local rate_pps="${4:-}"
    local body
    if [ -n "${rate_pps}" ]; then
        body="$(printf '{"action":"%s","target":"%s","ttl":"%s","rate_pps":%s}' \
            "${action}" "${target}" "${ttl}" "${rate_pps}")"
    else
        body="$(printf '{"action":"%s","target":"%s","ttl":"%s"}' \
            "${action}" "${target}" "${ttl}")"
    fi
    local resp
    resp="$(api_post /api/v1/responses/manual "${body}")" || return 1
    _load_http_status
    if [ "${HTTP_STATUS:-0}" != "201" ] && [ "${HTTP_STATUS:-0}" != "200" ]; then
        echo "create_response: HTTP ${HTTP_STATUS}: ${resp}" >&2
        return 1
    fi
    echo "${resp}" | jq -r '.id // empty'
}

# list_responses
#
# Echo the raw JSON array returned by GET /api/v1/responses.
list_responses() {
    api_get /api/v1/responses
}

# response_remaining_secs <id>
#
# Echo the remaining_secs field for response <id> from GET /api/v1/responses,
# or empty string if no such id exists.
response_remaining_secs() {
    local id="${1:?usage: response_remaining_secs <id>}"
    local body
    body="$(list_responses)" || return 1
    echo "${body}" | jq -r --arg id "${id}" \
        '.actions[] | select(.id == $id) | .remaining_secs // empty'
}

# response_present <id>
#
# Echo "1" when /api/v1/responses lists <id>, "0" otherwise.
response_present() {
    local id="${1:?usage: response_present <id>}"
    local body
    body="$(list_responses)" || return 1
    if echo "${body}" | jq -e --arg id "${id}" '.actions | any(.id == $id)' >/dev/null; then
        echo "1"
    else
        echo "0"
    fi
}

# revoke_response <id>
#
# DELETE /api/v1/responses/{id}. Returns non-zero on HTTP failure.
revoke_response() {
    local id="${1:?usage: revoke_response <id>}"
    api_delete "/api/v1/responses/${id}" >/dev/null || return 1
    _load_http_status
    case "${HTTP_STATUS:-0}" in
        200 | 202 | 204) return 0 ;;
        *)
            echo "revoke_response: HTTP ${HTTP_STATUS}" >&2
            return 1
            ;;
    esac
}

# wait_for_response_expired <id> [timeout_secs] [poll_s]
#
# Poll list_responses until <id> is no longer active or revoked=true. Default
# 30s timeout, 1s poll. Returns 0 on success, 1 on timeout.
wait_for_response_expired() {
    local id="${1:?usage: wait_for_response_expired <id> [timeout] [poll]}"
    local timeout="${2:-30}"
    local poll="${3:-1}"
    local i body still
    for ((i = 0; i < timeout; i += poll)); do
        body="$(list_responses)" || return 1
        still="$(echo "${body}" | jq -r --arg id "${id}" \
            '[.actions[] | select(.id == $id and (.revoked // false) == false)] | length')"
        if [ "${still:-0}" -eq 0 ]; then
            return 0
        fi
        sleep "${poll}"
    done
    return 1
}

# audit_log_count <component> <action> [limit]
#
# Echo the number of audit entries with the given component + action. The
# audit API is best-effort here — when the storage backend has no entries
# yet, the endpoint returns an empty array. Default limit 200.
audit_log_count() {
    local component="${1:?usage: audit_log_count <component> <action> [limit]}"
    local action="${2:?usage: audit_log_count <component> <action> [limit]}"
    local limit="${3:-200}"
    local body
    body="$(api_get "/api/v1/audit/logs?component=${component}&action=${action}&limit=${limit}")" || return 1
    echo "${body}" | jq -r '(.entries // []) | length'
}
