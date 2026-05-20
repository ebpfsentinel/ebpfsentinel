#!/usr/bin/env bash
# assertions.bash — Custom BATS assertions for eBPFsentinel integration tests

# assert_http_status <expected_code> [actual_code]
# If actual_code is empty (lost in subshell), recovers from the status file.
assert_http_status() {
    local expected="$1"
    local actual="${2:-}"
    if [ -z "$actual" ] && [ -f "$_HTTP_STATUS_FILE" ]; then
        actual="$(cat "$_HTTP_STATUS_FILE")"
    fi
    if [ "$actual" != "$expected" ]; then
        echo "Expected HTTP status $expected, got $actual" >&2
        return 1
    fi
}

# assert_json_field <json_string> <jq_expression> [expected_value]
# If expected_value is provided, checks equality. Otherwise checks field exists.
assert_json_field() {
    local json="$1"
    local field="$2"
    local expected="${3:-}"

    local value
    value="$(echo "$json" | jq -r "$field" 2>/dev/null)"

    if [ "$value" = "null" ] || [ -z "$value" ]; then
        echo "JSON field $field not found in: $json" >&2
        return 1
    fi

    if [ -n "$expected" ]; then
        if [ "$value" != "$expected" ]; then
            echo "Expected $field = '$expected', got '$value'" >&2
            return 1
        fi
    fi
}

# assert_json_array_length <json_string> <jq_array_expression> <expected_length>
assert_json_array_length() {
    local json="$1"
    local expr="$2"
    local expected="$3"

    local length
    length="$(echo "$json" | jq "$expr | length" 2>/dev/null)"

    if [ "$length" != "$expected" ]; then
        echo "Expected array length $expected at $expr, got $length" >&2
        return 1
    fi
}

# assert_json_field_exists <json_string> <jq_expression>
# Uses type check instead of jq -e, which treats false/null as errors.
assert_json_field_exists() {
    local json="$1"
    local field="$2"

    local field_type
    field_type="$(echo "$json" | jq -r "$field | type" 2>/dev/null)"

    if [ -z "$field_type" ] || [ "$field_type" = "null" ]; then
        echo "JSON field $field not found in: $json" >&2
        return 1
    fi
}

# assert_contains <haystack> <needle>
assert_contains() {
    local haystack="$1"
    local needle="$2"

    if [[ "$haystack" != *"$needle"* ]]; then
        echo "Expected to contain '$needle' in: $haystack" >&2
        return 1
    fi
}

# ── Metric / IPS / alert / latency assertions ─────────────────────────
# These build on get_metrics_value, get_blacklist_count, wait_for_alert
# from ebpf_helpers.bash, plus curl for in-band probes.

# assert_metric_increased <metric_name> <before_value> [min_delta] [label_filter]
# Polls the metric (up to 30 s) and asserts the value grew by at least
# <min_delta> (default 1).
assert_metric_increased() {
    local metric="${1:?usage: assert_metric_increased <metric> <before> [delta] [label]}"
    local before="${2:?usage: assert_metric_increased <metric> <before> [delta] [label]}"
    local min_delta="${3:-1}"
    local label="${4:-}"
    local target
    target="$(echo "$before + $min_delta" | bc -l 2>/dev/null)"
    [ -z "$target" ] && target="$((before + min_delta))"

    local attempt=0 value=""
    while [ "$attempt" -lt 30 ]; do
        value="$(get_metrics_value "$metric" "$label" 2>/dev/null || true)"
        if [ -n "$value" ] && [ "$(echo "$value >= $target" | bc -l 2>/dev/null)" = "1" ]; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "Metric ${metric}${label} did not grow by ${min_delta} from ${before} (last=${value:-<none>})" >&2
    return 1
}

# assert_ip_blacklisted <ip> [max_attempts]
# Polls /api/v1/ips/blacklist until <ip> is listed. Default 30 attempts (~30 s).
assert_ip_blacklisted() {
    local ip="${1:?usage: assert_ip_blacklisted <ip> [max_attempts]}"
    local max="${2:-30}"
    local attempt=0
    while [ "$attempt" -lt "$max" ]; do
        local body
        body="$(api_get /api/v1/ips/blacklist 2>/dev/null)" || body=""
        if [ -n "$body" ]; then
            local hit
            hit="$(echo "$body" | jq -r --arg ip "$ip" \
                '.[] | select(.ip == $ip or .source_ip == $ip or .src_ip == $ip) | .ip // .source_ip // .src_ip' \
                2>/dev/null | head -1)"
            if [ -n "$hit" ] && [ "$hit" != "null" ]; then
                return 0
            fi
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "IP ${ip} not present in /api/v1/ips/blacklist after ${max}s" >&2
    return 1
}

# assert_alert_has_mitre_technique <technique_id> [max_attempts]
# Polls /api/v1/alerts for an alert tagged with the given MITRE technique
# (T1498, T1499, ...). Matches either the canonical .mitre.techniques
# array or the flat .mitre_techniques fallback.
assert_alert_has_mitre_technique() {
    local technique="${1:?usage: assert_alert_has_mitre_technique <id> [max_attempts]}"
    local max="${2:-30}"
    local filter
    filter="$(printf '
        .[]
        | select(
            (.mitre.techniques // .mitre_techniques // [])
            | map(. | ascii_upcase) | index("%s") != null
        )
        | (.id // .alert_id // .timestamp)
    ' "$technique")"
    if wait_for_alert "$filter" "$max" 1 >/dev/null 2>&1; then
        return 0
    fi
    echo "No alert tagged with MITRE technique ${technique} after ${max}s" >&2
    return 1
}

# assert_api_p99_below <p99_ms_budget> [samples] [path]
# Sends <samples> sequential probes to <path> (default /healthz) and
# computes the 99th-percentile end-to-end curl time. Asserts that p99
# is below <p99_ms_budget> milliseconds.
assert_api_p99_below() {
    local budget_ms="${1:?usage: assert_api_p99_below <ms> [samples] [path]}"
    local samples="${2:-100}"
    local path="${3:-/healthz}"
    local url="${BASE_URL}${path}"

    local tmp
    tmp="$(mktemp)"
    local i
    for i in $(seq 1 "$samples"); do
        local t
        t="$(curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" \
            -w '%{time_total}\n' "$url" 2>/dev/null)" || t="$HTTP_TIMEOUT"
        echo "$t" >> "$tmp"
    done

    # p99 via sort + index. Samples are in seconds; convert at the end.
    local p99_secs
    p99_secs="$(sort -g "$tmp" | awk -v n="$samples" 'BEGIN{idx=int(n*0.99); if (idx<1) idx=1} NR==idx {print; exit}')"
    rm -f "$tmp"
    if [ -z "$p99_secs" ]; then
        echo "p99 sampling produced no data" >&2
        return 1
    fi
    local p99_ms
    p99_ms="$(echo "$p99_secs * 1000" | bc -l 2>/dev/null)"
    local ok
    ok="$(echo "$p99_ms < $budget_ms" | bc -l 2>/dev/null)"
    if [ "$ok" = "1" ]; then
        return 0
    fi
    echo "API p99 ${p99_ms} ms exceeded budget ${budget_ms} ms over ${samples} samples" >&2
    return 1
}
