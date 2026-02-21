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
