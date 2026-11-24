#!/usr/bin/env bats
# Host rules written in two steps and as counts, off real process starts.
#
# A sequence opens on its first step and closes on a second step about the
# same process or one started below it, within the window. A copy of bash
# starting a copy of sleep closes it; the same sleep started alone, with no
# shell before it, never does, and the first step waits in `pending` until a
# second step or the window ends it. A count holds on the event that brings
# enough starts into its window: two starts of a copy of true raise nothing,
# the third raises one alert and the group starts again from nothing.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 18
    require_tool jq
    require_root
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 135 starts its processes on the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-sequences-$$"
    mkdir -p "${DATA_DIR}"
    cp "$(readlink -f "$(type -P bash)")" "${DATA_DIR}/seq-opener"
    cp "$(readlink -f "$(type -P sleep)")" "${DATA_DIR}/seq-closer"
    cp "$(readlink -f "$(type -P true)")" "${DATA_DIR}/cnt-burst"
    chmod 0755 "${DATA_DIR}"/seq-* "${DATA_DIR}/cnt-burst"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-host-rules.yaml")"
    export PREPARED_CONFIG
    # The fixture's own rule stays; the two written here follow it.
    sed -i '/^host_rules:$/,/^  rules:$/ s/^  shipped: true$/  shipped: false/' "${PREPARED_CONFIG}"
    python3 - "${PREPARED_CONFIG}" "${DATA_DIR}" <<'PY'
import sys
path, data = sys.argv[1], sys.argv[2]
text = open(path).read()
anchor = "  rules:\n"
assert text.count(anchor) == 1
rules = f"""  rules:
    - id: seq-shell-then-sleep
      description: the suite's shell, then the suite's sleep below it
      severity: high
      when:
        process.starts:
          exe: [{data}/seq-opener]
      followed_by:
        within: 10s
        process.starts:
          exe: [{data}/seq-closer]
      then: [alert]
      mode: enforce
    - id: cnt-three-starts
      description: three starts of the suite's true within ten seconds
      severity: medium
      when:
        process.starts:
          exe: [{data}/cnt-burst]
          count:
            min: 3
            within: 10s
            per: host
      then: [alert]
      mode: enforce
"""
open(path, "w").write(text.replace(anchor, rules))
PY

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_rule cnt-three-starts || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "host rules never listed" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-sequences-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

_host_rules() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/host-rules"
}

_wait_rule() {
    local attempt=0
    while [ "${attempt}" -lt 30 ]; do
        [ -n "$(_host_rules | jq -c --arg r "$1" '.rules[] | select(.id == $r)' 2>/dev/null)" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

_requires_starts() {
    local state
    state="$(_host_rules | jq -r '.rules[] | select(.id == "cnt-three-starts") | .state')"
    if [ "${state}" != "applicable" ]; then
        env_skip "process.starts is not served on this host (${state})"
    fi
}

# _alerts <rule id> - how many alerts that rule raised so far.
_alerts() {
    api_get /api/v1/alerts | jq --arg r "$1" '[(.alerts // .)[] | select(.rule_id == $r)] | length'
}

@test "both rules load in force and applicable" {
    _requires_starts
    local body
    body="$(_host_rules)"
    jq -e '.rules[] | select(.id == "seq-shell-then-sleep") | .mode == "enforce" and .state == "applicable"' <<<"${body}" >/dev/null
    jq -e '.rules[] | select(.id == "cnt-three-starts") | .mode == "enforce" and .state == "applicable"' <<<"${body}" >/dev/null
}

@test "the second step alone, with no first step before it, raises nothing" {
    _requires_starts
    "${DATA_DIR}/seq-closer" 0.2
    run wait_for_alert '.[] | select(.rule_id == "seq-shell-then-sleep")' 3 1
    [ "$status" -ne 0 ]
}

@test "the first step waits in pending until its second step closes it" {
    _requires_starts
    # The shell waits a second before starting the sleep, long enough to be
    # read as waiting.
    "${DATA_DIR}/seq-opener" -c "sleep 2; '${DATA_DIR}/seq-closer' 0.2; true" &
    local opener=$! deadline=$((SECONDS + 10)) seen=0
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ "$(_host_rules | jq -r '.pending')" -ge 1 ]; then
            seen=1
            break
        fi
        sleep 0.3
    done
    wait "${opener}" || true
    [ "${seen}" -eq 1 ]

    local alert
    alert="$(wait_for_alert '[.[] | select(.rule_id == "seq-shell-then-sleep")] | first' 15 1)"
    echo "${alert}" | jq -c '{rule_id, message}'
    echo "${alert}" | jq -e '.message | contains("after process.starts within 10s")' >/dev/null
    [ "$(_host_rules | jq -r '.pending')" -eq 0 ]
}

@test "a count raises nothing below its minimum and one alert on the event that reaches it" {
    _requires_starts
    local before
    before="$(_alerts cnt-three-starts)"
    "${DATA_DIR}/cnt-burst"
    "${DATA_DIR}/cnt-burst"
    sleep 2
    [ "$(_alerts cnt-three-starts)" -eq "${before}" ]
    [ "$(_host_rules | jq -r '.counting')" -ge 1 ]

    "${DATA_DIR}/cnt-burst"
    local alert
    alert="$(wait_for_alert '[.[] | select(.rule_id == "cnt-three-starts")] | first' 15 1)"
    echo "${alert}" | jq -c '{rule_id, message}'
    echo "${alert}" | jq -e '.message | endswith(", 3 events within 10s per host")' >/dev/null
    [ "$(_alerts cnt-three-starts)" -eq $((before + 1)) ]
    # The group fired and starts again from nothing.
    [ "$(_host_rules | jq -r '.counting')" -eq 0 ]
}
