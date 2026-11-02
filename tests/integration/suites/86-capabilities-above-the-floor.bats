#!/usr/bin/env bats
# 86-capabilities-above-the-floor.bats - every capability above the kernel
# floor is answered on the lane's own kernel, and said once at start-up.
#
# The suite asserts:
#
#   * The kernel-features route answers every entry of the agent's published
#     catalogue, `capabilities.json`, in its order, each one active or carrying
#     a cause and a reason, and none decided without its fallback.
#   * The start-up log carries one summary line and one line per inactive
#     entry, naming the same entries the route calls inactive.
#   * With `bpf` left out of the active security modules, every entry resting
#     on the BPF LSM is inactive, and the BPF LSM entry itself names the
#     boot parameter that would turn it on. The list is shown through a bind
#     mount over /sys/kernel/security/lsm inside a private mount namespace,
#     so the host keeps its own modules and the agent reads exactly what it
#     reads in production.
#
# Requires: root, kernel >= 6.12, jq, unshare.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool unshare

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export CATALOGUE="${PROJECT_ROOT}/capabilities.json"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-above-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-all-programs.yaml")"
    export PREPARED_CONFIG
}

teardown() {
    stop_ebpf_agent 2>/dev/null || true
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
}

# The `capability` field of every "capability inactive" line of a JSON log.
_inactive_in_log() {
    jq -rR 'fromjson? | select((.fields.message // .message // "") == "capability inactive")
        | (.fields.capability // .capability)' "$1" | sort
}

@test "the route answers every catalogue entry, in order, each active or saying why not" {
    [ -r "$CATALOGUE" ] || soft_skip "no capabilities.json at $CATALOGUE"

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    # The programs answer before every attach has: the route is read once the
    # start-up has said what it found, so both describe the same moment.
    local waited=0
    until grep -q 'kernel capabilities above the floor' "$AGENT_LOG_FILE"; do
        [ "$waited" -lt 60 ] || {
            tail -20 "$AGENT_LOG_FILE" >&2
            return 1
        }
        sleep 0.5
        waited=$((waited + 1))
    done

    local body
    body="$(api_get /api/v1/ebpf/kernel-features)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local expected answered
    expected="$(jq -c '[.capabilities[].id]' "$CATALOGUE")"
    answered="$(echo "$body" | jq -c '[.capabilities[].id]')"
    [ "$answered" = "$expected" ]

    local unexplained
    unexplained="$(echo "$body" | jq '[.capabilities[]
        | select(.active == false and (((.cause // "") == "") or ((.reason // "") == "")))]
        | length')"
    [ "$unexplained" = "0" ]
    echo "$body" | jq -e '[.capabilities[] | select((.fallback // "") == "")] | length == 0' >/dev/null

    # The start-up log names exactly the entries the route calls inactive.
    local from_route from_log
    from_route="$(echo "$body" | jq -r '.capabilities[] | select(.active == false) | .id' | sort)"
    from_log="$(_inactive_in_log "$AGENT_LOG_FILE")"
    [ "$from_log" = "$from_route" ]
    [ "$(grep -c 'kernel capabilities above the floor' "$AGENT_LOG_FILE")" = "1" ]
}

@test "without bpf among the security modules, every LSM entry is off and the boot parameter is named" {
    [ -r "$CATALOGUE" ] || soft_skip "no capabilities.json at $CATALOGUE"
    [ -r /sys/kernel/security/lsm ] || env_skip "securityfs is not mounted on this host"
    local agent="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$agent" ] || soft_skip "no local agent build at $agent"

    local fake="${DATA_DIR}/lsm"
    tr ',' '\n' </sys/kernel/security/lsm | grep -vx 'bpf' | paste -sd, - | tr -d '\n' >"$fake"
    local log="${DATA_DIR}/no-bpf-lsm.log"

    run timeout 30 unshare --mount --propagation private sh -c \
        'mount --bind "$1" /sys/kernel/security/lsm && exec env EBPF_PROGRAM_DIR="$2" "$3" --config "$4"' \
        sh "$fake" "$EBPF_PROGRAM_DIR" "$agent" "$PREPARED_CONFIG"
    printf '%s\n' "$output" >"$log"
    grep -q 'kernel capabilities above the floor' "$log" || {
        tail -20 "$log" >&2
        return 1
    }

    local inactive
    inactive="$(_inactive_in_log "$log")"
    local id
    for id in $(jq -r '.capabilities[] | select(.needs_lsm) | .id' "$CATALOGUE"); do
        echo "$inactive" | grep -qx "$id" || {
            echo "$id rests on the BPF LSM and was not reported inactive" >&2
            return 1
        }
    done

    local line
    line="$(jq -cR 'fromjson? | select((.fields.capability // .capability) == "bpf_lsm")' "$log" | head -1)"
    [ -n "$line" ]
    [ "$(echo "$line" | jq -r '.fields.cause // .cause')" = "lsm_inactive" ]
    [[ "$(echo "$line" | jq -r '.fields.hint // .hint')" == *"lsm="* ]]
}
