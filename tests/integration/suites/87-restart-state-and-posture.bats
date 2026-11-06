#!/usr/bin/env bats
# 87-restart-state-and-posture.bats - what survives a restart of the agent, and
# the read-only routes that describe the node's own posture.
#
# The suite asserts:
#
#   * A learning window open when the agent stops is taken back when it
#     starts: same id, still running, and the time the agent was down counted
#     as a gap rather than silently folded into the window.
#   * A window whose deadline passed while the agent was down comes back
#     interrupted, never completed: a policy built from it would miss what
#     ran during the hole.
#   * The edges, policy, segmentation and stop routes answer for a window
#     that came back.
#   * The MITRE coverage report lists the IDS techniques under switched_off,
#     and none of them under techniques, when the IDS is disabled.
#   * A packet trace names the deny rule a crafted packet meets and stops on
#     it, and lets a packet the rule does not name through.
#   * The DLP scope route answers with the node-wide mode the fixture leaves
#     in place.
#   * The eBPF coverage route refuses with a reason on a node that has no
#     pod inventory, rather than reporting an empty node as covered.
#
# Requires: root, kernel >= 6.12, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-restart-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-restart-state.yaml")"
    export PREPARED_CONFIG
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

_start() {
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

_ensure_running() {
    api_get /api/v1/learning/sessions >/dev/null 2>&1 && return 0
    _start
}

_session() {
    api_get "/api/v1/learning/sessions/$1"
}

@test "an open learning window comes back running after a restart, with the downtime as a gap" {
    _start

    local body id
    body="$(api_post /api/v1/learning/sessions \
        '{"scope":{"kind":"node"},"duration_secs":600}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ] || {
        echo "# start answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    id="$(echo "$body" | jq -r '.id')"
    [ -n "$id" ] && [ "$id" != "null" ]
    echo "$id" > "${DATA_DIR}/open-window-id"
    [ "$(_session "$id" | jq -r '.gap_secs')" = "0" ]

    stop_ebpf_agent
    sleep 6
    _start

    body="$(_session "$id")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# the window did not come back: ${HTTP_STATUS} ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq -r '.status')" = "running" ] || {
        echo "# ${body}" >&3
        false
    }
    local gap
    gap="$(echo "$body" | jq -r '.gap_secs')"
    [ "$gap" -ge 5 ] || {
        echo "# downtime of at least six seconds counted as ${gap}" >&3
        false
    }
}

@test "the edges, policy and segmentation routes answer for a window that came back" {
    _ensure_running
    local id
    id="$(cat "${DATA_DIR}/open-window-id")"

    api_get "/api/v1/learning/sessions/${id}/edges" >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local body
    body="$(api_get "/api/v1/learning/sessions/${id}/policy")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# policy answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq -r '.session.id')" = "$id" ]

    body="$(api_get "/api/v1/learning/sessions/${id}/segmentation")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# segmentation answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq -r '.session.id')" = "$id" ]

    body="$(api_post "/api/v1/learning/sessions/${id}/stop" '{}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# stop answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(_session "$id" | jq -r '.status')" = "stopped" ]
}

@test "a window whose deadline passed while the agent was down comes back interrupted" {
    _ensure_running

    local body id
    body="$(api_post /api/v1/learning/sessions \
        '{"scope":{"kind":"node"},"duration_secs":5}')"
    id="$(echo "$body" | jq -r '.id')"
    [ -n "$id" ] && [ "$id" != "null" ] || {
        echo "# start answered: ${body}" >&3
        false
    }

    stop_ebpf_agent
    sleep 8
    _start

    body="$(_session "$id")"
    [ "$(echo "$body" | jq -r '.status')" = "interrupted" ] || {
        echo "# ${body}" >&3
        false
    }
    [ "$(api_get /api/v1/learning/sessions \
        | jq --arg id "$id" '[.[] | select(.id == $id)] | length')" = "1" ]
}

@test "a disabled IDS is reported as switched off and not as coverage" {
    _ensure_running

    local body
    body="$(api_get /api/v1/mitre/coverage)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(echo "$body" | jq '[.switched_off[] | select(.component == "ids")] | length')" -gt 0 ] || {
        echo "# switched_off: $(echo "$body" | jq -c '[.switched_off[].component] | unique')" >&3
        false
    }
    [ "$(echo "$body" | jq '[.techniques[] | select(.component == "ids")] | length')" = "0" ]
    [ "$(echo "$body" | jq '[.techniques[] | select(.component == "firewall")] | length')" -gt 0 ]
}

@test "a trace stops on the deny rule the crafted packet meets, and passes one it does not" {
    _ensure_running

    local body
    body="$(api_post /api/v1/trace "{\"src_ip\":\"${EBPF_NS_IP}\",\"dst_ip\":\"${EBPF_HOST_IP}\",\"src_port\":40000,\"dst_port\":9999,\"protocol\":\"tcp\"}")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# trace answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq '.stages | length')" -gt 0 ]
    [ "$(echo "$body" | jq '[.stages[] | select(.rule_id == "fw-restart-deny-9999")] | length')" -gt 0 ] || {
        echo "# ${body}" >&3
        false
    }
    case "$(echo "$body" | jq -r '.verdict')" in
        drop | reject) ;;
        *) echo "# deny rule did not stop the packet: ${body}" >&3; false ;;
    esac

    body="$(api_post /api/v1/trace "{\"src_ip\":\"${EBPF_NS_IP}\",\"dst_ip\":\"${EBPF_HOST_IP}\",\"src_port\":40000,\"dst_port\":8443,\"protocol\":\"tcp\"}")"
    [ "$(echo "$body" | jq '[.stages[] | select(.rule_id == "fw-restart-deny-9999")] | length')" = "0" ]
    case "$(echo "$body" | jq -r '.verdict')" in
        drop | reject) echo "# an unnamed port was stopped: ${body}" >&3; false ;;
        *) ;;
    esac
}

@test "the DLP scope route answers with the node-wide mode" {
    _ensure_running

    local body
    body="$(api_get /api/v1/dlp/scope)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# dlp scope answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(echo "$body" | jq -r '.mode')" = "all" ]
    [ "$(echo "$body" | jq -r '.enabled')" = "true" ]
}

@test "the eBPF coverage route refuses with a reason on a node with no pod inventory" {
    _ensure_running

    local body
    body="$(api_get /api/v1/ebpf/coverage)"
    _load_http_status
    [ "$HTTP_STATUS" = "404" ] || {
        echo "# coverage answered ${HTTP_STATUS} without a pod inventory: ${body}" >&3
        false
    }
    assert_contains "$body" "pod inventory"
}
