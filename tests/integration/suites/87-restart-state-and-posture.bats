#!/usr/bin/env bats
# 87-restart-state-and-posture.bats - what survives a restart of the agent, and
# the read-only routes that describe the node's own posture.
#
# The suite asserts:
#
#   * A learning window open when the agent dies is taken back when it
#     starts: same id, still running, and the time the agent was down counted
#     as a gap rather than silently folded into the window.
#   * A window open when the agent is stopped cleanly comes back interrupted:
#     nobody watched while the agent was down.
#   * A window whose deadline passed while the agent was down comes back
#     interrupted, never completed: a policy built from it would miss what
#     ran during the hole.
#   * The edges, policy and stop routes answer for a window that came back,
#     and the segmentation route refuses with its reason on a node whose
#     bridges are not read from Docker.
#   * The MITRE coverage report lists the IDS techniques under switched_off,
#     and none of them under techniques, when the IDS is disabled.
#   * A packet trace names the deny rule a crafted packet meets and stops on
#     it, and lets a packet the rule does not name through.
#   * The learning and trace commands print what the routes answer.
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
    # Learning mode is handed to the API late in startup, after the tracer,
    # so the API answers before either is there.
    local attempt
    for attempt in $(seq 1 60); do
        api_get /api/v1/learning/sessions >/dev/null 2>&1
        _load_http_status
        [ "$HTTP_STATUS" = "200" ] && return 0
        sleep 0.5
    done
    echo "# learning mode never came up" >&3
    return 1
}

# _kill_hard - end the agent the way a crash or an OOM kill does, with no
# chance to write anything down, then clear what the helper started beside it.
_kill_hard() {
    pkill -9 -f /tmp/ebpfsentinel-agent-staged 2>/dev/null || true
    sleep 1
    stop_ebpf_agent
}

_open_window() {
    local body
    body="$(api_post /api/v1/learning/sessions \
        "{\"scope\":{\"kind\":\"node\"},\"duration_secs\":$1}")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ] || {
        echo "# start answered ${HTTP_STATUS}: ${body}" >&3
        return 1
    }
    echo "$body" | jq -r '.id'
}

_ensure_running() {
    api_get /api/v1/learning/sessions >/dev/null 2>&1 && return 0
    _start
}

_session() {
    api_get "/api/v1/learning/sessions/$1"
}

@test "an open learning window comes back running after the agent dies, with the downtime as a gap" {
    _start

    local body id
    id="$(_open_window 600)"
    [ -n "$id" ] && [ "$id" != "null" ]
    echo "$id" > "${DATA_DIR}/open-window-id"
    [ "$(_session "$id" | jq -r '.gap_secs')" = "0" ]
    # Long enough for a sample to be written down.
    sleep 3

    _kill_hard
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

    # The segmentation names bridges, which this node does not read.
    body="$(api_get "/api/v1/learning/sessions/${id}/segmentation")"
    _load_http_status
    [ "$HTTP_STATUS" = "503" ] || {
        echo "# segmentation answered ${HTTP_STATUS} with Docker off: ${body}" >&3
        false
    }
    assert_contains "$body" "container.docker.enabled"

    body="$(api_post "/api/v1/learning/sessions/${id}/stop" '{}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || {
        echo "# stop answered ${HTTP_STATUS}: ${body}" >&3
        false
    }
    [ "$(_session "$id" | jq -r '.status')" = "stopped" ]
}

@test "a window open when the agent is stopped cleanly comes back interrupted" {
    _ensure_running

    local body id
    id="$(_open_window 600)"
    [ -n "$id" ] && [ "$id" != "null" ]

    stop_ebpf_agent
    _start

    body="$(_session "$id")"
    [ "$(echo "$body" | jq -r '.status')" = "interrupted" ] || {
        echo "# ${body}" >&3
        false
    }
}

@test "a window whose deadline passed while the agent was down comes back interrupted" {
    _ensure_running

    local body id
    # The shortest window the engine accepts.
    id="$(_open_window 60)"
    [ -n "$id" ] && [ "$id" != "null" ]
    sleep 3

    _kill_hard
    sleep 62
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
    [ "$(echo "$body" | jq '[.stages[] | select(.rule == "fw-restart-deny-9999")] | length')" -gt 0 ] || {
        echo "# ${body}" >&3
        false
    }
    case "$(echo "$body" | jq -r '.verdict')" in
        drop | reject) ;;
        *) echo "# deny rule did not stop the packet: ${body}" >&3; false ;;
    esac

    body="$(api_post /api/v1/trace "{\"src_ip\":\"${EBPF_NS_IP}\",\"dst_ip\":\"${EBPF_HOST_IP}\",\"src_port\":40000,\"dst_port\":8443,\"protocol\":\"tcp\"}")"
    [ "$(echo "$body" | jq '[.stages[] | select(.rule == "fw-restart-deny-9999")] | length')" = "0" ]
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

@test "the learning and trace commands read what the routes answer" {
    _ensure_running

    local out id
    out="$("$AGENT_BIN" --output json learning --port "$AGENT_HTTP_PORT" list 2>&1)" || {
        echo "# learning list: ${out}" >&3
        false
    }
    id="$(cat "${DATA_DIR}/open-window-id")"
    assert_contains "$out" "$id"

    out="$("$AGENT_BIN" --output json learning --port "$AGENT_HTTP_PORT" status "$id" 2>&1)" || {
        echo "# learning status: ${out}" >&3
        false
    }
    assert_contains "$out" "stopped"

    out="$("$AGENT_BIN" --output json trace --port "$AGENT_HTTP_PORT" "$EBPF_HOST_IP" \
        --src "$EBPF_NS_IP" --sport 40000 --dport 9999 --proto tcp 2>&1)" || {
        echo "# trace: ${out}" >&3
        false
    }
    assert_contains "$out" "fw-restart-deny-9999"
}
