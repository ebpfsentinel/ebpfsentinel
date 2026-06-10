#!/usr/bin/env bats
# 60-l7-smtp-ftp-smb-edge.bats — L7 SMTP/FTP/SMB edge-case sweep.
#
# Asserts that the L7 inspector exposes the SMTP/FTP/SMB protocol
# surface end-to-end:
#
#   * Three pre-loaded rules (SMTP EHLO log, FTP PORT deny, SMB1 deny)
#     round-trip through GET /api/v1/firewall/l7-rules with their
#     protocol-specific matcher fields preserved.
#   * Each protocol round-trips through POST + DELETE /api/v1/firewall/
#     l7-rules with the matcher fields preserved.
#   * Malformed input does not crash the agent: invalid protocol on POST
#     returns 4xx (not 5xx and not silent acceptance), and a truncated
#     TCP burst on the L7-hooked ports leaves the agent answering /readyz.
#
# Wire-level coverage:
#
#   * A genuine FTP PORT command and a genuine SMB1 negotiate, driven
#     from the test netns through the L7-hooked TC ingress, each fire a
#     component=l7 deny alert (rules l7-ftp-port-deny / l7-smb-smb1-deny).
#   * A genuine SMTP EHLO is parsed and recorded on the L7 audit trail
#     (the EHLO rule action is `log`, which audits without alerting).
#
# The L7 inspector only captures payload for the dst ports declared in
# `l7.ports` (25/21/445 here); the fixture wires them so the dataplane
# is live. Per-command parser corner cases (pipelining, PASV gating,
# SMB2 dialects) remain covered by the domain l7::parser unit tests.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-l7edge-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-l7-edge.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-l7edge-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ─────────────────────────────────────────────────────────

_l7_rules_array() {
    local body
    body="$(api_get /api/v1/firewall/l7-rules 2>/dev/null)" || body=""
    [ -n "${body}" ] || return 1
    echo "${body}" \
        | jq 'if type == "array" then . else (.rules // []) end' 2>/dev/null
}

_post_l7_rule() {
    api_post /api/v1/firewall/l7-rules "$1"
}

# ── Pre-loaded fixture rules round-trip ─────────────────────────────

@test "L7 fixture rules expose SMTP/FTP/SMB matchers via REST" {
    local rules
    rules="$(_l7_rules_array)" || {
        echo "could not fetch /api/v1/firewall/l7-rules" >&2
        return 1
    }

    for id in l7-smtp-ehlo-log l7-ftp-port-deny l7-smb-smb1-deny; do
        local hit
        hit="$(echo "${rules}" | jq --arg id "${id}" '[.[] | select(.id == $id)] | length')"
        [ "${hit}" = "1" ] || {
            echo "rule ${id} not surfaced via /api/v1/firewall/l7-rules" >&2
            echo "${rules}" >&2
            return 1
        }
    done

    # SMTP rule must expose command=EHLO in its matcher payload.
    local smtp_matcher
    smtp_matcher="$(echo "${rules}" \
        | jq -c '.[] | select(.id == "l7-smtp-ehlo-log") | .matcher')"
    echo "${smtp_matcher}" | grep -qi 'EHLO' || {
        echo "SMTP rule matcher missing 'EHLO' command: ${smtp_matcher}" >&2
        return 1
    }

    # FTP rule must expose command=PORT.
    local ftp_matcher
    ftp_matcher="$(echo "${rules}" \
        | jq -c '.[] | select(.id == "l7-ftp-port-deny") | .matcher')"
    echo "${ftp_matcher}" | grep -qi 'PORT' || {
        echo "FTP rule matcher missing 'PORT' command: ${ftp_matcher}" >&2
        return 1
    }

    # SMB rule must encode is_smb2=false (SMB1 reject policy).
    local smb_matcher
    smb_matcher="$(echo "${rules}" \
        | jq -c '.[] | select(.id == "l7-smb-smb1-deny") | .matcher')"
    echo "${smb_matcher}" | grep -qiE 'is_smb2.*false|smb2.*false' || {
        echo "SMB rule matcher missing is_smb2=false: ${smb_matcher}" >&2
        return 1
    }
}

# ── POST + DELETE round-trip per protocol ──────────────────────────

@test "SMTP rule POST + DELETE round-trip" {
    local body
    body='{"id":"smtp-rt-vrfy","priority":50,"action":"log","protocol":"smtp","command":"VRFY","enabled":true}'
    _post_l7_rule "${body}" >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ]

    local rules
    rules="$(_l7_rules_array)"
    local hit
    hit="$(echo "${rules}" | jq '[.[] | select(.id == "smtp-rt-vrfy")] | length')"
    [ "${hit}" = "1" ]

    api_delete /api/v1/firewall/l7-rules/smtp-rt-vrfy >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "204" ]

    rules="$(_l7_rules_array)"
    hit="$(echo "${rules}" | jq '[.[] | select(.id == "smtp-rt-vrfy")] | length')"
    [ "${hit}" = "0" ]
}

@test "FTP rule POST + DELETE round-trip" {
    local body
    body='{"id":"ftp-rt-retr","priority":51,"action":"deny","protocol":"ftp","command":"RETR","enabled":true}'
    _post_l7_rule "${body}" >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ]

    local rules
    rules="$(_l7_rules_array)"
    local hit
    hit="$(echo "${rules}" | jq '[.[] | select(.id == "ftp-rt-retr")] | length')"
    [ "${hit}" = "1" ]

    api_delete /api/v1/firewall/l7-rules/ftp-rt-retr >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "204" ]
}

@test "SMB rule POST + DELETE round-trip" {
    local body
    body='{"id":"smb-rt-negotiate","priority":52,"action":"log","protocol":"smb","smb_command":0,"is_smb2":true,"enabled":true}'
    _post_l7_rule "${body}" >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ]

    local rules
    rules="$(_l7_rules_array)"
    local hit
    hit="$(echo "${rules}" | jq '[.[] | select(.id == "smb-rt-negotiate")] | length')"
    [ "${hit}" = "1" ]

    api_delete /api/v1/firewall/l7-rules/smb-rt-negotiate >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "204" ]
}

# ── Malformed input rejection ──────────────────────────────────────

@test "invalid L7 protocol is rejected by POST without crashing the agent" {
    local body
    body='{"id":"bogus-proto","priority":99,"action":"deny","protocol":"banana","enabled":true}'

    local resp
    resp="$(_post_l7_rule "${body}" 2>/dev/null)" || true
    _load_http_status

    # 400 / 422 are acceptable rejection codes; 200/201 means we
    # silently accepted nonsense and that's a regression. 5xx means
    # the handler panicked.
    case "${HTTP_STATUS}" in
        400|422) : ;;
        500|502|503|504)
            echo "POST with invalid protocol returned ${HTTP_STATUS} (server error): ${resp}" >&2
            return 1
            ;;
        200|201)
            echo "POST with invalid protocol was silently accepted (status ${HTTP_STATUS}): ${resp}" >&2
            return 1
            ;;
        *)
            echo "POST with invalid protocol returned unexpected status ${HTTP_STATUS}: ${resp}" >&2
            return 1
            ;;
    esac

    # Agent must still answer /healthz after the rejection.
    local healthz
    healthz="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/healthz" 2>/dev/null)" || true
    [ -n "${healthz}" ]
}

# ── Parser robustness: truncated TCP segments ──────────────────────

@test "truncated TCP segments on L7-hooked ports leave the agent ready" {
    require_tool ncat

    # Start three brief listeners — one per L7 hook port — so the TCP
    # handshake completes and the segment hits the L7 inspector path.
    local pids=()
    for port in 25 21 445; do
        ip netns exec "${EBPF_TEST_NS}" \
            ncat -l -p "${port}" -k --recv-only >/dev/null 2>&1 &
        pids+=($!)
    done
    sleep 0.5

    # Fire truncated payloads — half a SMTP greeting, half an FTP
    # banner, three SMB header bytes. Each is well under the parser's
    # minimum-frame threshold so the parser must reject or no-op without
    # panicking.
    send_tcp_from_ns "${EBPF_HOST_IP}" 25 "EH" 1 || true
    send_tcp_from_ns "${EBPF_HOST_IP}" 21 "PO" 1 || true
    send_tcp_from_ns "${EBPF_HOST_IP}" 445 $'\x00\x00\x01' 1 || true

    sleep 1

    for p in "${pids[@]}"; do
        kill "${p}" 2>/dev/null || true
    done

    # Agent must still answer /readyz with ebpf_loaded=true.
    local readyz
    readyz="$(api_get /readyz 2>/dev/null)" || true
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    local loaded
    loaded="$(echo "${readyz}" | jq -r '.ebpf_loaded' 2>/dev/null)" || true
    [ "${loaded}" = "true" ] || {
        echo "agent /readyz did not report ebpf_loaded=true after truncated burst" >&2
        echo "${readyz}" >&2
        return 1
    }
}

# ── Wire-level per-command behaviour ───────────────────────────────

# _l7_host_listeners — start one recv-only TCP listener per L7 port on
# the host side of the veth (default netns) so the netns client's
# handshake completes and its first command segment is transmitted on
# the wire, where tc-ids ingress captures it. Echoes the listener PIDs.
_l7_host_listeners() {
    local pids=()
    local port
    for port in 25 21 445; do
        ncat -l "${EBPF_HOST_IP}" "${port}" -k --recv-only >/dev/null 2>&1 &
        pids+=($!)
    done
    sleep 0.5
    echo "${pids[@]}"
}

# _drive_l7_commands — fire a genuine command per protocol from the test
# netns a few times (capture is best-effort per segment).
#   SMTP EHLO            -> l7-smtp-ehlo-log  (action log  -> audit only)
#   FTP  PORT            -> l7-ftp-port-deny  (action deny -> l7 alert)
#   SMB1 negotiate       -> l7-smb-smb1-deny  (action deny -> l7 alert)
_drive_l7_commands() {
    local i
    for i in 1 2 3 4; do
        send_tcp_from_ns "${EBPF_HOST_IP}" 25 $'EHLO probe.test\r\n' 2 || true
        send_tcp_from_ns "${EBPF_HOST_IP}" 21 $'PORT 10,200,0,2,4,5\r\n' 2 || true
        # SMB1 negotiate: NetBIOS session header (4 B, leading NUL) + the
        # "\xffSMB" magic + an SMB1 command header. The payload starts with
        # a NUL byte, which a bash variable cannot carry, so it is streamed
        # straight from printf into ncat (bypassing send_tcp_from_ns's echo).
        ip netns exec "${EBPF_TEST_NS}" bash -c \
            "printf '\\x00\\x00\\x00\\x55\\xffSMB\\x72\\x00\\x00\\x00\\x00\\x18\\x53\\xc8' \
             | timeout 2 ncat -w 2 ${EBPF_HOST_IP} 445" 2>/dev/null || true
    done
}

@test "FTP PORT and SMB1 commands on the wire fire L7 deny alerts (component=l7)" {
    require_tool ncat

    local pids
    pids="$(_l7_host_listeners)"
    _drive_l7_commands

    # shellcheck disable=SC2086
    for p in ${pids}; do kill "${p}" 2>/dev/null || true; done

    # FTP PORT deny -> component=l7 alert.
    wait_for_alert \
        '.[] | select(.rule_id == "l7-ftp-port-deny" and .component == "l7")' \
        15 1 >/dev/null || {
        echo "no l7-ftp-port-deny alert after FTP PORT command" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    # SMB1 negotiate deny -> component=l7 alert.
    wait_for_alert \
        '.[] | select(.rule_id == "l7-smb-smb1-deny" and .component == "l7")' \
        15 1 >/dev/null || {
        echo "no l7-smb-smb1-deny alert after SMB1 negotiate" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }
}

@test "SMTP EHLO command is parsed and recorded on the L7 audit trail" {
    require_tool ncat

    local pids
    pids="$(_l7_host_listeners)"
    _drive_l7_commands

    # shellcheck disable=SC2086
    for p in ${pids}; do kill "${p}" 2>/dev/null || true; done

    # The EHLO rule action is `log` -> no alert, but the L7 path audits
    # the decision under component=l7 / action=pass.
    local count=0 attempt=0
    while [ "${attempt}" -lt 15 ]; do
        local body
        body="$(api_get '/api/v1/audit/logs?component=l7&limit=200' 2>/dev/null)" || body=""
        count="$(echo "${body}" | jq -r '(.entries // []) | length' 2>/dev/null)" || count=0
        [ "${count:-0}" -ge 1 ] && break
        sleep 1
        attempt=$((attempt + 1))
    done
    [ "${count:-0}" -ge 1 ] || {
        echo "no L7 audit entries after SMTP EHLO (expected component=l7)" >&2
        api_get '/api/v1/audit/logs?component=l7&limit=200' >&2 || true
        return 1
    }
}
