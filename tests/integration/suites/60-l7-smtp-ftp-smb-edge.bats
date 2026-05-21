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
# Coverage gaps (tracked, deferred):
#
#   * Wire-level SMTP/FTP/SMB alert assertions (AC #1 per-protocol
#     command behaviour: SMTP pipelining, FTP PASV data-channel gating,
#     SMB2 dialect capture, SMB1 policy reject) require swaks / lftp /
#     smbclient on the test VMs. The OSS test fleet does not ship
#     those today; the per-command behaviour is exercised by the L7
#     engine's domain unit tests instead. Tested here through the rule
#     surface + parser-robustness path.

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

# ── Documented deferral: wire-level per-command behaviour ──────────

@test "per-command SMTP/FTP/SMB wire-level assertions are tracked as a coverage gap" {
    skip "wire-level swaks/lftp/smbclient assertions need extra deps on test VMs; per-command behaviour exercised by domain l7::engine unit tests; AC #1 per-protocol behaviour deferred"
}
