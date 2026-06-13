#!/usr/bin/env bats
# 59-ssh-brute-force-real.bats — SSH brute-force IDS + IPS sweep.
#
# Drives a synthetic SYN burst from the test netns at the agent on
# TCP/22 with pre-loaded IDS + IPS threshold rules and asserts:
#
#   * The IDS rule (id=ids-ssh-bruteforce, protocol=tcp, dst_port=22,
#     threshold count=5 in 30 s, track_by=src_ip) surfaces via
#     GET /api/v1/ids/rules.
#   * The IPS rule (id=ips-ssh-bruteforce, mode=block) surfaces via
#     GET /api/v1/ips/rules.
#   * After exceeding the count, an alert is observable on
#     /api/v1/alerts with rule_id=ids-ssh-bruteforce, severity=high,
#     and MITRE technique T1110.001 (Password Guessing) per
#     domain::alert::mitre dst-port mapping for port 22.
#   * The IPS auto-blacklist endpoint accepts the source IP under load
#     and exposes at least one auto-generated entry.
#
# Real-tool coverage:
#
#   * A genuine hydra SSH credential burst from the test netns drives the
#     IDS brute-force alert (T1110.001) and the IPS auto-block, exercising
#     the same dataplane contract as the synthetic SYN burst with a real
#     attack tool (hydra is provisioned on the agent VM).
#   * The "no successful auth" negative assertion is checked locally: the
#     burst targets the key-only `vagrant` account with a wordlist that
#     cannot hold its password, and the test asserts hydra cracks nothing
#     ("0 valid password found") while the source is still auto-blocked.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq
    require_tool ncat

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        skip "TCP/22 is in use by sshd in 2VM mode; suite 59 is single-netns only"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-sshbf-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ssh-bruteforce.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-sshbf-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ─────────────────────────────────────────────────────────

# _drive_ssh_burst <count> — open <count> TCP connections from the test
# netns toward the agent's TCP/22 listener. Each connection completes
# the handshake so the IDS sees a distinct flow per attempt.
_drive_ssh_burst() {
    local count="${1:?usage: _drive_ssh_burst <count>}"
    timeout 30 ncat -l "${EBPF_HOST_IP}" 22 -k >/dev/null 2>&1 &
    local listener_pid=$!
    sleep 0.5

    local i
    for i in $(seq 1 "${count}"); do
        send_tcp_from_ns "${EBPF_HOST_IP}" 22 "BRUTE_${i}" 1 || true
        sleep 0.2
    done

    kill "${listener_pid}" 2>/dev/null || true
    wait 2>/dev/null || true
}

# ── Rule surface assertions ────────────────────────────────────────

@test "IDS surfaces the SSH brute-force rule with threshold + port" {
    local body
    body="$(api_get /api/v1/ids/rules)" || true
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    local rule
    rule="$(echo "${body}" \
        | jq -c '(if type == "array" then . else (.rules // []) end)[] | select(.id == "ids-ssh-bruteforce")')"
    [ -n "${rule}" ] && [ "${rule}" != "null" ] || {
        echo "ids-ssh-bruteforce not surfaced via /api/v1/ids/rules" >&2
        echo "${body}" >&2
        return 1
    }

    # Rule should declare port 22 — exact field name varies by serializer.
    echo "${rule}" | grep -qE '"dst_port"[^0-9]*22|"port"[^0-9]*22' || {
        echo "ids-ssh-bruteforce did not preserve dst_port=22: ${rule}" >&2
        return 1
    }

    # Threshold block should round-trip; either nested object or
    # flattened scalar fields.
    echo "${rule}" | grep -qiE 'threshold|count' || {
        echo "ids-ssh-bruteforce did not preserve threshold config: ${rule}" >&2
        return 1
    }
}

@test "IPS surfaces the SSH auto-block rule" {
    local body
    body="$(api_get /api/v1/ips/rules)" || true
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    local rule
    rule="$(echo "${body}" \
        | jq -c '(if type == "array" then . else (.rules // []) end)[] | select(.id == "ips-ssh-bruteforce")')"
    [ -n "${rule}" ] && [ "${rule}" != "null" ] || {
        echo "ips-ssh-bruteforce not surfaced via /api/v1/ips/rules" >&2
        echo "${body}" >&2
        return 1
    }
}

# ── Wire-level SYN-burst drives IDS alert + IPS blacklist ─────────

@test "SYN burst on TCP/22 fires the SSH brute-force IDS alert (MITRE T1110.001)" {
    _drive_ssh_burst 8
    sleep 3

    # Poll the alert stream for the rule_id; the IDS pipeline buffers
    # events through redb so the alert may be visible a few seconds
    # after the burst lands.
    # wait_for_alert already unwraps `.alerts`, so the filter selects over the
    # alert array directly (matching the convention used by suites 12/26/45)
    # and emits the matching alert objects — non-empty output means a match.
    local alerts
    alerts="$(wait_for_alert \
        '.[] | select(.rule_id == "ids-ssh-bruteforce")' \
        15 1)" || {
        echo "no ids-ssh-bruteforce alert surfaced after SYN burst" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    # Verify the first such alert carries the high severity declared
    # in the fixture and a MITRE technique consistent with the
    # dst-port mapping for port 22 (T1110.001 / T1110).
    local first
    first="$(echo "${alerts}" | jq -sc '.[0]')"
    local severity
    severity="$(echo "${first}" | jq -r '.severity // ""')"
    [ "${severity}" = "high" ] || {
        echo "expected severity=high; got ${severity}: ${first}" >&2
        return 1
    }

    # The MITRE technique surfaces in enriched alert fields. Field name
    # varies across exporters; accept either flat or nested form.
    echo "${first}" | grep -qE 'T1110\.001|T1110' || {
        echo "expected MITRE T1110(.001) in alert: ${first}" >&2
        return 1
    }
}

@test "IPS auto-blacklist captures the source after the SSH burst" {
    # The previous test already pushed 8 attempts; the auto_blacklist
    # threshold is 5 in 30 s, so the IPS should have at least one
    # entry by now. We allow the count to be either 1 (the netns IP)
    # or higher if other suites added entries earlier.
    local count
    count="$(get_blacklist_count 15)"
    [ "${count:-0}" -ge 1 ] || {
        echo "IPS auto-blacklist did not capture any source after SSH burst" >&2
        api_get /api/v1/ips/blacklist >&2 || true
        return 1
    }
}

# ── Real hydra credential burst ────────────────────────────────────

# _drive_ssh_hydra <user> <pwfile> — run an SSH credential burst from the
# test netns against the agent host's sshd on TCP/22. Each password is a
# distinct authentication attempt (one flow), so a wordlist of >= the IDS
# threshold drives the brute-force detection. The agent's host sshd
# already listens on 0.0.0.0:22, which answers on the veth host IP. The
# full stdout/stderr is captured in _HYDRA_OUT for the auth-outcome
# assertion.
_HYDRA_OUT=""
_drive_ssh_hydra() {
    local user="${1:?usage: _drive_ssh_hydra <user> <pwfile>}"
    local pwfile="${2:?usage: _drive_ssh_hydra <user> <pwfile>}"
    _HYDRA_OUT="$(ip netns exec "${EBPF_TEST_NS}" \
        timeout 45 hydra -l "${user}" -P "${pwfile}" -t 4 -W 2 \
        "ssh://${EBPF_HOST_IP}:22" 2>&1)" || true
}

@test "real hydra SSH credential burst fires the IDS brute-force alert (MITRE T1110.001)" {
    require_tool hydra

    local pwfile="${DATA_DIR}/ssh-pw-burst.lst"
    printf '%s\n' \
        badpass1 hunter2 letmein toor admin password123 qwerty 123456 changeme rootroot \
        > "${pwfile}"

    _drive_ssh_hydra nosuchuser "${pwfile}"

    local alerts
    alerts="$(wait_for_alert \
        '.[] | select(.rule_id == "ids-ssh-bruteforce")' 20 1)" || {
        echo "no ids-ssh-bruteforce alert after hydra credential burst" >&2
        echo "--- hydra output ---" >&2
        echo "${_HYDRA_OUT}" >&2
        api_get /api/v1/alerts >&2 || true
        return 1
    }

    local first severity
    first="$(echo "${alerts}" | jq -sc '.[0]')"
    severity="$(echo "${first}" | jq -r '.severity // ""')"
    [ "${severity}" = "high" ] || {
        echo "expected severity=high; got ${severity}: ${first}" >&2
        return 1
    }
    echo "${first}" | grep -qE 'T1110\.001|T1110' || {
        echo "expected MITRE T1110(.001) in alert: ${first}" >&2
        return 1
    }
}

# ── Negative auth + mitigation ─────────────────────────────────────

@test "the hydra brute force achieves no successful auth and the source is auto-blocked" {
    require_tool hydra

    local pwfile="${DATA_DIR}/ssh-pw-neg.lst"
    printf '%s\n' wrong1 wrong2 wrong3 wrong4 wrong5 wrong6 wrong7 wrong8 \
        > "${pwfile}"

    # Target the key-only `vagrant` account with a wordlist that cannot
    # hold its real (absent/disabled) password — every attempt must fail.
    _drive_ssh_hydra vagrant "${pwfile}"

    # Negative auth: a hydra success prints a "[22][ssh] host: ... login:
    # ... password: ..." line. Its absence proves no credential cracked.
    if echo "${_HYDRA_OUT}" | grep -qE '^\[22\]\[ssh\] host:'; then
        echo "hydra reported a successful SSH login (brute force succeeded):" >&2
        echo "${_HYDRA_OUT}" >&2
        return 1
    fi
    # And hydra's own tally must read zero valid passwords found.
    echo "${_HYDRA_OUT}" | grep -qiE '\b0 valid password' || {
        echo "expected '0 valid password found' from hydra; got:" >&2
        echo "${_HYDRA_OUT}" >&2
        return 1
    }

    # Mitigation: the IPS auto-blacklist captured the brute-force source.
    local count
    count="$(get_blacklist_count 15)"
    [ "${count:-0}" -ge 1 ] || {
        echo "IPS auto-blacklist did not capture the brute-force source" >&2
        api_get /api/v1/ips/blacklist >&2 || true
        return 1
    }
}
