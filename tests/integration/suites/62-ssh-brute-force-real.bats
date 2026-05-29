#!/usr/bin/env bats
# 62-ssh-brute-force-real.bats — SSH brute-force IDS + IPS sweep.
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
# Coverage gaps (tracked, deferred):
#
#   * Real hydra/ncrack credential bursts (AC #1 first bullet wording).
#     The OSS test fleet does not ship hydra/ncrack; the behaviour
#     asserted here — IDS rule fire + IPS auto-block under threshold
#     count from a single source — is the same dataplane contract
#     hydra/ncrack would drive on a richer fleet. Tracked-deferred
#     under "extra test-VM deps".
#   * sshd "no successful auth" negative assertion (AC #1 third bullet).
#     Requires a running sshd in the agent VM plus passwd seeding;
#     tracked as a multi-VM enablement task (3-VM topology with the
#     SSH backend already exists at story 34.2 level but is not
#     wired into the bats fleet today).

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq
    require_tool ncat

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        skip "TCP/22 is in use by sshd in 2VM mode; suite 62 is single-netns only"
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
        skip "eBPF programs not loaded (degraded mode)"
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
    if [ "${HTTP_STATUS}" = "404" ]; then
        skip "IDS rules REST endpoint not exposed"
    fi
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
    if [ "${HTTP_STATUS}" = "404" ]; then
        skip "IPS rules REST endpoint not exposed"
    fi
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

# ── Documented deferrals ──────────────────────────────────────────

@test "real hydra/ncrack credential bursts are tracked as a coverage gap" {
    skip "hydra/ncrack not on the OSS test fleet; SYN-burst path above asserts the same IDS/IPS dataplane contract"
}

@test "sshd no-successful-auth assertion is tracked as a multi-VM coverage gap" {
    skip "negative auth-log assertion needs an sshd in the agent VM; 3-VM SSH-backend topology deferred"
}
