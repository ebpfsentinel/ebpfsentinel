#!/usr/bin/env bats
# 61-pqc-handshake.bats — X25519MLKEM768 PQ-hybrid TLS handshake sweep.
#
# Verifies the agent's PQ-hybrid key exchange path end-to-end:
#
#   * pq_mode=prefer  — classical client (no PQ groups offered) still
#     negotiates, proving the classical fallback path; a PQ-aware client
#     lands on the X25519MLKEM768 hybrid named group.
#   * pq_mode=require — classical-only clients are rejected at the
#     handshake; PQ-aware client still succeeds, proving enforcement is
#     wired and not silently ignored.
#
# OpenSSL 3.5+ is the only client that natively supports the
# X25519MLKEM768 hybrid named group. The PQ-handshake assertions are
# skipped cleanly when the test VM ships an older OpenSSL, so the suite
# stays green on older fleets while still exercising the configuration
# surface (prefer/require parsing + binding) on every run.
#
# Coverage gaps (tracked, deferred):
#
#   * /api/v1/tls/status endpoint exposing the negotiated named group on
#     a per-connection basis (AC #1 second bullet). No such endpoint
#     exists in the OSS agent today; PQ negotiation is observable via
#     wire-level inspection (s_client output) only.
#   * HA mTLS PQ path (AC #3). The agent's HA stack is a separate
#     listener and runs in multi-node topology; the OSS test fleet runs
#     single-VM. Tracked as a multi-VM enablement task.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_tool curl
    require_tool openssl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-pqc-$$"
    export CERT_DIR="${CERT_DIR:-/tmp/ebpfsentinel-test-certs}"
    mkdir -p "${DATA_DIR}"

    # This suite runs a local userspace agent for a localhost TLS handshake —
    # no kernel/transit path. Prefer a build tree, then the installed binary.
    # In 2VM/3VM mode bats runs on the client VM, which has neither (target/ is
    # rsync-excluded), so pull the binary from the agent VM over the existing
    # SSH key.
    AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    if [ ! -x "${AGENT_BIN}" ]; then
        if [ -x /usr/local/bin/ebpfsentinel-agent ]; then
            AGENT_BIN=/usr/local/bin/ebpfsentinel-agent
        elif [ "${EBPF_2VM_MODE:-false}" = "true" ] && [ -n "${AGENT_VM_IP:-}" ]; then
            AGENT_BIN="${DATA_DIR}/ebpfsentinel-agent"
            scp -i "${AGENT_SSH_KEY}" -o StrictHostKeyChecking=no \
                "vagrant@${AGENT_VM_IP}:/usr/local/bin/ebpfsentinel-agent" \
                "${AGENT_BIN}" >/dev/null 2>&1 && chmod +x "${AGENT_BIN}"
        fi
    fi
    [ -x "${AGENT_BIN}" ] || skip "agent binary not available on this host"
    export AGENT_BIN

    if [ ! -f "${CERT_DIR}/server.pem" ]; then
        bash "${SCRIPT_DIR}/generate-certs.sh" --out-dir "${CERT_DIR}"
    fi

    # Resolve the openssl client binary. X25519MLKEM768 needs OpenSSL >= 3.5,
    # which Ubuntu 24.04 does not ship; the provisioner builds it under
    # /opt/openssl-3.5 (see setup-agent.sh). Prefer that build when it advertises
    # the hybrid group, else fall back to the system openssl (PQ tests skip).
    # OpenSSL 3.5 advertises the hybrid under `list -kem-algorithms`; the older
    # `list -groups` is empty there, so probe both listings.
    _openssl_has_mlkem() {
        { "$1" list -groups 2>/dev/null; "$1" list -kem-algorithms 2>/dev/null; } \
            | grep -q 'X25519MLKEM768'
    }
    export EBPF_OPENSSL="openssl"
    if [ -x /opt/openssl-3.5/bin/openssl ] && _openssl_has_mlkem /opt/openssl-3.5/bin/openssl; then
        EBPF_OPENSSL="/opt/openssl-3.5/bin/openssl"
    fi

    # Detect PQ-hybrid client support in the resolved openssl build. If
    # X25519MLKEM768 is unknown, every PQ-handshake test in this file
    # is skipped, but the configuration-surface assertions still run.
    if _openssl_has_mlkem "${EBPF_OPENSSL}"; then
        export EBPF_OPENSSL_HAS_MLKEM=1
    else
        export EBPF_OPENSSL_HAS_MLKEM=0
    fi

    export PREPARED_CONFIG_PREFER="/tmp/ebpfsentinel-test-pq-prefer-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        "${FIXTURE_DIR}/config-tls-pq-prefer.yaml" > "${PREPARED_CONFIG_PREFER}"
    chmod 640 "${PREPARED_CONFIG_PREFER}"

    export PREPARED_CONFIG_REQUIRE="/tmp/ebpfsentinel-test-pq-require-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        "${FIXTURE_DIR}/config-tls-pq-require.yaml" > "${PREPARED_CONFIG_REQUIRE}"
    chmod 640 "${PREPARED_CONFIG_REQUIRE}"

    export AGENT_HTTP_PORT="${AGENT_TLS_PORT}"

    # This suite starts its own agent on the local host (binds 0.0.0.0). In
    # 2VM/3VM mode the inherited AGENT_HOST points at the remote agent VM, so
    # the health probe and s_client must be re-pinned to localhost or they hit
    # the wrong host (no TLS on :8443 there → connection refused).
    export AGENT_HOST="127.0.0.1"
    export TLS_URL="https://${AGENT_HOST}:${AGENT_TLS_PORT}"
    export BASE_URL="http://${AGENT_HOST}:${AGENT_HTTP_PORT}"

    stop_agent 2>/dev/null || true
    _kill_port_holders "${AGENT_TLS_PORT}" "${AGENT_GRPC_PORT}"

    "${AGENT_BIN}" --config "${PREPARED_CONFIG_PREFER}" \
        >"${AGENT_LOG_FILE}" 2>&1 &
    AGENT_PID=$!
    echo "${AGENT_PID}" > "${AGENT_PID_FILE}"
    sleep 0.3
    if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
        echo "PQ-prefer agent exited immediately. Log tail:" >&2
        tail -20 "${AGENT_LOG_FILE}" >&2
        return 1
    fi
    wait_for_agent_tls "${TLS_URL}/healthz" "${CERT_DIR}/ca.pem" || {
        echo "PQ-prefer agent failed to start. Log tail:" >&2
        tail -20 "${AGENT_LOG_FILE}" >&2
        return 1
    }
}

setup() {
    # bats re-sources the file (and thus constants.bash) before each test,
    # which recomputes TLS_URL from the inherited AGENT_HOST — in 2VM/3VM mode
    # that is the remote agent VM. This suite's agent runs locally, so re-pin
    # every test to localhost (mirrors the setup_file pin).
    export AGENT_HOST="127.0.0.1"
    export TLS_URL="https://${AGENT_HOST}:${AGENT_TLS_PORT}"
    export BASE_URL="http://${AGENT_HOST}:${AGENT_TLS_PORT}"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "${DATA_DIR}"
    rm -f "${PREPARED_CONFIG_PREFER:-}" "${PREPARED_CONFIG_REQUIRE:-}"
}

# ── Helpers ─────────────────────────────────────────────────────────

# _s_client_named_group <-groups arg> [extra openssl s_client args...]
#
# Drives a TLS 1.3 handshake against the agent's TLS port restricted to
# the supplied named-group list, parses the openssl trace for the
# "Server Temp Key" line, and prints just the negotiated group name.
# Returns a non-zero exit code if the handshake itself failed.
_s_client_named_group() {
    local groups="${1:?usage: _s_client_named_group <groups> [args...]}"
    shift
    local out
    out="$(echo Q \
        | timeout 5 "${EBPF_OPENSSL:-openssl}" s_client \
            -connect "${AGENT_HOST}:${AGENT_TLS_PORT}" \
            -CAfile "${CERT_DIR}/ca.pem" \
            -groups "${groups}" \
            -tls1_3 \
            -brief \
            -servername "${AGENT_HOST}" \
            "$@" 2>&1)" || return 1
    # `-brief` prints "Server Temp Key: <group>, <bits> bits" on OpenSSL < 3.5
    # and "Peer Temp Key: <group>, <bits> bits" on OpenSSL >= 3.5; the
    # negotiated named group is the substring before the comma.
    local key_line
    key_line="$(echo "${out}" | grep -E '^(Server|Peer) Temp Key' | head -1)"
    if [ -z "${key_line}" ]; then
        # Older openssl (< 3.5) uses a different trace format; fall
        # back to parsing -msg style if `-brief` was a no-op.
        key_line="$(echo "${out}" | grep -E 'Negotiated TLS1.3 group' | head -1)"
    fi
    if [ -z "${key_line}" ]; then
        echo "no named group line in s_client output" >&2
        echo "${out}" >&2
        return 1
    fi
    echo "${key_line}" | sed -E 's/^[^:]+:[[:space:]]*//; s/,.*$//'
}

# Readiness probe by TCP connect rather than a completed TLS handshake.
# In pq_mode=require the server rejects any client that cannot offer the PQ
# hybrid group, so a curl/openssl health probe on a host without MLKEM support
# can never succeed even though the agent is up — confirming the port is
# listening is the correct restart check; the require-mode rejection itself is
# asserted by the test body.
_wait_for_tls_port() {
    retry "${RETRY_MAX_ATTEMPTS}" \
        bash -c "exec 3<>/dev/tcp/${AGENT_HOST}/${AGENT_TLS_PORT}"
}

_restart_agent_with() {
    local config="${1:?usage: _restart_agent_with <config>}"
    stop_agent 2>/dev/null || true
    _kill_port_holders "${AGENT_TLS_PORT}" "${AGENT_GRPC_PORT}"
    "${AGENT_BIN}" --config "${config}" >"${AGENT_LOG_FILE}" 2>&1 &
    AGENT_PID=$!
    echo "${AGENT_PID}" > "${AGENT_PID_FILE}"
    sleep 0.3
    kill -0 "${AGENT_PID}" 2>/dev/null || return 1
    _wait_for_tls_port
}

# ── prefer-mode tests ──────────────────────────────────────────────

@test "TLS endpoint serves over HTTPS in pq_mode=prefer" {
    local status
    status="$(curl -s -o /dev/null --max-time "${HTTP_TIMEOUT}" \
        --cacert "${CERT_DIR}/ca.pem" \
        -w '%{http_code}' "${TLS_URL}/healthz")"
    [ "${status}" = "200" ] || {
        echo "expected 200 from /healthz in pq_mode=prefer; got ${status}" >&2
        return 1
    }
}

@test "classical client (X25519 only) negotiates in pq_mode=prefer" {
    local group
    group="$(_s_client_named_group X25519)" || {
        echo "classical X25519 client failed to negotiate against pq_mode=prefer" >&2
        return 1
    }
    [ "${group}" = "X25519" ] || {
        echo "classical client expected to land on X25519; got ${group}" >&2
        return 1
    }
}

@test "PQ-aware client (X25519MLKEM768) lands on the hybrid group in prefer mode" {
    if [ "${EBPF_OPENSSL_HAS_MLKEM:-0}" != "1" ]; then
        skip "local openssl lacks X25519MLKEM768; PQ handshake assertion deferred"
    fi
    local group
    group="$(_s_client_named_group X25519MLKEM768)" || {
        echo "PQ-aware client failed to negotiate hybrid against pq_mode=prefer" >&2
        return 1
    }
    [ "${group}" = "X25519MLKEM768" ] || {
        echo "PQ-aware client expected X25519MLKEM768; got ${group}" >&2
        return 1
    }
}

# ── require-mode tests (restart agent on require fixture) ──────────

@test "pq_mode=require rejects classical-only clients" {
    _restart_agent_with "${PREPARED_CONFIG_REQUIRE}" || {
        echo "agent failed to restart in pq_mode=require" >&2
        return 1
    }

    # Force the client to advertise only classical groups; in
    # require mode the server must abort the handshake.
    local rc=0
    echo Q \
        | timeout 5 "${EBPF_OPENSSL:-openssl}" s_client \
            -connect "${AGENT_HOST}:${AGENT_TLS_PORT}" \
            -CAfile "${CERT_DIR}/ca.pem" \
            -groups X25519:secp256r1 \
            -tls1_3 \
            -brief \
            -servername "${AGENT_HOST}" \
            >/dev/null 2>&1 || rc=$?
    [ "${rc}" -ne 0 ] || {
        echo "pq_mode=require accepted a classical-only client (no rejection)" >&2
        return 1
    }
}

@test "pq_mode=require still accepts PQ-aware clients" {
    if [ "${EBPF_OPENSSL_HAS_MLKEM:-0}" != "1" ]; then
        skip "local openssl lacks X25519MLKEM768; PQ require-mode acceptance deferred"
    fi
    local group
    group="$(_s_client_named_group X25519MLKEM768)" || {
        echo "PQ-aware client failed against pq_mode=require" >&2
        return 1
    }
    [ "${group}" = "X25519MLKEM768" ] || {
        echo "expected X25519MLKEM768 in require mode; got ${group}" >&2
        return 1
    }
}

# ── Documented deferrals ──────────────────────────────────────────

@test "tls/status surfaces the per-connection negotiated key-exchange group" {
    # Run in prefer mode so a classical OpenSSL curl client can complete the
    # handshake (the preceding require-mode test would reject it).
    _restart_agent_with "${PREPARED_CONFIG_PREFER}" || {
        echo "agent failed to restart in pq_mode=prefer" >&2
        return 1
    }

    local body
    body="$(curl -s --max-time "${HTTP_TIMEOUT}" \
        --cacert "${CERT_DIR}/ca.pem" \
        "${TLS_URL}/api/v1/tls/status")" || {
        echo "GET /api/v1/tls/status failed" >&2
        return 1
    }

    echo "${body}" | jq -e '.tls == true' >/dev/null 2>&1 || {
        echo "expected tls=true from /api/v1/tls/status; got: ${body}" >&2
        return 1
    }

    local group
    group="$(echo "${body}" | jq -r '.negotiated_group // empty')"
    [ -n "${group}" ] || {
        echo "tls/status did not surface a negotiated_group; got: ${body}" >&2
        return 1
    }
    case "${group}" in
        X25519MLKEM768 | X25519 | secp256r1 | secp384r1 | secp521r1) : ;;
        *)
            echo "unexpected negotiated_group '${group}'" >&2
            return 1
            ;;
    esac

    # The post_quantum flag must agree with the named group. A classical curl
    # client lands on X25519 (post_quantum=false); a PQ-aware client would show
    # X25519MLKEM768 (post_quantum=true).
    local pq
    pq="$(echo "${body}" | jq -r '.post_quantum')"
    if [ "${group}" = "X25519MLKEM768" ]; then
        [ "${pq}" = "true" ] || {
            echo "post_quantum must be true for X25519MLKEM768; got ${pq}" >&2
            return 1
        }
    else
        [ "${pq}" = "false" ] || {
            echo "post_quantum must be false for ${group}; got ${pq}" >&2
            return 1
        }
    fi
}

@test "HA mTLS PQ path is tracked as a multi-VM coverage gap" {
    skip "agent HA stack runs on a separate listener and requires a multi-node fixture; AC #3 deferred"
}
