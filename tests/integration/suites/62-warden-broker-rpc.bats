#!/usr/bin/env bats
# 62-warden-broker-rpc.bats — the privilege broker itself.
#
# Suite 57 asserts that every eBPF program loads through a BPF token, which
# exercises the broker's `Delegate` path as a side effect. This suite covers
# the broker as a component: its socket, its authentication gate, and the
# privileged operations it forwards for an agent that has no capabilities of
# its own.
#
#   * The warden runs as a separate root process and owns a mode-0666 unix
#     socket (the file mode is deliberately permissive — SO_PEERCRED is the
#     auth gate, not the mode).
#   * The agent runs in its own user namespace, distinct from init's, and
#     still ends up with eBPF loaded — only the broker can explain that.
#   * A peer whose uid is not the served one is dropped without being
#     served, while the served uid keeps its connection open.
#   * Conntrack teardown, a netlink operation the user-namespace agent
#     cannot perform itself, succeeds end-to-end through the broker.
#
# Requires: root, kernel >= 6.9, local eBPF build + warden binary, python3,
# setpriv, ncat, jq. VM-only (Vagrant agent).

load '../lib/helpers'
load '../lib/ebpf_helpers'

# start_ebpf_agent derives the broker socket from the host veth name.
_warden_sock() {
    echo "/tmp/ebpfsentinel-warden-${EBPF_VETH_HOST:-local}.sock"
}

_warden_pid() {
    cat "${AGENT_PID_FILE}.warden" 2>/dev/null || echo ""
}

_agent_pid() {
    cat "${AGENT_PID_FILE}" 2>/dev/null || echo ""
}

# _probe_as <uid|root> — run the peer probe, optionally as another uid.
_probe_as() {
    local who="${1}"
    local sock probe
    sock="$(_warden_sock)"
    probe="${BATS_TEST_DIRNAME}/../scripts/warden-peer-probe.py"

    if [ "${who}" = "root" ]; then
        python3 "${probe}" "${sock}" 2
    else
        setpriv --reuid "${who}" --regid "${who}" --clear-groups \
            python3 "${probe}" "${sock}" 2
    fi
}

setup_file() {
    require_root
    require_kernel 6 9
    require_tool python3
    require_tool setpriv
    require_tool ncat
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$(dirname "${AGENT_BIN}")/warden" ] \
        || skip "warden binary not found next to ${AGENT_BIN} — split deployment not built"

    export DATA_DIR="/tmp/ebpfsentinel-test-data-warden-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-conntrack.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-warden-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Broker process + socket ────────────────────────────────────────

@test "warden broker runs as a separate root process" {
    local wpid apid
    wpid="$(_warden_pid)"
    apid="$(_agent_pid)"

    [ -n "${wpid}" ] || skip "no warden pid recorded — agent started without the broker"
    kill -0 "${wpid}" 2>/dev/null || {
        echo "warden pid ${wpid} is not alive" >&2
        tail -30 "${AGENT_LOG_FILE}" >&2 || true
        return 1
    }

    [ "${wpid}" != "${apid}" ] || {
        echo "warden and agent share pid ${wpid} — not a split deployment" >&2
        return 1
    }

    local euid
    euid="$(awk '/^Uid:/ {print $3}' "/proc/${wpid}/status" 2>/dev/null)"
    [ "${euid}" = "0" ] || {
        echo "warden effective uid is ${euid}, expected 0" >&2
        return 1
    }
}

@test "broker socket is a unix socket with mode 0666" {
    local sock
    sock="$(_warden_sock)"
    [ -S "${sock}" ] || {
        echo "no broker socket at ${sock}" >&2
        ls -l /tmp/ebpfsentinel-warden-* >&2 2>/dev/null || true
        return 1
    }

    local mode owner
    mode="$(stat -c '%a' "${sock}")"
    owner="$(stat -c '%u' "${sock}")"
    # 0666 is intentional: the rootless agent may run under another uid, and
    # SO_PEERCRED — not the file mode — is what authenticates it.
    [ "${mode}" = "666" ] || {
        echo "expected socket mode 666; got ${mode}" >&2
        return 1
    }
    [ "${owner}" = "0" ] || {
        echo "expected root-owned socket; got uid ${owner}" >&2
        return 1
    }
}

@test "broker announces delegation and its protocol version" {
    grep -q "\[warden\] delegation ready" "${AGENT_LOG_FILE}" || {
        echo "no delegation-ready line in the agent/warden log" >&2
        tail -40 "${AGENT_LOG_FILE}" >&2 || true
        return 1
    }
    grep -qE "\[warden\] serving on .* protocol v[0-9]+" "${AGENT_LOG_FILE}" || {
        echo "no serving line with a protocol version" >&2
        return 1
    }

    # A version mismatch is the failure mode that silently degrades the agent
    # to API-only; it must not be present.
    ! grep -qi "protocol mismatch\|unsupported protocol" "${AGENT_LOG_FILE}" || {
        echo "warden/agent protocol mismatch reported" >&2
        grep -i "protocol" "${AGENT_LOG_FILE}" >&2 || true
        return 1
    }
}

# ── Rootless split ─────────────────────────────────────────────────

@test "agent runs in its own user namespace yet has eBPF loaded" {
    local apid
    apid="$(_agent_pid)"
    [ -n "${apid}" ] && [ -d "/proc/${apid}" ] || skip "agent pid not resolvable"

    local agent_ns init_ns
    agent_ns="$(readlink "/proc/${apid}/ns/user" 2>/dev/null || true)"
    init_ns="$(readlink /proc/1/ns/user 2>/dev/null || true)"
    [ -n "${agent_ns}" ] && [ -n "${init_ns}" ] || skip "user namespaces not readable"

    [ "${agent_ns}" != "${init_ns}" ] || {
        echo "agent shares init's user namespace (${agent_ns}) — not rootless" >&2
        return 1
    }

    # An agent in an unprivileged user namespace cannot have loaded these on
    # its own: the bpffs and the token came from the broker.
    local body
    body="$(api_get /api/v1/ebpf/status)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || {
        echo "GET /api/v1/ebpf/status returned ${HTTP_STATUS}" >&2
        return 1
    }
    echo "${body}" | jq -e '[.programs[] | select(.loaded)] | length >= 1' >/dev/null || {
        echo "no loaded eBPF program reported: ${body}" >&2
        return 1
    }
}

# ── SO_PEERCRED gate ───────────────────────────────────────────────

@test "a peer with an unserved uid is dropped without being served" {
    local sock
    sock="$(_warden_sock)"
    [ -S "${sock}" ] || skip "no broker socket to probe"

    local verdict
    verdict="$(_probe_as 65534)"
    [ "${verdict}" = "closed" ] || {
        echo "expected the broker to drop uid 65534; probe said '${verdict}'" >&2
        return 1
    }
}

@test "the served uid keeps its connection open" {
    local sock
    sock="$(_warden_sock)"
    [ -S "${sock}" ] || skip "no broker socket to probe"

    # The harness starts the warden with --uid 0 and the probe runs as root,
    # so the connection must be accepted and held awaiting a request frame.
    local verdict
    verdict="$(_probe_as root)"
    [ "${verdict}" = "open" ] || {
        echo "expected the broker to serve uid 0; probe said '${verdict}'" >&2
        return 1
    }
}

@test "the broker survives a rejected peer" {
    local sock
    sock="$(_warden_sock)"
    [ -S "${sock}" ] || skip "no broker socket to probe"

    _probe_as 65534 >/dev/null || true

    local wpid
    wpid="$(_warden_pid)"
    [ -n "${wpid}" ] && kill -0 "${wpid}" 2>/dev/null || {
        echo "warden died after a rejected connection" >&2
        return 1
    }

    # And it still serves the legitimate uid afterwards.
    local verdict
    verdict="$(_probe_as root)"
    [ "${verdict}" = "open" ] || {
        echo "broker stopped serving uid 0 after a rejection: '${verdict}'" >&2
        return 1
    }
}

# ── Brokered privileged operation ──────────────────────────────────

@test "conntrack teardown succeeds through the broker" {
    # Establish a tracked flow first so the flush has something to tear down.
    timeout 6 ncat -l "$EBPF_HOST_IP" 9876 >/dev/null 2>&1 &
    local listener_pid=$!
    sleep 0.5
    send_tcp_from_ns "$EBPF_HOST_IP" 9876 "WARDEN_CT_TEST" 2 || true
    kill "${listener_pid}" 2>/dev/null || true
    wait "${listener_pid}" 2>/dev/null || true
    sleep 1

    # The agent holds no CAP_NET_ADMIN in its user namespace: the netlink
    # teardown can only reach the kernel through the broker.
    api_post /api/v1/conntrack/flush '{}' >/dev/null
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || {
        echo "conntrack flush returned ${HTTP_STATUS}" >&2
        tail -30 "${AGENT_LOG_FILE}" >&2 || true
        return 1
    }

    # A broker refusal surfaces in the log rather than in the HTTP status.
    ! grep -qi "warden.*denied\|broker.*refused\|ConntrackDelete.*error" \
        "${AGENT_LOG_FILE}" || {
        echo "broker refused the conntrack teardown" >&2
        grep -i "warden\|conntrack" "${AGENT_LOG_FILE}" | tail -20 >&2 || true
        return 1
    }
}
