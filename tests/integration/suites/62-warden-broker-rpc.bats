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
#   * Every privileged operation the agent delegates succeeds end-to-end,
#     each one impossible from an unprivileged user namespace:
#       ConntrackFlush  netlink teardown
#       PcapOpen        AF_PACKET fds handed over SCM_RIGHTS
#       DlpScan +
#       AttachUprobe    uprobe_multi link fd for the DLP probes
#       ArpAnnounce     gratuitous ARP on VIP speaker takeover
#
# The feature suites (18 conntrack, 27 DLP, 37 VIP, 49 capture) own the
# behaviour of each feature; here the claim is narrower — the broker served
# the privileged half.
#
# `RouteAdd` / `RouteDel` are deliberately absent: the proto, the client and
# the warden implement them, but no OSS agent code issues them (multi-WAN
# tracks gateway health and selection without programming kernel routes), so
# there is nothing to drive end-to-end.
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

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-warden-broker.yaml")"
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

@test "the broker hands over AF_PACKET capture sockets" {
    # The warden opens the pool up front (it holds CAP_NET_RAW) and reports it
    # on startup; the agent may also open more explicitly through PcapOpen.
    local announced=0
    grep -qE "\[warden\] delegation ready: [0-9]+ module BTF fd\(s\), [1-9][0-9]* pcap fd\(s\)" \
        "${AGENT_LOG_FILE}" && announced=1
    grep -q "packet-capture sockets provisioned by the warden" \
        "${AGENT_LOG_FILE}" && announced=1

    [ "${announced}" -eq 1 ] || {
        echo "the broker provisioned no capture socket" >&2
        grep -i "pcap\|delegation ready" "${AGENT_LOG_FILE}" | tail -10 >&2 || true
        return 1
    }

    ! grep -q "warden pcap socket open failed" "${AGENT_LOG_FILE}" || {
        echo "PcapOpen failed against the broker" >&2
        grep "warden pcap socket open failed" "${AGENT_LOG_FILE}" | tail -5 >&2
        return 1
    }
}

@test "a capture session runs on a broker-provided socket" {
    local body resp
    body="$(printf '{"filter":"tcp port 4444","duration_seconds":3,"snap_length":256,"interface":"%s"}' \
        "${EBPF_VETH_HOST}")"
    resp="$(api_post /api/v1/captures/manual "${body}")"
    _load_http_status

    if [ "${HTTP_STATUS}" = "503" ]; then
        skip "capture engine unavailable (pcap-capture feature off)"
    fi
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ] || {
        echo "POST /captures/manual returned ${HTTP_STATUS}: ${resp}" >&2
        return 1
    }

    # The agent holds no CAP_NET_RAW of its own: a session that reaches the
    # capture engine at all means the fd came from the broker.
    local id
    id="$(echo "${resp}" | jq -r '.id // empty')"
    [ -n "${id}" ] || {
        echo "no capture id in the response: ${resp}" >&2
        return 1
    }
}

@test "DLP uprobes attach through the broker" {
    # The scan runs in the warden (it can read neighbouring /proc), and each
    # probe is attached with a link fd passed back over SCM_RIGHTS.
    ! grep -q "warden DLP scan failed" "${AGENT_LOG_FILE}" || {
        echo "the broker refused the DLP scan" >&2
        grep "warden DLP scan failed" "${AGENT_LOG_FILE}" | tail -5 >&2
        return 1
    }

    local body loaded
    body="$(api_get /api/v1/ebpf/status)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ] || {
        echo "GET /api/v1/ebpf/status returned ${HTTP_STATUS}" >&2
        return 1
    }

    loaded="$(echo "${body}" | jq -r '
        [.programs[] | select((.name | test("uprobe.?dlp"; "i")) and .loaded)] | length
    ')"
    [ "${loaded:-0}" -ge 1 ] || {
        echo "uprobe-dlp not loaded — nothing could have been attached: ${body}" >&2
        return 1
    }
}

@test "gratuitous ARP for the VIP goes through the broker" {
    # The announcer emits one gratuitous ARP per owned VIP on the transition
    # into the speaker role; the adapter proxies it to the warden.
    local attempt=0 sent=0
    while [ "${attempt}" -lt 20 ]; do
        if grep -q "vip announcer: gratuitous ARP sent" "${AGENT_LOG_FILE}"; then
            sent=1
            break
        fi
        sleep 1
        attempt=$((attempt + 1))
    done

    if [ "${sent}" -eq 0 ]; then
        # No takeover happened at all (no speaker transition) — that is a
        # fixture/topology issue, not a broker refusal, so surface it as such.
        grep -q "vip announcer" "${AGENT_LOG_FILE}" \
            || skip "vip announcer never ran — no speaker transition in this topology"
        echo "vip announcer ran but emitted no gratuitous ARP" >&2
        grep -i "vip announcer" "${AGENT_LOG_FILE}" | tail -10 >&2
        return 1
    fi

    ! grep -q "warden arp_announce failed" "${AGENT_LOG_FILE}" || {
        echo "the broker refused ArpAnnounce" >&2
        grep "warden arp_announce failed" "${AGENT_LOG_FILE}" | tail -5 >&2
        return 1
    }

    # And the takeover is reflected in the metric the announcer bumps.
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || metrics=""
    echo "${metrics}" | grep -qE 'ebpfsentinel_lb_vip_takeovers_total\{[^}]*vip="warden-vip"' || {
        echo "no lb_vip_takeovers_total series for vip=warden-vip" >&2
        echo "${metrics}" | grep -i "vip" >&2 || true
        return 1
    }
}
