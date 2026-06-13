#!/usr/bin/env bats
# 49-capture-pcap-export.bats — Manual packet capture lifecycle + pcap export.
#
# Drives the agent's capture engine via /api/v1/captures/manual (and the
# matching `ebpfsentinel-agent capture start` CLI). The capture engine is
# wired in startup whenever the binary is built with the `pcap-capture`
# feature (default-on); when the feature is off the engine accepts the
# session but no pcap is produced, so we surface that as a skip.
#
# Suite assertions:
#   * POST creates a session and the pcap file lands at the documented
#     /var/lib/ebpfsentinel/captures/<id>.pcap path
#   * tcpdump -r can parse the produced pcap (validity check)
#   * the session moves to status=completed once the duration elapses
#   * the CLI subcommand is equivalent to the REST call

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 5 15
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-capture-$$"
    mkdir -p "$DATA_DIR"

    # The capture handler writes to /var/lib/ebpfsentinel/captures/. The
    # directory is not pre-created by the agent or the provisioner, so we
    # mkdir it on the agent VM up-front; pcap savefile init will fail
    # otherwise and the test would surface as an opaque pcap-not-found.
    _agent_ssh_sudo mkdir -p /var/lib/ebpfsentinel/captures \
        >/dev/null 2>&1 || true

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-capture.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _agent_ssh_sudo rm -rf /var/lib/ebpfsentinel/captures 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-capture-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_capture_iface() {
    # Capture suite runs single-NIC against the configured agent eth1.
    echo "${AGENT_IFACE:-eth1}"
}

_drive_traffic_to_port() {
    local port="${1:?usage: _drive_traffic_to_port <port>}"
    # Fire a couple of TCP SYN+payload bursts to the loopback of the agent
    # on the target port. The capture filter is "tcp port <port>"; the
    # destination doesn't have to be listening — we just need wire
    # traffic that tcpdump can record. Loop on the test host (one nc per
    # iteration) so the remote shell never re-parses a multi-statement
    # script — SSH flattens args, which would mangle a remote for-loop.
    local i
    for i in 1 2 3 4 5; do
        printf 'probe\n' | _agent_ssh_sudo nc -w1 127.0.0.1 "${port}" >/dev/null 2>&1 || true
        sleep 0.1
    done
}

_pull_remote_pcap() {
    local remote="${1:?usage: _pull_remote_pcap <remote_path> <local>}"
    local local_dest="${2:?usage: _pull_remote_pcap <remote_path> <local>}"
    # The agent runs as root, so the pcap lands root-owned 0600 and the
    # unprivileged vagrant scp user cannot read it. Relax to world-readable
    # first (test artefact in a throwaway VM dir).
    _agent_ssh_sudo chmod 0644 "${remote}" >/dev/null 2>&1 || true
    scp -i "${AGENT_SSH_KEY}" -o StrictHostKeyChecking=no \
        "vagrant@${AGENT_VM_IP}:${remote}" "${local_dest}" >/dev/null 2>&1
}

# ── REST: create + collect + parse ──────────────────────────────────

@test "POST /api/v1/captures/manual writes a parseable pcap" {
    local iface
    iface="$(_capture_iface)"
    local body
    body="$(printf '{"filter":"tcp port 4444","duration_seconds":8,"snap_length":1500,"interface":"%s"}' "${iface}")"

    local resp
    resp="$(api_post /api/v1/captures/manual "${body}")"
    _load_http_status
    if [ "${HTTP_STATUS}" = "503" ]; then
        skip "capture engine not available (pcap-capture feature off?)"
    fi
    [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "201" ] || {
        echo "POST /captures/manual returned HTTP ${HTTP_STATUS}: ${resp}" >&2
        return 1
    }

    local id remote_path
    id="$(echo "${resp}" | jq -r '.id')"
    remote_path="$(echo "${resp}" | jq -r '.output_path')"
    [ -n "${id}" ] && [ "${id}" != "null" ]
    [ "${remote_path}" = "/var/lib/ebpfsentinel/captures/${id}.pcap" ]

    # Drive a handful of matching frames through the configured interface.
    _drive_traffic_to_port 4444

    # Wait for the session to flip to "completed" (duration + small grace).
    local i status
    for ((i = 0; i < 20; i++)); do
        status="$(api_get /api/v1/captures | jq -r --arg id "${id}" \
            '.captures[] | select(.id == $id) | .status')"
        [ "${status}" = "completed" ] && break
        sleep 1
    done
    [ "${status}" = "completed" ] || {
        echo "capture ${id} did not reach completed status: ${status:-?}" >&2
        return 1
    }

    # Pull the pcap back to the test host and verify tcpdump can parse it.
    local local_pcap="${DATA_DIR}/${id}.pcap"
    _pull_remote_pcap "${remote_path}" "${local_pcap}" || {
        echo "scp failed for ${remote_path}" >&2
        return 1
    }
    [ -s "${local_pcap}" ] || {
        echo "pcap ${local_pcap} is empty" >&2
        return 1
    }
    tcpdump -nr "${local_pcap}" >/dev/null 2>&1 || {
        echo "tcpdump cannot parse pcap ${local_pcap}" >&2
        return 1
    }
}

# ── REST list shows the completed session ───────────────────────────

@test "GET /api/v1/captures lists prior capture sessions" {
    local body
    body="$(api_get /api/v1/captures)" || return 1
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]
    # Expect at least one session from the test above (or any prior).
    local count
    count="$(echo "${body}" | jq -r '.captures | length')"
    [ "${count}" -ge 1 ]
}

# ── CLI parity ──────────────────────────────────────────────────────

@test "capture start via CLI produces a parseable pcap" {
    if ! _agent_ssh test -x /usr/local/bin/ebpfsentinel-agent 2>/dev/null; then
        skip "ebpfsentinel-agent CLI not installed on agent VM"
    fi

    local iface
    iface="$(_capture_iface)"

    # Pass the whole command as one string so SSH forwards it verbatim and
    # the remote shell parses the multi-word --filter argument; SSH flattens
    # separate argv with spaces, which would split "tcp port 4445".
    local out
    out="$(_agent_ssh_sudo "/usr/local/bin/ebpfsentinel-agent --output json capture start --filter 'tcp port 4445' --duration 6s --interface '${iface}'" 2>&1)" || {
        echo "CLI capture start failed: ${out}" >&2
        return 1
    }

    # Resolve the id from CLI output or from the REST list.
    local id remote_path
    id="$(echo "${out}" | jq -r '.id // empty' 2>/dev/null)" || true
    if [ -z "${id}" ]; then
        id="$(api_get /api/v1/captures \
            | jq -r '.captures[] | select(.filter == "tcp port 4445") | .id' \
            | tail -1)"
    fi
    [ -n "${id}" ] || {
        echo "could not resolve CLI-created capture id" >&2
        echo "stdout: ${out}" >&2
        return 1
    }
    remote_path="/var/lib/ebpfsentinel/captures/${id}.pcap"

    _drive_traffic_to_port 4445

    local i status
    for ((i = 0; i < 20; i++)); do
        status="$(api_get /api/v1/captures | jq -r --arg id "${id}" \
            '.captures[] | select(.id == $id) | .status')"
        [ "${status}" = "completed" ] && break
        sleep 1
    done
    [ "${status}" = "completed" ]

    local local_pcap="${DATA_DIR}/${id}.pcap"
    _pull_remote_pcap "${remote_path}" "${local_pcap}" || {
        echo "scp failed for ${remote_path}" >&2
        return 1
    }
    [ -s "${local_pcap}" ]
    tcpdump -nr "${local_pcap}" >/dev/null 2>&1
}
