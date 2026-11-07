#!/usr/bin/env bats
# 101-encryption-written-through-a-file-share.bats - a run encrypting a
# share from another host is named by that host's address, and the file
# service it reached is left running.
#
# The suite asserts:
#
#   * A client on another address rewriting every document of a share with
#     random bytes through Samba, and renaming each, reaches a verdict whose
#     alert says the run was written for the client at that address through
#     smbd, rather than naming smbd as the run.
#   * The stop is armed and in force, and still nothing is killed: the
#     run is stopped where it runs, on the client's host, so the client
#     finishes, every document carries its new name, and smbd and the
#     session it served are both still alive.
#
# The client is in the test namespace, which is another host as far as the
# file service and the agent can tell: it reaches smbd over the veth by its
# own address. The folding of this side and the client host's own reading
# into one incident across an estate is the enterprise correlation's, and
# is asserted there.
#
# Requires: root, python3, jq, smbd, smbclient

load '../lib/helpers'
load '../lib/ebpf_helpers'

DOCUMENTS=600
DIRECTORIES=20

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool smbd
    require_tool smbclient
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 101 serves its share from the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-share-$$"
    mkdir -p "${DATA_DIR}/share" "${DATA_DIR}/samba/private" "${DATA_DIR}/client"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    _start_smbd || { echo "smbd did not start" >&2; return 1; }

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption-stop.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_enforced || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the mass encryption verdict never reported itself in force" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _stop_smbd
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-share-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_wait_enforced() {
    local attempt=0 body
    while [ "${attempt}" -lt 30 ]; do
        body="$(api_get /api/v1/host-rules/mass-encryption 2>/dev/null)" || body=""
        [ "$(jq -r '.enabled' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.mode' <<<"${body}" 2>/dev/null)" = "enforce" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _start_smbd - a Samba of the suite's own, on the host side of the veth
# alone, serving one guest-writable share. Every directory it writes is its
# own: the distribution's service is disabled on the VM, so /run/samba is
# never created and smbd refuses to start on the default.
_start_smbd() {
    local samba="${DATA_DIR}/samba"
    cat >"${samba}/smb.conf" <<EOF
[global]
  server role = standalone server
  interfaces = ${EBPF_HOST_IP}
  bind interfaces only = yes
  smb ports = 445
  disable netbios = yes
  map to guest = Bad User
  guest account = nobody
  pid directory = ${samba}
  lock directory = ${samba}
  state directory = ${samba}
  cache directory = ${samba}
  private dir = ${samba}/private
  ncalrpc dir = ${samba}/ncalrpc
  log file = ${samba}/log.smbd
  server min protocol = SMB3
[share]
  path = ${DATA_DIR}/share
  guest ok = yes
  read only = no
EOF
    smbd -D -s "${samba}/smb.conf" || return 1
    local attempt=0
    while [ "${attempt}" -lt 40 ]; do
        ss -ltn | grep -q "${EBPF_HOST_IP}:445 " && return 0
        sleep 0.25
        attempt=$((attempt + 1))
    done
    return 1
}

_stop_smbd() {
    local pidfile pid
    for pidfile in "${DATA_DIR:-/nonexistent}"/samba/*.pid; do
        [ -f "${pidfile}" ] || continue
        pid="$(cat "${pidfile}")"
        kill "${pid}" 2>/dev/null || true
    done
    pkill -f "smbd -D -s ${DATA_DIR:-/nonexistent}/samba/smb.conf" 2>/dev/null || true
}

_smbd_master() {
    pgrep -o -f "smbd -D -s ${DATA_DIR}/samba/smb.conf"
}

# _tree <dir> - documents carrying the heads their names promise.
_tree() {
    python3 - "$1" "${DOCUMENTS}" "${DIRECTORIES}" <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = ("ledger line with ordinary words in it\n" * 400).encode()
for d in range(directories):
    os.makedirs(f"{root}/d{d}", exist_ok=True)
for n in range(documents):
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + text)
PY
    chmod -R a+rwX "$1"
}

# _commands <payload> - the client's session: every document overwritten
# with the payload, then renamed.
_commands() {
    local n d
    echo "prompt"
    for n in $(seq 0 $((DOCUMENTS - 1))); do
        d=$((n % DIRECTORIES))
        echo "put $1 d${d}/report${n}.pdf"
        echo "rename d${d}/report${n}.pdf d${d}/report${n}.pdf.lockd"
    done
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a client encrypting a share is named by its address, and the run is not stopped here" {
    _tree "${DATA_DIR}/share"
    head -c 15000 /dev/urandom >"${DATA_DIR}/client/payload"
    sleep 5
    local master
    master="$(_smbd_master)"
    [ -n "${master}" ]

    _commands "${DATA_DIR}/client/payload" >"${DATA_DIR}/client/session"
    run ip netns exec "${EBPF_TEST_NS}" smbclient "//${EBPF_HOST_IP}/share" -N -m SMB3 \
        <"${DATA_DIR}/client/session"
    [ "$status" -eq 0 ]

    local alert
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"mass-encryption\" and (.message | contains(\"${DATA_DIR}/share/\")))] | first" 30 1)"
    [ -n "${alert}" ]
    jq -e --arg peer "${EBPF_NS_IP}" \
        '.message | startswith("mass encryption written for the client at " + $peer + " through /usr/sbin/smbd (pid ")' <<<"${alert}"

    # Not stopped here: the session ran to its end and the service lives.
    [ "$(find "${DATA_DIR}/share" -name '*.pdf.lockd' | wc -l)" -eq "${DOCUMENTS}" ]
    kill -0 "${master}"
    run wait_for_alert '.[] | select(.rule_id == "mass-encryption" and .mitigation_status != null)' 3 1
    [ "$status" -ne 0 ]
}

@test "the share still answers the same client once the verdict is reached" {
    run ip netns exec "${EBPF_TEST_NS}" smbclient "//${EBPF_HOST_IP}/share" -N -m SMB3 -c "cd d0; ls"
    [ "$status" -eq 0 ]
    grep -q "report0.pdf.lockd" <<<"${output}"
}
