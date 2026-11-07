#!/usr/bin/env bats
# 108-encryption-from-another-machine.bats - a second machine encrypting a
# share the agent's host serves is named by that machine's address, and the
# file service is left running.
#
# The suite asserts:
#
#   * A client on another machine rewriting every document of a share with
#     random bytes through Samba, and renaming each, reaches a verdict on the
#     file server whose alert says the run was written for the client at that
#     machine's address through smbd, rather than naming smbd as the run.
#   * The stop is armed and in force, and still nothing is killed on the file
#     server: the run is stopped where it runs, on the client's machine, so
#     the client finishes, every document carries its new name, and smbd is
#     still alive and still serves the share.
#
# Two machines: bats and smbclient run on the attacker VM, Samba and the agent
# on the agent VM, and the session crosses the private network between them.
# The folding of this reading and the client machine's own into one incident
# across an estate is the enterprise correlation's, and is asserted there.
#
# Requires: jq, python3, smbclient here; smbd and ssh to the agent VM (the
# 2VM lane).

load '../lib/helpers'
load '../lib/ebpf_helpers'

DOCUMENTS=600
DIRECTORIES=20
# Same path on the agent VM. Under /var/tmp because /tmp can be a tmpfs and
# the watch marks the filesystem holding this directory, and named so the
# lane's rewrite of /tmp/ebpfsentinel-test-data* paths leaves it alone.
SHARE_ROOT="/var/tmp/ebpfsentinel-share-across"

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool smbclient

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 108 needs the client on a second machine (2VM lane only)"
    fi
    _agent_ssh test -x /usr/sbin/smbd || env_skip "smbd not installed on the agent VM"

    export CLIENT_IP="${ATTACKER_VM_IP:-192.168.56.20}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-across-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    _stop_smbd

    _agent_ssh_sudo rm -rf "${SHARE_ROOT}"
    _agent_ssh_sudo mkdir -p "${SHARE_ROOT}/share" "${SHARE_ROOT}/samba/private"
    # Files are copied into a directory of the suite's own: the copy hands
    # the directory it lands in to the login user.
    _write_tree >"${DATA_DIR}/tree.py"
    _agent_scp "${DATA_DIR}/tree.py" "${SHARE_ROOT}/stage/tree.py" || return 1
    _start_smbd || { echo "smbd did not start on the agent VM" >&2; return 1; }

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption-stop.yaml")"
    export PREPARED_CONFIG
    # The watch and the audit store go under the share's root rather than the
    # lane's data directory, which may sit on a tmpfs.
    sed -i -e "s|/tmp/ebpfsentinel-test-data|${SHARE_ROOT}|g" "${PREPARED_CONFIG}"
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
    _agent_ssh_sudo rm -rf "${SHARE_ROOT}" 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-across-$$}"
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

# _start_smbd - a Samba of the suite's own on the agent VM, bound to its
# private address alone, serving one guest-writable share. Every directory it
# writes is its own: the distribution's service is disabled on the VM, so
# /run/samba is never created and smbd refuses to start on the default.
_start_smbd() {
    local samba="${SHARE_ROOT}/samba"
    cat >"${DATA_DIR}/smb.conf" <<EOF
[global]
  server role = standalone server
  interfaces = ${AGENT_VM_IP}
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
  path = ${SHARE_ROOT}/share
  guest ok = yes
  read only = no
EOF
    _agent_scp "${DATA_DIR}/smb.conf" "${SHARE_ROOT}/stage/smb.conf" || return 1
    _agent_ssh_sudo install -m 0644 -o root -g root "${SHARE_ROOT}/stage/smb.conf" "${samba}/smb.conf" || return 1
    _agent_ssh_sudo smbd -D -s "${samba}/smb.conf" || return 1
    local attempt=0
    while [ "${attempt}" -lt 40 ]; do
        _agent_ssh ss -ltn 2>/dev/null | grep -q "${AGENT_VM_IP}:445 " && return 0
        sleep 0.25
        attempt=$((attempt + 1))
    done
    return 1
}

# _stop_smbd - by its pid files; a pattern match would also hit the remote
# shell carrying it.
_stop_smbd() {
    _agent_ssh_sudo bash -c "'for f in ${SHARE_ROOT}/samba/*.pid; do \
        [ -f \"\$f\" ] && kill \"\$(cat \"\$f\")\" 2>/dev/null; done; true'" 2>/dev/null || true
}

_smbd_master() {
    _agent_ssh_sudo bash -c "'cat ${SHARE_ROOT}/samba/*.pid 2>/dev/null | head -1'"
}

# _write_tree - documents carrying the heads their names promise.
_write_tree() {
    cat <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = ("ledger line with ordinary words in it\n" * 400).encode()
for d in range(directories):
    os.makedirs(f"{root}/d{d}", exist_ok=True)
for n in range(documents):
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + text)
PY
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

@test "a machine encrypting a share is named by its address, and the run is not stopped on the server" {
    _agent_ssh_sudo python3 "${SHARE_ROOT}/stage/tree.py" "${SHARE_ROOT}/share" \
        "${DOCUMENTS}" "${DIRECTORIES}"
    _agent_ssh_sudo chmod -R a+rwX "${SHARE_ROOT}/share"
    head -c 15000 /dev/urandom >"${DATA_DIR}/payload"
    sleep 5
    local master
    master="$(_smbd_master)"
    [ -n "${master}" ]

    _commands "${DATA_DIR}/payload" >"${DATA_DIR}/session"
    run smbclient "//${AGENT_VM_IP}/share" -N -m SMB3 <"${DATA_DIR}/session"
    [ "$status" -eq 0 ]

    local alert
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"mass-encryption\" and (.message | contains(\"${SHARE_ROOT}/share/\")))] | first" 30 1)"
    [ -n "${alert}" ]
    jq -e --arg peer "${CLIENT_IP}" \
        '.message | startswith("mass encryption written for the client at " + $peer + " through /usr/sbin/smbd (pid ")' <<<"${alert}"

    # Not stopped on the server: the session ran to its end and the service lives.
    [ "$(_agent_ssh "find ${SHARE_ROOT}/share -name '*.pdf.lockd'" | wc -l)" -eq "${DOCUMENTS}" ]
    _agent_ssh_sudo kill -0 "${master}"
    run wait_for_alert '.[] | select(.rule_id == "mass-encryption" and .mitigation_status != null)' 3 1
    [ "$status" -ne 0 ]
}

@test "the share still answers the same machine once the verdict is reached" {
    run smbclient "//${AGENT_VM_IP}/share" -N -m SMB3 -c "cd d0; ls"
    [ "$status" -eq 0 ]
    grep -q "report0.pdf.lockd" <<<"${output}"
}
