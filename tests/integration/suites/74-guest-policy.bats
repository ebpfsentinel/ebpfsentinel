#!/usr/bin/env bats
# 74-guest-policy.bats - a rule names a virtual machine, and is decided on
# the guest's tap.
#
# A guest runs its own kernel, so nothing of it is in the host's process
# table or cgroup tree: what the host sees is the device its traffic
# crosses. An IDS rule scoped to a guest is therefore keyed on that device
# and decided by the classifier attached to it. The frames here are written
# into each tap the way the guest's network driver would hand them to the
# host, so the classifier sees them on the tap's ingress exactly as it sees
# a guest's own packets, and no guest needs to run.
#
# The suite asserts:
#
#   * A rule naming a Proxmox guest by name fires on that guest's tap, and
#     the same frame on another guest's tap or on an unnamed tap does not.
#   * A rule naming a libvirt guest by UUID fires on its tap.
#   * A guest whose record is written after its device is picked up once the
#     names are read again, and not before.
#   * The guest list says the guest is protected on the network only, that
#     process attribution and data loss prevention are not covered, and why.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 74 makes its guest devices beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-guest-policy-$$"
    mkdir -p "${DATA_DIR}/pve/qemu-server" "${DATA_DIR}/libvirt/qemu"
    printf '%s\n' 'name: web-01' 'net0: virtio=BC:24:11:00:00:01,bridge=vmbr0' \
        >"${DATA_DIR}/pve/qemu-server/4101.conf"
    _libvirt_status db 6f1c1a8e-0a7b-4d3c-9b8e-2f9d1e7c4a55 gvnet7 >"${DATA_DIR}/libvirt/qemu/db.xml"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    _remove_devices

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-guest-policy.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    local dev
    for dev in tap4101i0 gvnet7 gtap9 glate8; do
        ip tuntap add dev "${dev}" mode tap
        ip link set "${dev}" up
    done
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _remove_devices
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-guest-policy-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_remove_devices() {
    local dev
    for dev in tap4101i0 gvnet7 gtap9 glate8; do
        ip link del "${dev}" 2>/dev/null || true
    done
}

# _libvirt_status <name> <uuid> <device> - a libvirt status file for a
# running domain with one tap.
_libvirt_status() {
    cat <<XML
<domstatus state='running' reason='booted' pid='4242'>
  <domain type='kvm' id='3'>
    <name>$1</name>
    <uuid>$2</uuid>
    <devices>
      <interface type='network'><target dev='$3'/></interface>
    </devices>
  </domain>
</domstatus>
XML
}

# _attached <interface> - wait until the guest list reports the device with
# the chain on it.
_attached() {
    local iface="${1:?usage: _attached <interface>}" attempt=0
    while [ "${attempt}" -lt 50 ]; do
        if curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
            | jq -e --arg i "${iface}" '.guests[] | select(.interface == $i and .attached)' \
                >/dev/null; then
            return 0
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    echo "${iface} never reported attached" >&2
    return 1
}

# _send <interface> <dst_port> - write one TCP SYN into the tap, as the
# guest's driver hands its frames to the host.
_send() {
    python3 - "$1" "$2" <<'PY'
import fcntl, os, socket, struct, sys

iface, port = sys.argv[1], int(sys.argv[2])
fd = os.open("/dev/net/tun", os.O_RDWR)
IFF_TAP, IFF_NO_PI, TUNSETIFF = 0x0002, 0x1000, 0x400454CA
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", iface.encode(), IFF_TAP | IFF_NO_PI))

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF

src, dst = socket.inet_aton("10.250.0.2"), socket.inet_aton("10.250.0.1")
tcp = struct.pack("!HHIIBBHHH", 40000, port, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
eth = bytes.fromhex("feffffffffff") + bytes.fromhex("bc2411000001") + b"\x08\x00"
for _ in range(3):
    os.write(fd, eth + ip + tcp)
os.close(fd)
PY
}

_alerted() {
    wait_for_alert ".[] | select(.rule_id == \"$1\") | .rule_id" "${2:-15}" 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a rule naming a guest does not fire on another guest's tap or an unnamed one" {
    _attached tap4101i0
    _attached gtap9
    _send tap4101i0 4445
    _send gtap9 4445
    _send gtap9 4444
    run _alerted ids-guest-db 5
    [ "$status" -ne 0 ]
    run _alerted ids-guest-web 3
    [ "$status" -ne 0 ]
}

@test "a rule naming a Proxmox guest by name fires on its tap" {
    _attached tap4101i0
    _send tap4101i0 4444
    run _alerted ids-guest-web
    echo "alert: ${output}" >&2
    [ "$status" -eq 0 ]
}

@test "a rule naming a libvirt guest by UUID fires on its tap" {
    _attached gvnet7
    _send gvnet7 4445
    run _alerted ids-guest-db
    echo "alert: ${output}" >&2
    [ "$status" -eq 0 ]
}

@test "a guest whose record is written after its device is covered once named" {
    _attached glate8
    _send glate8 4446
    run _alerted ids-guest-late 5
    [ "$status" -ne 0 ]

    _libvirt_status late 0b9f4e2a-5c61-4d7e-8a3b-1c2d3e4f5a6b glate8 \
        >"${DATA_DIR}/libvirt/qemu/late.xml"
    local named="" attempt=0
    while [ "${attempt}" -lt 50 ]; do
        named="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
            | jq -r '.guests[] | select(.interface == "glate8") | .guest.name // empty')"
        [ "${named}" = "late" ] && break
        sleep 0.2
        attempt=$((attempt + 1))
    done
    [ "${named}" = "late" ]
    # The scope is written on the next refresh of the names, every five
    # seconds.
    sleep 6
    _send glate8 4446
    run _alerted ids-guest-late
    echo "alert: ${output}" >&2
    [ "$status" -eq 0 ]
}

@test "the guest list says the guest is protected on the network only, and why" {
    _attached tap4101i0
    local entry
    entry="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
        | jq -c '.guests[] | select(.interface == "tap4101i0")')"
    echo "entry: ${entry}" >&2
    [ "$(jq -c '.protection.covered' <<<"${entry}")" = '["network"]' ]
    [ "$(jq -c '.protection.not_covered' <<<"${entry}")" = '["process","dlp"]' ]
    [[ "$(jq -r '.protection.reason' <<<"${entry}")" == "network only: the guest runs its own kernel"* ]]
}
