#!/usr/bin/env bats
# 73-hypervisor-guests.bats - a tap device is a guest, and the guest has a
# name.
#
# A virtual machine's traffic crosses the host on its tap or macvtap device,
# so the agent attaches there and names the guest from the record its
# hypervisor keeps. The devices here are made with `ip`, the way a
# hypervisor makes them, and the records are written in Proxmox's and
# libvirt's own layouts under the data directory: what is under test is the
# device kind the kernel reports and the record that names it, and no
# guest needs to run for either.
#
# The suite asserts:
#
#   * A tap named the Proxmox way is attached and named from the VM's
#     configuration, snapshot sections ignored, with its tags.
#   * A tap and a macvtap listed in a libvirt status file are named from the
#     domain, with its UUID.
#   * A tap no record names is listed unnamed, with the reason, never with
#     a placeholder name.
#   * A tun device, which carries IP packets for a VPN rather than a guest's
#     frames, is not listed.
#   * A device that goes away leaves the list.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 73 makes its guest devices beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-guests-$$"
    mkdir -p "${DATA_DIR}/pve/qemu-server" "${DATA_DIR}/libvirt/qemu"
    printf '%s\n' 'boot: order=scsi0' 'name: web-01' \
        'net0: virtio=BC:24:11:00:00:01,bridge=vmbr0' 'tags: prod;eu-west' \
        '' '[before-upgrade]' 'name: web-old' >"${DATA_DIR}/pve/qemu-server/4101.conf"
    cat >"${DATA_DIR}/libvirt/qemu/db.xml" <<'XML'
<domstatus state='running' reason='booted' pid='4242'>
  <monitor path='/var/lib/libvirt/qemu/domain-3-db/monitor.sock' type='unix'/>
  <domain type='kvm' id='3'>
    <name>db</name>
    <uuid>6f1c1a8e-0a7b-4d3c-9b8e-2f9d1e7c4a55</uuid>
    <devices>
      <disk type='file' device='disk'><target dev='vda' bus='virtio'/></disk>
      <interface type='network'><target dev='gvnet7'/></interface>
      <interface type='direct'><target dev='gmacvtap7'/></interface>
    </devices>
  </domain>
</domstatus>
XML

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    _remove_devices
    ip link add gdummy7 type dummy
    ip link set gdummy7 up

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-guests.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    ip tuntap add dev tap4101i0 mode tap
    ip tuntap add dev gvnet7 mode tap
    ip tuntap add dev gtap9 mode tap
    ip tuntap add dev gtun9 mode tun
    ip link add link gdummy7 name gmacvtap7 type macvtap mode bridge
    local dev
    for dev in tap4101i0 gvnet7 gtap9 gtun9 gmacvtap7; do
        ip link set "${dev}" up
    done
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _remove_devices
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-guests-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_remove_devices() {
    local dev
    for dev in gmacvtap7 tap4101i0 gvnet7 gtap9 gtun9 gdummy7; do
        ip link del "${dev}" 2>/dev/null || true
    done
}

# _guest <interface> - the entry for one device, waiting for the link
# watcher to report it.
_guest() {
    local iface="${1:?usage: _guest <interface>}"
    local entry="" attempt=0
    while [ "${attempt}" -lt 50 ]; do
        entry="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
            | jq -c --arg i "${iface}" '.guests[] | select(.interface == $i)')"
        [ -n "${entry}" ] && break
        sleep 0.2
        attempt=$((attempt + 1))
    done
    echo "${entry}"
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a Proxmox tap is attached and named from the VM's configuration" {
    local entry
    entry="$(_guest tap4101i0)"
    echo "entry: ${entry}" >&2
    [ "$(jq -r '.kind' <<<"${entry}")" = "tap" ]
    [ "$(jq -r '.attached' <<<"${entry}")" = "true" ]
    [ "$(jq -r '.guest.source' <<<"${entry}")" = "proxmox" ]
    [ "$(jq -r '.guest.name' <<<"${entry}")" = "web-01" ]
    [ "$(jq -r '.guest.id' <<<"${entry}")" = "4101" ]
    [ "$(jq -c '.guest.tags' <<<"${entry}")" = '["prod","eu-west"]' ]
}

@test "a libvirt tap and macvtap are named from the domain's status file" {
    local entry
    entry="$(_guest gvnet7)"
    echo "tap: ${entry}" >&2
    [ "$(jq -r '.kind' <<<"${entry}")" = "tap" ]
    [ "$(jq -r '.guest.source' <<<"${entry}")" = "libvirt" ]
    [ "$(jq -r '.guest.name' <<<"${entry}")" = "db" ]
    [ "$(jq -r '.guest.id' <<<"${entry}")" = "6f1c1a8e-0a7b-4d3c-9b8e-2f9d1e7c4a55" ]

    entry="$(_guest gmacvtap7)"
    echo "macvtap: ${entry}" >&2
    [ "$(jq -r '.kind' <<<"${entry}")" = "macvtap" ]
    [ "$(jq -r '.guest.name' <<<"${entry}")" = "db" ]
}

@test "a tap no record names is listed unnamed with the reason" {
    local entry
    entry="$(_guest gtap9)"
    echo "entry: ${entry}" >&2
    [ "$(jq -r '.kind' <<<"${entry}")" = "tap" ]
    [ "$(jq -r '.guest // "absent"' <<<"${entry}")" = "absent" ]
    [ "$(jq -r '.unnamed' <<<"${entry}")" = "no_record" ]
    [ -n "$(jq -r '.reason' <<<"${entry}")" ]
}

@test "a tun device is not a guest" {
    [ -n "$(_guest gtap9)" ]
    run bash -c "curl -sf --max-time ${HTTP_TIMEOUT} ${BASE_URL}/api/v1/ebpf/guests \
        | jq -r '.guests[].interface'"
    [ "$status" -eq 0 ]
    [[ "$output" != *"gtun9"* ]]
}

@test "a device that goes away leaves the list" {
    [ -n "$(_guest gtap9)" ]
    ip link del gtap9
    local listed="gtap9" attempt=0
    while [ "${attempt}" -lt 50 ]; do
        listed="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
            | jq -r '.guests[].interface' | grep -x gtap9 || true)"
        [ -z "${listed}" ] && break
        sleep 0.2
        attempt=$((attempt + 1))
    done
    [ -z "${listed}" ]
}
