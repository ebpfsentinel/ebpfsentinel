#!/usr/bin/env bats
# 75-libvirt-guest.bats - a real libvirt guest, named by libvirt, denied on
# its tap.
#
# Suite 74 writes frames into taps it made itself, beside status files it
# wrote itself. This one leaves both to the hypervisor: libvirtd creates the
# network, the taps and its own status files, and QEMU runs two guests that
# boot from the network, so their firmware sends DHCP requests the moment it
# starts. No disk image is needed and no guest operating system runs.
#
# The suite asserts:
#
#   * Both guests are listed under the names libvirt gives them, from the
#     status files libvirtd wrote, with the chain on each tap.
#   * The guest the blocking rule names never gets a lease: its requests are
#     dropped on its tap and the drop is alerted under the rule.
#   * The guest the rule does not name, on the same network and the same
#     bridge, gets its lease, so the drop is the guest's and not the network's.

load '../lib/helpers'
load '../lib/ebpf_helpers'

NET_NAME="es-guests"
GUEST_A="es-pxe-a"
GUEST_B="es-pxe-b"
MAC_A="52:54:00:e5:00:0a"
MAC_B="52:54:00:e5:00:0b"
TAP_A="espxea"
TAP_B="espxeb"

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 75 runs its guests beside the agent (local lane only)"
    fi
    if ! command -v virsh &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
        env_skip "libvirt and QEMU not installed (run the libvirt provisioner)"
    fi
    if ! virsh -c qemu:///system version &>/dev/null; then
        env_skip "libvirtd not reachable on qemu:///system"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-libvirt-guest-$$"
    mkdir -p "${DATA_DIR}"
    _remove_guests

    _network_xml >"${DATA_DIR}/net.xml"
    virsh -c qemu:///system net-create "${DATA_DIR}/net.xml" >/dev/null

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-libvirt-guest.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    # The guests start paused: libvirt has made the taps and written its
    # status files, and no firmware has run yet, so no request leaves before
    # the rule's scope is written.
    _domain_xml "${GUEST_A}" "${MAC_A}" "${TAP_A}" >"${DATA_DIR}/a.xml"
    _domain_xml "${GUEST_B}" "${MAC_B}" "${TAP_B}" >"${DATA_DIR}/b.xml"
    virsh -c qemu:///system create --paused "${DATA_DIR}/a.xml" >/dev/null
    virsh -c qemu:///system create --paused "${DATA_DIR}/b.xml" >/dev/null

    _named "${TAP_A}" "${GUEST_A}"
    _named "${TAP_B}" "${GUEST_B}"
    # The scope is written on the next refresh of the names, every five
    # seconds.
    sleep 6
    virsh -c qemu:///system resume "${GUEST_A}" >/dev/null
    virsh -c qemu:///system resume "${GUEST_B}" >/dev/null
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _remove_guests
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-libvirt-guest-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_remove_guests() {
    virsh -c qemu:///system destroy "${GUEST_A}" &>/dev/null || true
    virsh -c qemu:///system destroy "${GUEST_B}" &>/dev/null || true
    virsh -c qemu:///system net-destroy "${NET_NAME}" &>/dev/null || true
}

# An isolated network of its own, so the suite never claims the subnet of
# libvirt's default network or of the lab.
_network_xml() {
    cat <<XML
<network>
  <name>${NET_NAME}</name>
  <bridge name="esbr0"/>
  <ip address="10.231.0.1" netmask="255.255.255.0">
    <dhcp><range start="10.231.0.100" end="10.231.0.200"/></dhcp>
  </ip>
</network>
XML
}

# _domain_xml <name> <mac> <tap> - a guest with no disk that boots from the
# network through QEMU's iPXE ROM, under TCG since the lab has no KVM.
_domain_xml() {
    cat <<XML
<domain type="qemu">
  <name>$1</name>
  <memory unit="MiB">96</memory>
  <vcpu>1</vcpu>
  <os><type arch="x86_64" machine="pc">hvm</type><boot dev="network"/></os>
  <devices>
    <interface type="network">
      <source network="${NET_NAME}"/>
      <mac address="$2"/>
      <target dev="$3"/>
      <model type="e1000"/>
    </interface>
  </devices>
</domain>
XML
}

_guest_entry() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/ebpf/guests" \
        | jq -c --arg i "$1" '.guests[] | select(.interface == $i)'
}

# _named <tap> <guest> - wait until the guest list names the tap's guest
# with the chain on it.
_named() {
    local attempt=0
    while [ "${attempt}" -lt 100 ]; do
        if _guest_entry "$1" | jq -e --arg g "$2" \
            'select(.attached and .guest.name == $g and .guest.source == "libvirt")' \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    echo "$1 never named $2 with the chain attached: $(_guest_entry "$1")" >&2
    return 1
}

_leased() {
    virsh -c qemu:///system net-dhcp-leases "${NET_NAME}" --mac "$1" 2>/dev/null \
        | grep -q "$1"
}

# _wait_lease <mac> <seconds>
_wait_lease() {
    local deadline=$((SECONDS + $2))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        _leased "$1" && return 0
        sleep 1
    done
    return 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "both guests are named from the status files libvirtd wrote" {
    local a b
    a="$(_guest_entry "${TAP_A}")"
    b="$(_guest_entry "${TAP_B}")"
    echo "a: ${a}" >&2
    echo "b: ${b}" >&2
    [ "$(jq -r '.kind' <<<"${a}")" = "tap" ]
    [ "$(jq -r '.guest.name' <<<"${a}")" = "${GUEST_A}" ]
    [ "$(jq -r '.guest.name' <<<"${b}")" = "${GUEST_B}" ]
    [ -n "$(jq -r '.guest.id' <<<"${a}")" ]
    [ "$(jq -r '.guest.id' <<<"${a}")" != "$(jq -r '.guest.id' <<<"${b}")" ]
}

@test "the guest the rule does not name gets its lease on the same network" {
    run _wait_lease "${MAC_B}" 120
    [ "$status" -eq 0 ]
}

@test "the guest the rule names is denied on its tap, and the drop is alerted" {
    run wait_for_alert '.[] | select(.rule_id == "ids-guest-dhcp-deny") | .rule_id' 60 1
    echo "alert: ${output}" >&2
    [ "$status" -eq 0 ]
    # The other guest leased long ago on the same bridge, so a request of
    # this one reaching dnsmasq would have had its answer by now.
    _wait_lease "${MAC_B}" 120
    sleep 10
    run _leased "${MAC_A}"
    [ "$status" -ne 0 ]
}
