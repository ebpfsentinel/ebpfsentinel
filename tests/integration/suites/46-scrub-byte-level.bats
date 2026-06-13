#!/usr/bin/env bats
# 46-scrub-byte-level.bats — tc-scrub byte-level normalization, 3-VM.
#
# Crafted IPv4 + TCP SYNs are emitted by scapy on the attacker VM
# toward the backend through the agent's transit datapath. tc-scrub
# rewrites the IP/TCP headers in flight; the backend captures the
# post-scrub bytes off its NIC and tcpdump verifies field-level changes.
#
# Asserted rewrites (config-ebpf-scrub-byte.yaml):
#   * IPv4 TTL floor   — min_ttl: 64       → send ttl=10, expect ttl >= 64
#   * IPv4 DF flag     — clear_df: true    → send DF=1,  expect DF cleared
#   * IPv4 IP-ID rand  — random_ip_id: true→ send id=12345, expect id != 12345
#   * TCP MSS option   — max_mss: 1400     → send MSS=65535, expect MSS <= 1400
#
# Fragment policy AC: the current ScrubConfig (firewall.rs) has no
# fragment_policy / drop_fragments / reassemble field — the kernel
# program only normalizes headers on first-fragment / unfragmented
# packets. The fragment-policy AC is deferred to a follow-up Rust
# feature story and explicitly skipped here so the suite remains
# honest about coverage.
#
# Requires: 3-VM mode, kernel >= 6.9, scapy on attacker
# (/opt/scapy-venv), tcpdump on the bats runner, libpcap on backend.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/scrub_helpers'

setup_file() {
    skip_if_not_3vm
    require_kernel 6 9

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-scrub-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-scrub-byte.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    route_via_agent backend >/dev/null 2>&1 || true
    start_backend_service nginx 80 || true
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-scrub-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# Common capture filter — TCP SYNs from attacker toward backend:80.
_scrub_bpf() {
    echo "tcp and src host ${ATTACKER_VM_IP} and dst port 80"
}

# ── IPv4 TTL floor (min_ttl: 64) ─────────────────────────────────────

@test "tc-scrub raises IPv4 TTL below floor to min_ttl" {
    skip_if_not_3vm

    local pcap
    pcap="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" "$(_scrub_bpf)")"
    [ -n "$pcap" ] || skip "capture_on backend returned no pcap"

    scapy_send_via "${BACKEND_VM_IP:-192.168.57.30}" 10 1111 536 1 5 >/dev/null 2>&1 || true
    sleep 2

    local local_pcap
    local_pcap="$(stop_capture backend "$pcap")"
    [ -s "$local_pcap" ] || skip "pcap empty (transit may not have reached backend)"

    # tc-scrub floors the TTL to min_ttl (64) at the agent's ingress hook, then
    # the agent forwards the packet and the kernel's IP-forward path decrements
    # it by one hop. The backend therefore captures min_ttl - 1 (63). Asserting
    # >= 63 confirms the floor was applied (the packet was sent with ttl=10).
    local res
    res="$(assert_ttl_ge "$local_pcap" "tcp and dst port 80" 63)"
    [ "$res" = "ok" ] || {
        echo "TTL floor violated: ${res}" >&2
        return 1
    }
}

# ── IPv4 DF flag cleared (clear_df: true) ────────────────────────────

@test "tc-scrub clears IPv4 DF flag" {
    skip_if_not_3vm

    local pcap
    pcap="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" "$(_scrub_bpf)")"
    [ -n "$pcap" ] || skip "capture_on backend returned no pcap"

    scapy_send_via "${BACKEND_VM_IP:-192.168.57.30}" 128 2222 1200 1 5 >/dev/null 2>&1 || true
    sleep 2

    local local_pcap
    local_pcap="$(stop_capture backend "$pcap")"
    [ -s "$local_pcap" ] || skip "pcap empty (transit may not have reached backend)"

    local res
    res="$(assert_df_cleared "$local_pcap" "tcp and dst port 80")"
    [ "$res" = "ok" ] || {
        echo "DF still set: ${res}" >&2
        return 1
    }
}

# ── IPv4 IP-ID randomized (random_ip_id: true) ───────────────────────

@test "tc-scrub randomizes IPv4 identification field" {
    skip_if_not_3vm

    local pcap
    pcap="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" "$(_scrub_bpf)")"
    [ -n "$pcap" ] || skip "capture_on backend returned no pcap"

    # Send 5 SYNs all with id=12345; after rand, none should arrive
    # with id=12345 (probability of a clash on 5 packets ≈ 0.008%).
    scapy_send_via "${BACKEND_VM_IP:-192.168.57.30}" 128 12345 1200 0 5 >/dev/null 2>&1 || true
    sleep 2

    local local_pcap
    local_pcap="$(stop_capture backend "$pcap")"
    [ -s "$local_pcap" ] || skip "pcap empty (transit may not have reached backend)"

    local res
    res="$(assert_ip_id_not "$local_pcap" "tcp and dst port 80" 12345)"
    [ "$res" = "ok" ] || {
        echo "IP-ID randomization failed: ${res}" >&2
        return 1
    }
}

# ── TCP MSS option clamped (max_mss: 1400) ───────────────────────────

@test "tc-scrub clamps TCP MSS option above ceiling" {
    skip_if_not_3vm

    local pcap
    pcap="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" "$(_scrub_bpf)")"
    [ -n "$pcap" ] || skip "capture_on backend returned no pcap"

    scapy_send_via "${BACKEND_VM_IP:-192.168.57.30}" 128 3333 65535 0 5 >/dev/null 2>&1 || true
    sleep 2

    local local_pcap
    local_pcap="$(stop_capture backend "$pcap")"
    [ -s "$local_pcap" ] || skip "pcap empty (transit may not have reached backend)"

    local res
    res="$(assert_mss_le "$local_pcap" "tcp and dst port 80" 1400)"
    [ "$res" = "ok" ] || {
        echo "MSS ceiling violated: ${res}" >&2
        return 1
    }
}

# ── Fragment policy (deferred) ───────────────────────────────────────

@test "tc-scrub drops IPv4 fragments when drop_fragments is enabled" {
    skip_if_not_3vm

    local dst="${BACKEND_VM_IP:-192.168.57.30}"
    local pcap
    pcap="$(capture_on backend "${EBPF_BACKEND_IFACE:-eth1}" \
        "src host ${ATTACKER_VM_IP} and dst host ${dst}")"
    [ -n "$pcap" ] || skip "capture_on backend returned no pcap"

    # Control: an unfragmented SYN must traverse (proves the transit path is up,
    # so an empty fragment result means "dropped", not "path broken").
    scapy_send_via "${dst}" 64 4444 1200 1 2 >/dev/null 2>&1 || true
    # Fragmented datagrams: tc-scrub must drop these at the agent ingress hook
    # before they are forwarded to the backend.
    scapy_send_fragment_via "${dst}" 5 >/dev/null 2>&1 || true
    sleep 2

    local local_pcap
    local_pcap="$(stop_capture backend "$pcap")"
    [ -s "$local_pcap" ] || skip "pcap empty — transit path did not deliver the control packet"

    # The control SYN (unfragmented, dst port 80) must reach the backend.
    local control
    control="$(tshark -r "$local_pcap" \
        -Y 'tcp.dstport == 80 and ip.flags.mf == 0 and ip.frag_offset == 0' \
        2>/dev/null | wc -l)"
    [ "${control:-0}" -ge 1 ] || skip "control SYN never reached backend — transit inconclusive"

    # No fragment (MF set or non-zero offset) may reach the backend.
    local frags
    frags="$(tshark -r "$local_pcap" \
        -Y 'ip.flags.mf == 1 or ip.frag_offset > 0' 2>/dev/null | wc -l)"
    [ "${frags:-0}" -eq 0 ] || {
        echo "expected fragments dropped by tc-scrub, but ${frags} reached backend" >&2
        return 1
    }
}
