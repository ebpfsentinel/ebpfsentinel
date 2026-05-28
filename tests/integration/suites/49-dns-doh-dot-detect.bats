#!/usr/bin/env bats
# 49-dns-doh-dot-detect.bats — DoH/DoT detection across the 3-VM transit.
#
# Drives TLS handshakes from the attacker VM to the backend VM through
# the agent's transit datapath and asserts:
#
#   * a ClientHello whose SNI matches a built-in DoH resolver surfaces
#     an EncryptedDns alert with protocol=doh
#   * a ClientHello whose SNI matches the custom dns.doh_resolvers
#     entry surfaces an EncryptedDns alert with protocol=doh and the
#     resolver field reflects the configured domain
#   * a TLS handshake on port 853 (any SNI) surfaces an alert with
#     protocol=dot
#   * plain UDP/53 traffic does NOT raise a DoH/DoT alert (false-
#     positive guard for the encrypted-DNS detector)
#
# Requires: 3-VM mode, kernel >= 6.9, openssl on attacker, nginx :443
# and openssl s_server :853 on backend (dot-backend.service shipped by
# the backend provisioner).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/dns_encrypted_helpers'

setup_file() {
    skip_if_not_3vm
    require_kernel 6 9
    require_tool curl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dnsenc-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dns-encrypted.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }

    route_via_agent backend >/dev/null 2>&1 || true
    start_backend_service nginx 443 || true
    # dot-backend.service is the openssl s_server on :853 shipped by the
    # backend provisioner. Best-effort start; the DoT-by-port test skips
    # itself if the listener never opens.
    _backend_ssh_sudo systemctl start dot-backend.service 2>/dev/null || true
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dnsenc-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── DoH-by-SNI (built-in resolver list) ──────────────────────────────

@test "DoH detected by ClientHello SNI on built-in resolver list" {
    skip_if_not_3vm

    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 443 "cloudflare-dns.com"
    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 443 "cloudflare-dns.com"

    local count
    count="$(wait_for_encrypted_dns_alert doh 20 1)" || {
        echo "no DoH alert observed after 20s; count=${count}" >&2
        return 1
    }
    [ "${count:-0}" -gt 0 ]
}

# ── DoH-by-SNI (custom dns.doh_resolvers) ────────────────────────────

@test "DoH detected by ClientHello SNI on custom dns.doh_resolvers" {
    skip_if_not_3vm

    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 443 "corp-doh.test"
    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 443 "corp-doh.test"

    local matched
    matched="$(encrypted_dns_resolver_match "corp-doh.test")"
    if [ "${matched:-0}" -eq 0 ]; then
        # Allow up to 20s for the alert to surface.
        local i=0
        while [ "$i" -lt 20 ]; do
            matched="$(encrypted_dns_resolver_match "corp-doh.test")"
            [ "${matched:-0}" -gt 0 ] && break
            sleep 1
            i=$((i + 1))
        done
    fi
    [ "${matched:-0}" -gt 0 ] || {
        echo "no DoH alert for custom resolver corp-doh.test" >&2
        return 1
    }
}

# ── DoT-by-port (TLS on :853) ────────────────────────────────────────

@test "DoT detected by TLS handshake on dst_port 853" {
    skip_if_not_3vm

    # Verify the backend's DoT listener is reachable; if dot-backend.service
    # didn't come up (older provisioner, missing systemd unit) the
    # agent still has nothing to observe — skip rather than fail.
    if ! _attacker_ssh \
            "nc -z -w2 ${BACKEND_VM_IP:-192.168.57.30} 853"; then
        skip "backend DoT listener (:853) unreachable; dot-backend.service not running"
    fi

    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 853 "dot-probe.test"
    tls_probe_sni "${BACKEND_VM_IP:-192.168.57.30}" 853 "dot-probe.test"

    local count
    count="$(wait_for_encrypted_dns_alert dot 20 1)" || {
        echo "no DoT alert observed after 20s; count=${count}" >&2
        return 1
    }
    [ "${count:-0}" -gt 0 ]
}

# ── Plain DNS no false-positive ─────────────────────────────────────

@test "plain DNS UDP/53 does not raise an EncryptedDns alert" {
    skip_if_not_3vm

    local doh_before dot_before doh_after dot_after
    doh_before="$(encrypted_dns_alerts doh)"
    dot_before="$(encrypted_dns_alerts dot)"

    # Send a handful of UDP/53 packets through the agent transit. The
    # backend has no resolver bound on :53 so each query yields ICMP
    # port-unreach, but the packet still crosses the agent — which is
    # what we want to assert against.
    _attacker_ssh \
        "for i in 1 2 3; do (echo 'q'; sleep 0.2) | nc -u -w1 ${BACKEND_VM_IP:-192.168.57.30} 53 >/dev/null 2>&1 || true; done"
    sleep 3

    doh_after="$(encrypted_dns_alerts doh)"
    dot_after="$(encrypted_dns_alerts dot)"

    [ "${doh_after:-0}" -eq "${doh_before:-0}" ] || {
        echo "DoH alerts grew on plain UDP/53 (${doh_before} -> ${doh_after})" >&2
        return 1
    }
    [ "${dot_after:-0}" -eq "${dot_before:-0}" ] || {
        echo "DoT alerts grew on plain UDP/53 (${dot_before} -> ${dot_after})" >&2
        return 1
    }
}
