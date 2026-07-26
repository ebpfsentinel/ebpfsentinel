#!/usr/bin/env bash
# dns_encrypted_helpers.bash — DoH/DoT probe + alert filter helpers.
#
# The agent's encrypted-DNS detector consumes TLS ClientHello SNI plus
# destination port. We don't need a real DoH proxy to drive detection —
# any TLS handshake whose SNI matches the built-in / configured resolver
# list (or whose dst_port is 853) is enough. These helpers drive that
# handshake from the attacker VM and filter the alerts surface for the
# resulting EncryptedDns event.

# _attacker_ssh <cmd...>
# Same wrapper as ct_helpers; redefined here so the file is sourceable
# stand-alone.
if ! declare -F _attacker_ssh >/dev/null 2>&1; then
    _attacker_ssh() {
        ssh -i "${AGENT_SSH_KEY%agent_key}attacker_key" \
            -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "vagrant@${ATTACKER_VM_IP}" -- "$@"
    }
fi

# tls_probe_sni <host_ip> <port> <sni>
#
# Drive a TLS ClientHello with the named SNI from the attacker VM
# towards host_ip:port via openssl s_client. The handshake may fail
# (cert mismatch, peer drops) — the agent only needs to observe the
# ClientHello bytes on transit. Returns 0 once openssl exits.
tls_probe_sni() {
    local host="${1:?usage: tls_probe_sni <host_ip> <port> <sni>}"
    local port="${2:?usage: tls_probe_sni <host_ip> <port> <sni>}"
    local sni="${3:?usage: tls_probe_sni <host_ip> <port> <sni>}"
    # Pass the whole remote command as a SINGLE string. _attacker_ssh is
    # exec-style (ssh ... -- "$@"), so ssh re-joins argv with spaces and the
    # remote login shell parses the result; an extra `sh -c` wrapper would be
    # re-split and mangle multi-token / multi-statement scripts.
    _attacker_ssh \
        "echo Q | openssl s_client -connect ${host}:${port} -servername ${sni} -tls1_2 </dev/null >/dev/null 2>&1 || true"
}

# encrypted_dns_alerts <protocol>
#
# Pull /api/v1/alerts and count rows whose description matches the
# encrypted-DNS reason for the given protocol ("doh" or "dot"). Echoes
# the count on stdout. Empty / missing alerts surface as 0.
encrypted_dns_alerts() {
    local proto="${1:?usage: encrypted_dns_alerts <doh|dot>}"
    local body
    body="$(api_get /api/v1/alerts 2>/dev/null)" || { echo 0; return 0; }
    local count
    count="$(echo "$body" | jq --arg p "$proto" '
        [ (.alerts // .)
          | .[]?
          | select((.message // .description // "") | test("Encrypted DNS detected: " + $p; "i"))
        ] | length' 2>/dev/null)" || count=0
    echo "${count:-0}"
}

# wait_for_encrypted_dns_alert <protocol> [retries] [sleep_s]
#
# Poll the alerts surface until at least one EncryptedDns row of the
# given protocol appears. Returns 0 with the row count on success, 1
# with the last observed count on timeout. Default retries=15,
# sleep_s=1.
wait_for_encrypted_dns_alert() {
    local proto="${1:?usage: wait_for_encrypted_dns_alert <doh|dot>}"
    local retries="${2:-15}"
    local sleep_s="${3:-1}"
    local i count
    for ((i = 0; i < retries; i++)); do
        count="$(encrypted_dns_alerts "${proto}")"
        if [ "${count:-0}" -gt 0 ]; then
            echo "${count}"
            return 0
        fi
        sleep "${sleep_s}"
    done
    echo "${count:-0}"
    return 1
}

# real_doh_probe_cloudflared <backend_ip> <resolver_host>
#
# Drive a *genuine* DoH client (cloudflared proxy-dns) from the attacker VM.
# cloudflared resolves over HTTPS to <resolver_host>, which we alias to the
# backend transit IP via /etc/hosts, so its real ClientHello (SNI =
# resolver_host) crosses the agent on :443. A raw UDP DNS query into the
# local proxy forces the upstream connection. Returns 0 once the client ran.
real_doh_probe_cloudflared() {
    local backend="${1:?usage: real_doh_probe_cloudflared <backend_ip> <resolver_host>}"
    local resolver="${2:?usage: real_doh_probe_cloudflared <backend_ip> <resolver_host>}"
    _attacker_ssh "\
        sudo sed -i '/[[:space:]]${resolver}\$/d' /etc/hosts 2>/dev/null || true; \
        echo '${backend} ${resolver}' | sudo tee -a /etc/hosts >/dev/null; \
        pkill -f 'cloudflared proxy-dns' 2>/dev/null || true; \
        setsid cloudflared proxy-dns --address 127.0.0.1 --port 5599 \
            --upstream 'https://${resolver}/dns-query' >/tmp/cloudflared-doh.log 2>&1 & \
        sleep 2; \
        for i in 1 2 3; do \
            python3 - <<'PY'
import socket
q = b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, ('127.0.0.1', 5599)); s.recvfrom(512)
except Exception:
    pass
PY
        done; \
        pkill -f 'cloudflared proxy-dns' 2>/dev/null || true"
}

# real_dot_probe_dnscrypt <backend_ip> <resolver_host>
#
# Drive a genuine DoT client (dnscrypt-proxy) from the attacker VM against
# the backend's :853 listener. A DoT server stamp (protocol 0x03, no cert
# pinning) is generated on the fly so dnscrypt-proxy TLS-connects to the
# backend with SNI = resolver_host, which the agent detects as DoT-by-port.
real_dot_probe_dnscrypt() {
    local backend="${1:?usage: real_dot_probe_dnscrypt <backend_ip> <resolver_host>}"
    local resolver="${2:?usage: real_dot_probe_dnscrypt <backend_ip> <resolver_host>}"
    _attacker_ssh "\
        STAMP=\$(python3 - '${backend}' '${resolver}' <<'PY'
import base64, sys, struct
ip, host = sys.argv[1], sys.argv[2]
def lp(b): return struct.pack('B', len(b)) + b
# 0x03 = DoT; props=0 (no dnssec/nolog/nofilter claims); addr ip:853;
# empty hashes = no pinning; hostname carries the SNI.
body = b'\\x03' + struct.pack('<Q', 0) + lp((ip + ':853').encode()) + lp(b'') + lp(host.encode())
print('sdns://' + base64.urlsafe_b64encode(body).decode().rstrip('='))
PY
); \
        cfg=/tmp/dnscrypt-dot.toml; \
        { echo 'listen_addresses = [\"127.0.0.1:5699\"]'; \
          echo 'server_names = [\"dot-backend\"]'; \
          echo 'cert_ignore_timestamp = true'; \
          echo '[static.dot-backend]'; \
          echo \"stamp = '\$STAMP'\"; } > \$cfg; \
        pkill -f 'dnscrypt-proxy' 2>/dev/null || true; \
        setsid dnscrypt-proxy -config \$cfg >/tmp/dnscrypt-dot.log 2>&1 & \
        sleep 3; \
        for i in 1 2 3; do \
            python3 - <<'PY'
import socket
q = b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, ('127.0.0.1', 5699)); s.recvfrom(512)
except Exception:
    pass
PY
        done; \
        pkill -f 'dnscrypt-proxy' 2>/dev/null || true"
}

# encrypted_dns_resolver_match <resolver_substr>
#
# Count alerts whose description mentions a particular resolver
# fragment. Used for the custom-DoH-resolver assertion path.
encrypted_dns_resolver_match() {
    local frag="${1:?usage: encrypted_dns_resolver_match <substr>}"
    local body
    body="$(api_get /api/v1/alerts 2>/dev/null)" || { echo 0; return 0; }
    local count
    count="$(echo "$body" | jq --arg s "$frag" '
        [ (.alerts // .)
          | .[]?
          | select((.message // .description // "") | test("Encrypted DNS detected.*" + $s; "i"))
        ] | length' 2>/dev/null)" || count=0
    echo "${count:-0}"
}
