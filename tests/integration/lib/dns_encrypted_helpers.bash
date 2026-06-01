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
