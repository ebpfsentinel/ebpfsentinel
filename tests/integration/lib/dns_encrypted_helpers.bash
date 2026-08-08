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
    # Bound the handshake: if transit is misrouted the TCP SYN would
    # otherwise retry for ~130s per probe. `timeout` caps it so a broken
    # path fails fast instead of stalling the suite for minutes.
    _attacker_ssh \
        "timeout 10 bash -c 'echo Q | openssl s_client -connect ${host}:${port} -servername ${sni} -tls1_2 </dev/null >/dev/null 2>&1' || true"
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

# real_doh_probe <backend_ip> <resolver_host>
#
# Drive a *genuine* RFC 8484 DoH client (curl --doh-url) from the attacker
# VM. <resolver_host> is aliased to the backend transit IP via /etc/hosts, so
# curl's real ClientHello (SNI = resolver_host) crosses the agent on :443
# when it POSTs the DNS query to https://<resolver_host>/dns-query. The DoH
# exchange itself fails (the backend is not a real DoH server) but the
# ClientHello has already traversed the datapath, which is all the detector
# needs. A single one-shot curl per iteration — no background proxy, no
# heredoc — so the ssh session cannot self-terminate (status 255).
real_doh_probe() {
    local backend="${1:?usage: real_doh_probe <backend_ip> <resolver_host>}"
    local resolver="${2:?usage: real_doh_probe <backend_ip> <resolver_host>}"
    _attacker_ssh "\
        sudo sed -i '/[[:space:]]${resolver}\$/d' /etc/hosts 2>/dev/null || true; \
        echo '${backend} ${resolver}' | sudo tee -a /etc/hosts >/dev/null; \
        for i in 1 2 3; do \
            timeout 8 curl -s -o /dev/null \
                --doh-url 'https://${resolver}/dns-query' \
                --connect-timeout 4 'https://doh-target.test/' >/dev/null 2>&1 || true; \
        done"
}

# real_dot_probe <backend_ip> <resolver_host>
#
# Drive a genuine DoT client (kdig +tls from knot-dnsutils) from the attacker
# VM against the backend's :853 listener. kdig opens a real TLS connection to
# backend:853 (SNI = resolver_host) and sends a DNS query inside it; the
# agent detects the handshake as DoT-by-port. The upstream is not a real DoT
# resolver so no answer comes back, but the ClientHello has crossed transit.
# `timeout` bounds each probe so a dead path fails fast.
real_dot_probe() {
    local backend="${1:?usage: real_dot_probe <backend_ip> <resolver_host>}"
    local resolver="${2:?usage: real_dot_probe <backend_ip> <resolver_host>}"
    _attacker_ssh "\
        for i in 1 2 3; do \
            timeout 8 kdig +tls +tls-hostname='${resolver}' +timeout=4 \
                -p 853 '@${backend}' example.com >/dev/null 2>&1 || true; \
        done"
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
