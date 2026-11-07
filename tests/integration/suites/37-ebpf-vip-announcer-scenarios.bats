#!/usr/bin/env bats
# 37-ebpf-vip-announcer-scenarios.bats - L2 VIP announcer eBPF scenarios
#
# Validates the bounded XDP ARP responder + userspace gratuitous ARP:
#   * a speaker answers ARP for an owned VIP with its own NIC MAC
#   * a speaker does NOT answer ARP for a non-VIP address
#   * gratuitous ARP is emitted on speaker takeover (takeover metric)
#   * the per-VIP forged-reply metric increments
#   * a standby node is completely silent (split-brain safe)
#   * the status, role and grant routes drive the responder at run time
#   * BGP export goes through the routing daemon's control socket, the
#     speaker exporting each VIP and a standby withdrawing it
#
# Requires: root, kernel >= 5.17, bpftool, python3 + scapy

load '../lib/helpers'
load '../lib/ebpf_helpers'

VIP_ADDR="10.200.0.50"
NON_VIP_ADDR="10.200.0.99"

require_scapy() {
    "$EBPF_SCAPY_PY" -c 'import scapy.all' 2>/dev/null || { echo "scapy not available" >&2; return 1; }
}

# Send a broadcast ARP request for $1 from inside the test netns and echo
# the responder's hardware address (empty if no reply within the timeout).
arp_probe() {
    local target="$1"
    ip netns exec "$EBPF_TEST_NS" "$EBPF_SCAPY_PY" - "$EBPF_VETH_NS" "$target" <<'PY'
import sys
from scapy.all import Ether, ARP, srp
iface, target = sys.argv[1], sys.argv[2]
ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
    iface=iface, timeout=3, retry=2, verbose=0,
)
if ans:
    print(ans[0][1].hwsrc)
PY
}

host_mac() {
    cat "/sys/class/net/${EBPF_VETH_HOST}/address"
}

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-vip-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-vip-announcer.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-vip-$$}"
    rm -f "${PREPARED_CONFIG:-}"
    rm -f "${STANDBY_CONFIG:-}"
    rm -f "${BGP_CONFIG:-}"
}

# ── Speaker: answers ARP for an owned VIP ────────────────────────────

@test "speaker answers ARP for owned VIP with its own NIC MAC" {
    require_root
    require_scapy

    sleep 2
    local responder expected
    responder="$(arp_probe "$VIP_ADDR")"
    expected="$(host_mac)"

    [ -n "$responder" ] || {
        echo "no ARP reply received for VIP $VIP_ADDR" >&2
        return 1
    }
    local got want
    got="$(echo "$responder" | tr 'A-F' 'a-f')"
    want="$(echo "$expected" | tr 'A-F' 'a-f')"
    [ "$got" = "$want" ] || {
        echo "ARP reply MAC $got != NIC MAC $want" >&2
        return 1
    }
}

# ── Speaker: silent for a non-VIP address ────────────────────────────

@test "speaker does NOT answer ARP for a non-VIP address" {
    require_root
    require_scapy

    local responder
    responder="$(arp_probe "$NON_VIP_ADDR")"
    [ -z "$responder" ] || {
        echo "unexpected ARP reply for non-VIP $NON_VIP_ADDR: $responder" >&2
        return 1
    }
}

# ── Gratuitous ARP on takeover (metric) ──────────────────────────────

@test "gratuitous ARP emitted on speaker takeover" {
    require_root

    # announce_takeover() emits one gratuitous ARP per owned VIP and bumps
    # the takeover counter exactly once on the transition into speaker.
    local value
    value="$(wait_for_metric ebpfsentinel_lb_vip_takeovers_total 1 20 '{vip="web-vip"}')" || {
        echo "takeover metric never reached >= 1" >&2
        return 1
    }
    [ -n "$value" ]
}

# ── Per-VIP forged-reply metric ──────────────────────────────────────

@test "lb_vip_arp_replies increments after an ARP for the VIP" {
    require_root
    require_scapy

    arp_probe "$VIP_ADDR" >/dev/null
    arp_probe "$VIP_ADDR" >/dev/null

    # The kernel per-CPU counter is mirrored into Prometheus on a 15s
    # cadence - allow one full refresh cycle plus slack.
    local value
    value="$(wait_for_metric ebpfsentinel_lb_vip_arp_replies 1 25 '{vip="web-vip"}')" || {
        echo "arp replies metric never reached >= 1" >&2
        return 1
    }
    [ -n "$value" ]
}

# ── Announcer status and role over the API ───────────────────────────

# Apply a role over the API with the fixture's interface and VIP.
_apply_role() {
    api_post /api/v1/lb/vips "{\"role\":\"$1\",\"interface\":\"${EBPF_VETH_HOST}\",\"vips\":[{\"name\":\"web-vip\",\"addr\":\"${VIP_ADDR}\"}]}"
}

@test "GET /api/v1/lb/vips reports the speaker and its VIP" {
    local body
    body="$(api_get /api/v1/lb/vips)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "status $HTTP_STATUS: $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.role')" = "primary" ] || { echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.is_speaker')" = "true" ] || { echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.vips[] | select(.name == "web-vip") | .addr')" = "$VIP_ADDR" ] || {
        echo "web-vip missing: $body" >&2
        return 1
    }
    [ "$(echo "$body" | jq -r '.bindings_count')" -ge 1 ] || { echo "$body" >&2; return 1; }
}

@test "POST /api/v1/lb/vips to standby silences the ARP responder, primary restores it" {
    require_scapy

    local body
    body="$(_apply_role standby)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "status $HTTP_STATUS: $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.is_speaker')" = "false" ] || { _apply_role primary >/dev/null; echo "$body" >&2; return 1; }
    sleep 1
    local responder
    responder="$(arp_probe "$VIP_ADDR")"
    [ -z "$responder" ] || {
        _apply_role primary >/dev/null
        echo "standby still answers ARP: $responder" >&2
        return 1
    }

    body="$(_apply_role primary)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "status $HTTP_STATUS: $body" >&2; return 1; }
    sleep 1
    responder="$(arp_probe "$VIP_ADDR")"
    [ -n "$responder" ] || { echo "primary restored over the API stays silent" >&2; return 1; }
}

@test "POST /api/v1/lb/vips/grant makes an elected node speak and 0 releases it" {
    require_scapy

    local body responder
    body="$(_apply_role elected)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "status $HTTP_STATUS: $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.is_speaker')" = "false" ] || {
        _apply_role primary >/dev/null
        echo "elected node speaks before any grant: $body" >&2
        return 1
    }
    sleep 1
    responder="$(arp_probe "$VIP_ADDR")"
    [ -z "$responder" ] || { _apply_role primary >/dev/null; echo "ungranted node answers ARP" >&2; return 1; }

    body="$(api_post /api/v1/lb/vips/grant '{"seconds":60}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { _apply_role primary >/dev/null; echo "grant: $HTTP_STATUS $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.is_speaker')" = "true" ] || { _apply_role primary >/dev/null; echo "$body" >&2; return 1; }
    local left
    left="$(echo "$body" | jq -r '.grant_remaining_ms // 0')"
    { [ "$left" -gt 0 ] && [ "$left" -le 60000 ]; } || { _apply_role primary >/dev/null; echo "grant_remaining_ms=$left" >&2; return 1; }
    sleep 1
    responder="$(arp_probe "$VIP_ADDR")"
    [ -n "$responder" ] || { _apply_role primary >/dev/null; echo "granted node stays silent" >&2; return 1; }

    body="$(api_post /api/v1/lb/vips/grant '{"seconds":0}')"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { _apply_role primary >/dev/null; echo "release: $HTTP_STATUS $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.is_speaker')" = "false" ] || { _apply_role primary >/dev/null; echo "$body" >&2; return 1; }
    sleep 1
    responder="$(arp_probe "$VIP_ADDR")"
    _apply_role primary >/dev/null
    [ -z "$responder" ] || { echo "released node still answers ARP: $responder" >&2; return 1; }
}

@test "POST /api/v1/lb/vips/grant is refused on a node that is not elected" {
    local body
    body="$(api_post /api/v1/lb/vips/grant '{"seconds":30}')"
    _load_http_status
    [ "$HTTP_STATUS" = "400" ] || { echo "grant on a primary: $HTTP_STATUS $body" >&2; return 1; }

    _apply_role elected >/dev/null
    body="$(api_post /api/v1/lb/vips/grant '{"seconds":301}')"
    _load_http_status
    local capped="$HTTP_STATUS"
    _apply_role primary >/dev/null
    [ "$capped" = "400" ] || { echo "grant past the cap: $capped $body" >&2; return 1; }
}

@test "GET /api/v1/lb/vips/bgp reports BGP off when it is not configured" {
    local body
    body="$(api_get /api/v1/lb/vips/bgp)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { echo "status $HTTP_STATUS: $body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.enabled')" = "false" ] || { echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.exporting')" = "false" ] || { echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.sessions | length')" = "0" ] || { echo "$body" >&2; return 1; }
}

# ── Standby is split-brain safe (silent) ─────────────────────────────

@test "standby node never answers ARP for the VIP" {
    require_root
    require_scapy

    stop_ebpf_agent 2>/dev/null || true
    sleep 1

    STANDBY_CONFIG="$(prepare_ebpf_config \
        "${FIXTURE_DIR}/config-ebpf-vip-announcer-standby.yaml" \
        "/tmp/ebpfsentinel-test-vip-standby-$$.yaml")"
    export STANDBY_CONFIG

    start_ebpf_agent "$STANDBY_CONFIG"
    wait_for_ebpf_loaded 30 || { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    sleep 2

    local responder
    responder="$(arp_probe "$VIP_ADDR")"
    [ -z "$responder" ] || {
        echo "standby answered ARP for VIP (split-brain!): $responder" >&2
        return 1
    }

    # A standby must never have emitted a gratuitous ARP / takeover.
    local takeovers
    takeovers="$(get_metrics_value ebpfsentinel_lb_vip_takeovers_total '{vip="web-vip"}')" || true
    [ -z "$takeovers" ] || [ "$takeovers" = "0" ] || {
        echo "standby recorded a takeover: $takeovers" >&2
        return 1
    }
}

# ── BGP export through the routing daemon's control socket ───────────

# A stand-in for BIRD 2: it speaks the control protocol's reply framing,
# records every command, keeps the configuration the agent asked it to
# load, and reports one established session per peer it was given.
_start_fake_bird() {
    local sock="$1" log="$2"
    python3 - "$sock" "$log" >/dev/null 2>&1 <<'PY' &
import os, re, socket, sys
sock_path, log_path = sys.argv[1], sys.argv[2]
try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
os.chmod(sock_path, 0o777)
srv.listen(8)
peers = []
while True:
    conn, _ = srv.accept()
    with conn:
        f = conn.makefile("rwb")
        f.write(b"0001 BIRD 2.0.12 ready.\n"); f.flush()
        line = f.readline().decode().strip()
        with open(log_path, "a") as log:
            log.write(line + "\n")
        m = re.match(r'configure "(.*)"', line)
        if m:
            try:
                text = open(m.group(1)).read()
            except OSError as e:
                f.write(f"8001 {e}\n".encode()); f.flush(); continue
            open(log_path + ".conf", "w").write(text)
            peers = re.findall(r"protocol bgp (\S+) \{", text)
            f.write(b"0002-Reading configuration\n0003 Reconfigured\n")
        elif line == "show protocols":
            out = "2002-Name       Proto      Table      State  Since         Info\n"
            for p in peers:
                out += f"1002-{p} BGP        ---        up     2026-11-07 10:00:00  Established\n"
            out += "0000 \n"
            f.write(out.encode())
        else:
            f.write(b"9001 Unknown command\n")
        f.flush()
PY
    echo $!
}

@test "BGP: the speaker exports the VIP through the daemon and /vips/bgp reads the session back" {
    stop_ebpf_agent 2>/dev/null || true
    sleep 1

    local sock="${DATA_DIR}/bird.ctl" log="${DATA_DIR}/bird.log"
    chmod 0755 "$DATA_DIR"
    : > "$log"
    local bird_pid
    bird_pid="$(_start_fake_bird "$sock" "$log")"
    for _ in $(seq 1 20); do [ -S "$sock" ] && break; sleep 0.2; done
    [ -S "$sock" ] || { kill "$bird_pid" 2>/dev/null; echo "fake daemon socket never appeared" >&2; return 1; }

    BGP_CONFIG="$(prepare_ebpf_config \
        "${FIXTURE_DIR}/config-ebpf-vip-announcer-bgp.yaml" \
        "/tmp/ebpfsentinel-test-vip-bgp-$$.yaml")"
    export BGP_CONFIG
    start_ebpf_agent "$BGP_CONFIG"
    wait_for_ebpf_loaded 30 || { kill "$bird_pid" 2>/dev/null; echo "eBPF programs not loaded" >&2; return 1; }

    local body ok=""
    for _ in $(seq 1 20); do
        body="$(api_get /api/v1/lb/vips/bgp)"
        if [ "$(echo "$body" | jq -r '[.sessions[]? | select(.peer == "upstream" and .state == "Established")] | length')" = "1" ]; then
            ok=1; break
        fi
        sleep 1
    done
    [ -n "$ok" ] || { kill "$bird_pid" 2>/dev/null; echo "no established session read back: $body; daemon log: $(cat "$log")" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.enabled')" = "true" ] || { kill "$bird_pid" 2>/dev/null; echo "$body" >&2; return 1; }
    [ "$(echo "$body" | jq -r '.exporting')" = "true" ] || { kill "$bird_pid" 2>/dev/null; echo "$body" >&2; return 1; }
    grep -q "route ${VIP_ADDR}/32 blackhole" "${log}.conf" || {
        kill "$bird_pid" 2>/dev/null
        echo "speaker did not export the VIP: $(cat "${log}.conf")" >&2
        return 1
    }
    grep -q "neighbor 10.200.0.2 port 179 as 65002" "${log}.conf" || {
        kill "$bird_pid" 2>/dev/null
        echo "peer missing from the daemon configuration: $(cat "${log}.conf")" >&2
        return 1
    }

    # A standby keeps its session but withdraws the route.
    body="$(_apply_role standby)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || { kill "$bird_pid" 2>/dev/null; echo "standby: $HTTP_STATUS $body" >&2; return 1; }
    body="$(api_get /api/v1/lb/vips/bgp)"
    kill "$bird_pid" 2>/dev/null || true
    [ "$(echo "$body" | jq -r '.exporting')" = "false" ] || { echo "standby still exporting: $body" >&2; return 1; }
    if grep -q "route ${VIP_ADDR}/32" "${log}.conf"; then
        echo "standby left the VIP route in the daemon: $(cat "${log}.conf")" >&2
        return 1
    fi
}
