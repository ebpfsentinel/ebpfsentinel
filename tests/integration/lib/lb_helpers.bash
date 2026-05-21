#!/usr/bin/env bash
# lb_helpers.bash — Load balancer (DSR + Maglev) integration test helpers.
#
# Active when sourced by a suite running in EBPF_3VM_MODE=true. Wraps the
# agent's LB REST surface and the in-kernel Maglev map to drive end-to-end
# DSR + consistent-hash assertions from the attacker (client) VM.
#
# Requires:
#   - vm_helpers.bash already sourced (provides _agent_ssh, _backend_ssh,
#     set_backend_arp, AGENT_VM_IP / BACKEND_VM_IP / EBPF_AGENT_BACKEND_IFACE)
#   - bpftool present on the agent VM
#   - python3 available locally (to parse bpftool's JSON map dump)

LB_VIP_ADDR="${LB_VIP_ADDR:-192.168.56.100}"
LB_MAGLEV_RING_SIZE="${LB_MAGLEV_RING_SIZE:-65537}"

# setup_vip <vip_addr> <iface> <role>
#
# Apply the VIP announcer policy via POST /api/v1/lb/vips. Role is one of
# "primary" / "standby" / "disabled". Echoes the HTTP status on stdout.
setup_vip() {
    local vip="${1:?usage: setup_vip <vip> <iface> <role>}"
    local iface="${2:?usage: setup_vip <vip> <iface> <role>}"
    local role="${3:?usage: setup_vip <vip> <iface> <role>}"
    local body
    body="$(cat <<EOF
{
  "role": "${role}",
  "interface": "${iface}",
  "vips": [ { "name": "dsr-vip", "addr": "${vip}" } ]
}
EOF
)"
    api_post /api/v1/lb/vips "$body" >/dev/null
    _load_http_status
    echo "${HTTP_STATUS}"
}

# register_backends <svc_id> <listen_port> <algo> <mode> <backend...>
#
# Each backend argument is "id:addr:port[:weight]". When mode is l2dsr the
# helper sets same_segment=true on every backend. Returns the HTTP status
# on stdout (200 / 201 on success).
register_backends() {
    local svc_id="${1:?usage: register_backends <id> <port> <algo> <mode> <be...>}"
    local listen_port="${2:?usage: register_backends <id> <port> <algo> <mode> <be...>}"
    local algo="${3:?usage: register_backends <id> <port> <algo> <mode> <be...>}"
    local mode="${4:?usage: register_backends <id> <port> <algo> <mode> <be...>}"
    shift 4
    local same_segment="false"
    case "$mode" in
        l2dsr|l2_dsr|dsr) same_segment="true" ;;
    esac
    local backends_json=""
    local be id addr port weight
    for be in "$@"; do
        IFS=':' read -r id addr port weight <<<"$be"
        weight="${weight:-1}"
        if [ -n "${backends_json}" ]; then
            backends_json="${backends_json},"
        fi
        backends_json+="{\"id\":\"${id}\",\"addr\":\"${addr}\",\"port\":${port},\"weight\":${weight},\"enabled\":true,\"same_segment\":${same_segment}}"
    done
    local body
    body=$(cat <<EOF
{
  "id": "${svc_id}",
  "name": "${svc_id}",
  "protocol": "tcp",
  "listen_port": ${listen_port},
  "algorithm": "${algo}",
  "mode": "${mode}",
  "enabled": true,
  "backends": [ ${backends_json} ]
}
EOF
)
    api_post /api/v1/lb/services "$body" >/dev/null
    _load_http_status
    echo "${HTTP_STATUS}"
}

# delete_lb_service <svc_id>
delete_lb_service() {
    local svc_id="${1:?usage: delete_lb_service <id>}"
    api_delete "/api/v1/lb/services/${svc_id}" >/dev/null
    _load_http_status
    echo "${HTTP_STATUS}"
}

# dump_maglev_table <out_path>
#
# Pull LB_MAGLEV map (whatever service index it holds) off the agent VM
# and write a newline-separated list of u16 ring entries to <out_path>.
# Returns 0 on success. The ring is dumped as JSON by bpftool, then
# decoded locally so the test can diff two snapshots cheaply.
dump_maglev_table() {
    local out="${1:?usage: dump_maglev_table <out_path>}"
    local raw
    raw="$(_agent_ssh_sudo bpftool -j map dump name LB_MAGLEV 2>/dev/null)" || return 1
    [ -n "$raw" ] || return 1
    printf '%s' "$raw" | python3 - "$out" <<'PY' || return 1
import json, sys
out_path = sys.argv[1]
data = json.loads(sys.stdin.read() or "[]")
if not data:
    sys.exit(1)
# Each entry has "value" as a list of byte strings ("0x12") in little-endian
# order; pairs form u16 entries of the Maglev ring.
entry = data[0]
val = entry.get("value") or entry.get("formatted", {}).get("value") or []
if not val:
    sys.exit(1)
bs = bytes(int(b, 16) if isinstance(b, str) else int(b) for b in val)
if len(bs) < 2:
    sys.exit(1)
ring = []
for i in range(0, len(bs) - 1, 2):
    ring.append(bs[i] | (bs[i + 1] << 8))
with open(out_path, "w", encoding="utf-8") as f:
    for r in ring:
        f.write(f"{r}\n")
PY
    [ -s "$out" ] || return 1
}

# count_remapped_flows <before_path> <after_path>
#
# Compare two Maglev ring dumps line-by-line and echo the count of
# entries that resolve to a different backend index. Empty / missing
# files yield 0.
count_remapped_flows() {
    local before="${1:?usage: count_remapped_flows <before> <after>}"
    local after="${2:?usage: count_remapped_flows <before> <after>}"
    [ -s "$before" ] && [ -s "$after" ] || { echo 0; return 0; }
    paste "$before" "$after" | awk '$1 != $2 { c++ } END { print c+0 }'
}
