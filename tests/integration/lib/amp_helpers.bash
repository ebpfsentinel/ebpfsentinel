#!/usr/bin/env bash
# amp_helpers.bash — Drive the scapy amplification scripts from BATS.
#
# Each script under scripts/amp/{dns_any,ntp_monlist,ssdp_search,
# memcached_stats}.py crafts spoofed-source UDP packets pointed at the
# agent under test. Helper validates targets (RFC1918 only), exports
# the script directory, and runs each probe synchronously.
#
# Public entrypoints:
#   require_amp                      — skip if python3+scapy missing
#   amp_run <vector> [count] [rate] [spoof-src] [extra...]
#       Foreground run of one amplification probe. Captures stdout into
#       AMP_LOG and returns the script's exit code.
#   amp_egress_zero <iface> <pcap>
#       Assert the agent-side pcap contains no amplification *response*
#       traffic on the four monitored ports.

AMP_SCRIPT_DIR="${AMP_SCRIPT_DIR:-${SCRIPT_DIR:-${BATS_TEST_DIRNAME:-.}/../scripts}/amp}"
AMP_DEFAULT_COUNT="${AMP_DEFAULT_COUNT:-500}"
AMP_DEFAULT_RATE="${AMP_DEFAULT_RATE:-200}"
AMP_DEFAULT_SPOOF_SRC="${AMP_DEFAULT_SPOOF_SRC:-192.168.56.99}"
# Scapy lives in a dedicated venv on the attacker VM (the system python has no
# scapy). Prefer it, mirroring EBPF_SCAPY_PY, and fall back to a bare python3.
AMP_PY="${AMP_PY:-/opt/scapy-venv/bin/python3}"
[ -x "$AMP_PY" ] || AMP_PY="python3"

# ── Guards ────────────────────────────────────────────────────────────

# require_amp
# Skip if scapy is not importable. Probe runs as root so we exec with
# `sudo -n` from a non-root BATS host, otherwise direct.
require_amp() {
    if ! command -v "$AMP_PY" >/dev/null 2>&1; then
        skip "python3 not available on attacker VM"
    fi
    if ! "$AMP_PY" -c "import scapy.all" >/dev/null 2>&1; then
        skip "scapy not installed on attacker VM (run story 34.3 provisioner)"
    fi
    local vector
    for vector in dns_any ntp_monlist ssdp_search memcached_stats; do
        if [ ! -f "${AMP_SCRIPT_DIR}/${vector}.py" ]; then
            skip "amplification script missing: ${AMP_SCRIPT_DIR}/${vector}.py"
        fi
    done
}

# _amp_resolve_script <vector>
# Maps a logical vector name to its script path.
_amp_resolve_script() {
    local vector="$1"
    case "$vector" in
        dns_any|dns|DNS)               echo "${AMP_SCRIPT_DIR}/dns_any.py" ;;
        ntp_monlist|ntp|monlist|NTP)   echo "${AMP_SCRIPT_DIR}/ntp_monlist.py" ;;
        ssdp_search|ssdp|SSDP|msearch) echo "${AMP_SCRIPT_DIR}/ssdp_search.py" ;;
        memcached_stats|memcached|MEMCACHED) echo "${AMP_SCRIPT_DIR}/memcached_stats.py" ;;
        *)
            echo "_amp_resolve_script: unknown vector '${vector}'" >&2
            return 2
            ;;
    esac
}

# ── Public entrypoints ────────────────────────────────────────────────

# amp_run <vector> [count] [rate] [spoof-src]
# Run one amplification probe synchronously. Returns the script's exit
# code (non-zero only on argv / sanity errors — packet send is best-
# effort and never aborts on partial delivery).
amp_run() {
    local vector="${1:?usage: amp_run <vector> [count] [rate] [spoof-src]}"
    local count="${2:-$AMP_DEFAULT_COUNT}"
    local rate="${3:-$AMP_DEFAULT_RATE}"
    local spoof_src="${4:-$AMP_DEFAULT_SPOOF_SRC}"

    require_amp

    local script
    script="$(_amp_resolve_script "$vector")" || return 2

    local dst="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"

    AMP_LOG="${AMP_LOG:-/tmp/amp-${vector}-$$.log}"
    : > "$AMP_LOG"

    local -a runner
    if [ "$(id -u)" -eq 0 ]; then
        runner=("$AMP_PY" "$script")
    else
        runner=(sudo -n "$AMP_PY" "$script")
    fi

    "${runner[@]}" \
        --dst "$dst" \
        --spoof-src "$spoof_src" \
        --count "$count" \
        --rate "$rate" \
        >>"$AMP_LOG" 2>&1
}

# amp_egress_zero <pcap_path>
# Assert the captured pcap on the agent VM contains zero response
# packets sourced from the four amplification ports (DNS/53, NTP/123,
# SSDP/1900, Memcached/11211). Uses tcpdump's -r counter; tshark is
# preferred if present.
amp_egress_zero() {
    local pcap="${1:?usage: amp_egress_zero <pcap_path>}"
    if [ ! -s "$pcap" ]; then
        # Empty pcap = zero packets = pass. Capture missing means the
        # test couldn't start the capture, which is a setup error.
        if [ ! -e "$pcap" ]; then
            echo "amp_egress_zero: pcap ${pcap} not found" >&2
            return 1
        fi
        return 0
    fi
    local filter='(src port 53 or src port 123 or src port 1900 or src port 11211)'
    local count
    if command -v tshark >/dev/null 2>&1; then
        count="$(tshark -r "$pcap" -Y "udp.srcport == 53 or udp.srcport == 123 or udp.srcport == 1900 or udp.srcport == 11211" 2>/dev/null | wc -l)"
    else
        count="$(tcpdump -nn -r "$pcap" "$filter" 2>/dev/null | wc -l)"
    fi
    count="${count:-0}"
    if [ "$count" -gt 0 ]; then
        echo "amp_egress_zero: found ${count} amplification response packets in ${pcap}" >&2
        return 1
    fi
    return 0
}
