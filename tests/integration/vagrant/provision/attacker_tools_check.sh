#!/usr/bin/env bash
# attacker_tools_check.sh — Verify every attack tool installed by
# setup-attacker.sh is present and matches its pinned series.
#
# Invoked at the tail of setup-attacker.sh (failure aborts the boot)
# and on demand by `make check-attacker-tools` from the host.
#
# Exit codes:
#   0  — all tools present and within pin range
#   1  — at least one tool missing or out-of-range
#   2  — script invocation error (bad args, etc.)

set -euo pipefail

MISSING=()
DRIFT=()
OK=()

# ── Helpers ────────────────────────────────────────────────────────

# check_bin <tool-name> <binary> <version-flag> <expected-substring>
check_bin() {
    local name="$1" bin="$2" flag="$3" expect="$4"
    if ! command -v "$bin" >/dev/null 2>&1; then
        MISSING+=("$name ($bin not in PATH)")
        return
    fi
    local out
    out="$("$bin" "$flag" 2>&1 | head -3 || true)"
    if [ -z "$expect" ] || echo "$out" | grep -qF "$expect"; then
        OK+=("$name")
    else
        DRIFT+=("$name (expected substring '$expect', got: $(echo "$out" | head -1))")
    fi
}

# check_path <tool-name> <path>
check_path() {
    local name="$1" path="$2"
    if [ -e "$path" ]; then
        OK+=("$name")
    else
        MISSING+=("$name (path missing: $path)")
    fi
}

# check_venv <tool-name> <venv> <module>
check_venv() {
    local name="$1" venv="$2" module="$3"
    if [ ! -x "${venv}/bin/python3" ]; then
        MISSING+=("$name (venv missing: ${venv})")
        return
    fi
    if "${venv}/bin/python3" -c "import ${module}" 2>/dev/null; then
        OK+=("$name")
    else
        DRIFT+=("$name (venv ${venv} cannot import ${module})")
    fi
}

# check_kmod <module>
check_kmod() {
    local mod="$1"
    if modinfo "$mod" >/dev/null 2>&1; then
        OK+=("kmod:${mod}")
    else
        MISSING+=("kmod:${mod}")
    fi
}

# ── Checks ─────────────────────────────────────────────────────────

# apt-managed tools (loose substring match per TOOL_VERSIONS.md)
check_bin "slowhttptest"  slowhttptest -h      "slowhttptest, version"
check_bin "nping"         nping        --version "Nping"
check_bin "t50"           t50          -v       "T50"
check_bin "wrk"           wrk          -v       "wrk "
check_bin "dnsperf"       dnsperf      -h       ""
check_bin "hydra"         hydra        -h       "Hydra v"
check_bin "ncrack"        ncrack       -V       "Ncrack"
check_bin "tcpdump"       tcpdump      --version "tcpdump version"
check_bin "scapy-cli"     /opt/scapy-venv/bin/python3 -V "Python"
check_bin "sshpass"       sshpass      -V       "sshpass"

# Release tarballs / source-built binaries — pinned to exact versions
check_bin "vegeta"        vegeta       -version "12.13.0"
check_bin "k6"            k6           version  "k6 v2.0.0"
check_bin "nuclei"        nuclei       -version "3.8.0"
check_bin "dnscrypt-proxy" dnscrypt-proxy -version "2.1.15"
check_bin "cloudflared"   cloudflared  --version "2026.5.0"
check_bin "hyenae-ng"     hyenae-ng    --version "0.10"

# Venvs
check_venv "MHDDoS"     /opt/MHDDoS/.venv      certifi
check_venv "scapy"      /opt/scapy-venv        scapy
check_venv "mitmproxy"  /opt/mitmproxy-venv    mitmproxy

# Vendored submodule
check_path "MHDDoS source"   /opt/MHDDoS/start.py
check_path "pktgen modprobe" /etc/modules-load.d/pktgen.conf

# Kernel modules
check_kmod pktgen

# ── Report ─────────────────────────────────────────────────────────
echo ""
echo "═══ Attacker VM tooling verification ═══"
echo "  OK:      ${#OK[@]} tools"
[ "${#MISSING[@]}" -gt 0 ] && {
    echo "  MISSING: ${#MISSING[@]}"
    for m in "${MISSING[@]}"; do echo "    - $m"; done
}
[ "${#DRIFT[@]}" -gt 0 ] && {
    echo "  DRIFT:   ${#DRIFT[@]}"
    for d in "${DRIFT[@]}"; do echo "    - $d"; done
}

if [ "${#MISSING[@]}" -eq 0 ] && [ "${#DRIFT[@]}" -eq 0 ]; then
    echo "  Result: PASS"
    exit 0
fi
echo "  Result: FAIL"
exit 1
