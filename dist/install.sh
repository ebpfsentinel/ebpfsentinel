#!/usr/bin/env bash
set -euo pipefail

INSTALL_BIN="/usr/local/bin"
INSTALL_LIB="/usr/local/lib/ebpfsentinel"
INSTALL_ETC="/etc/ebpfsentinel"
INSTALL_VAR="/var/lib/ebpfsentinel"
SYSTEMD_DIR="/etc/systemd/system"

# ── Preflight checks ──────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root." >&2
  exit 1
fi

# Check kernel version >= 6.9
# Kernel 6.9 is required for:
#   - BPF token delegation (BPF_TOKEN_CREATE, BPF_F_TOKEN_FD)
#   - BPF_MAP_TYPE_ARENA mmap'd zero-copy map
#   - kfuncs bpf_task_get_cgroup1, bpf_xdp_metadata_rx_vlan_tag,
#     bpf_xdp_get_xfrm_state, bpf_iter_css_task (kernel 6.7–6.8)
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -lt 6 ]] || { [[ "$KERNEL_MAJOR" -eq 6 ]] && [[ "$KERNEL_MINOR" -lt 9 ]]; }; then
  echo "Error: kernel >= 6.9 is required (found $(uname -r))." >&2
  echo "       Container-aware least-privilege (BPF token) and cgroup1" >&2
  echo "       enrichment require kernel 6.9 or later." >&2
  exit 1
fi

# Check BTF support
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  echo "Error: BTF not available (/sys/kernel/btf/vmlinux missing)." >&2
  echo "Your kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y." >&2
  exit 1
fi

# Check for libpcap (optional — only needed for manual packet capture)
if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
  echo "Warning: libpcap not found. Packet capture (POST /api/v1/captures/manual) will not work." >&2
  echo "         Install with: apt-get install libpcap0.8 (Debian/Ubuntu) or dnf install libpcap (RHEL/Fedora)." >&2
  echo "         This is optional — all other features work without it." >&2
  echo ""
fi

# ── Determine source directory ────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Install binary ────────────────────────────────────────────────

echo "Installing ebpfsentinel-agent to ${INSTALL_BIN}..."
install -Dm755 "${SCRIPT_DIR}/ebpfsentinel-agent" "${INSTALL_BIN}/ebpfsentinel-agent"

# ── Build + install the BPF token launcher ────────────────────────
#
# eBPF loads only through a BPF token, which is a user-namespace feature
# (BPF_TOKEN_CREATE is EOPNOTSUPP in the host userns). The launcher is a
# minimal privileged bootstrap: it sets up a delegated bpffs in a child
# user namespace and execs the agent there, so the agent runs with no
# capabilities over the host. The systemd unit's ExecStart calls it.
#
# Ship a prebuilt binary if present, else compile from source with cc.
if [[ -x "${SCRIPT_DIR}/ebpfsentinel-token-launch" ]]; then
  echo "Installing ebpfsentinel-token-launch to ${INSTALL_BIN}..."
  install -Dm755 "${SCRIPT_DIR}/ebpfsentinel-token-launch" "${INSTALL_BIN}/ebpfsentinel-token-launch"
elif command -v cc > /dev/null; then
  echo "Building ebpfsentinel-token-launch from source..."
  cc -O2 -o "${INSTALL_BIN}/ebpfsentinel-token-launch" "${SCRIPT_DIR}/ebpfsentinel-token-launch.c"
  chmod 755 "${INSTALL_BIN}/ebpfsentinel-token-launch"
else
  echo "Error: no prebuilt ebpfsentinel-token-launch and no C compiler (cc) found." >&2
  echo "       Install a C toolchain (e.g. apt-get install gcc) and re-run." >&2
  exit 1
fi

# ── Install eBPF programs ─────────────────────────────────────────

echo "Installing eBPF programs to ${INSTALL_LIB}..."
mkdir -p "${INSTALL_LIB}"
if [[ -d "${SCRIPT_DIR}/ebpf" ]]; then
  cp -a "${SCRIPT_DIR}/ebpf/"* "${INSTALL_LIB}/"
fi

# ── Install configuration ─────────────────────────────────────────

mkdir -p "${INSTALL_ETC}"
if [[ ! -f "${INSTALL_ETC}/config.yaml" ]]; then
  echo "Installing default configuration to ${INSTALL_ETC}/config.yaml..."
  install -Dm644 "${SCRIPT_DIR}/ebpfsentinel.yaml" "${INSTALL_ETC}/config.yaml"
else
  echo "Configuration already exists at ${INSTALL_ETC}/config.yaml, skipping."
fi

# ── Create state directories ─────────────────────────────────────

mkdir -p "${INSTALL_VAR}"
mkdir -p "${INSTALL_VAR}/captures"

# ── Install systemd unit ──────────────────────────────────────────

echo "Installing systemd service..."
install -Dm644 "${SCRIPT_DIR}/ebpfsentinel.service" "${SYSTEMD_DIR}/ebpfsentinel.service"
systemctl daemon-reload

# ── Done ──────────────────────────────────────────────────────────

echo ""
echo "eBPFsentinel installed successfully."
echo ""
echo "Next steps:"
echo "  1. Edit configuration: ${INSTALL_ETC}/config.yaml"
echo "  2. Start the agent:    systemctl start ebpfsentinel"
echo "  3. Enable on boot:     systemctl enable ebpfsentinel"
echo "  4. View logs:          journalctl -u ebpfsentinel -f"
