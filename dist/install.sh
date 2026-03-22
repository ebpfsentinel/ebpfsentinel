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

# Check kernel version >= 6.6
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -lt 6 ]] || { [[ "$KERNEL_MAJOR" -eq 6 ]] && [[ "$KERNEL_MINOR" -lt 6 ]]; }; then
  echo "Error: kernel >= 6.6 is required (found $(uname -r))." >&2
  exit 1
fi

# Check BTF support
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  echo "Error: BTF not available (/sys/kernel/btf/vmlinux missing)." >&2
  echo "Your kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y." >&2
  exit 1
fi

# ── Determine source directory ────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Install binary ────────────────────────────────────────────────

echo "Installing ebpfsentinel-agent to ${INSTALL_BIN}..."
install -Dm755 "${SCRIPT_DIR}/ebpfsentinel-agent" "${INSTALL_BIN}/ebpfsentinel-agent"

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

# ── Create state directory ────────────────────────────────────────

mkdir -p "${INSTALL_VAR}"

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
