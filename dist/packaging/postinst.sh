#!/bin/sh
# Runs after the files land, on both package formats.
#
# Neither unit is started or enabled here. The agent attaches to interfaces
# this package cannot guess, and the shipped configuration names none, so
# starting it would either fail or quietly watch nothing. The administrator
# edits the configuration and enables the two units, which the message below
# says in as many words.
set -eu

CONFIG=/etc/ebpfsentinel/config.yaml
STATE=/var/lib/ebpfsentinel

# An upgrade is `configure <old-version>` on dpkg and `2` on rpm; a first
# install carries no old version and `1`. Only the message at the end differs.
first_install=yes
case "${1:-}" in
  configure) [ -n "${2:-}" ] && first_install=no ;;
  2) first_install=no ;;
esac

if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/ebpfsentinel.conf || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

# The agent self-unshares a user namespace to load its eBPF. Hosts that gate
# that behind AppArmor (Ubuntu 24.04 and up) refuse it to a process without
# CAP_SYS_ADMIN in the init namespace. The unit runs as root, which is exempt,
# so this only bites a reconfigured deployment - the per-binary profile is
# installed by the package and loaded here, and the host-wide sysctl drop-in
# stays in /usr/share where it is a documented fallback rather than something
# a package silently widened.
if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ] &&
   command -v apparmor_parser >/dev/null 2>&1 &&
   [ -f /etc/apparmor.d/ebpfsentinel-agent ]; then
  apparmor_parser -r -W /etc/apparmor.d/ebpfsentinel-agent || true
fi

# An upgrade restarts what was already running, and nothing else: a unit the
# administrator had stopped stays stopped.
if [ "$first_install" = no ] && command -v systemctl >/dev/null 2>&1; then
  for unit in ebpfsentinel-warden.service ebpfsentinel.service; do
    if systemctl is-active --quiet "$unit"; then
      systemctl restart "$unit" || true
    fi
  done
  exit 0
fi

cat <<MESSAGE
eBPFsentinel is installed. Nothing is running yet.

  1. Name the interfaces to watch: $CONFIG
     Three ready profiles are in /usr/share/ebpfsentinel/profiles - a home
     router, a single k3s node and a Proxmox host. Copy one over the
     configuration rather than starting from the reference.
  2. Enable both units:  systemctl enable --now ebpfsentinel-warden ebpfsentinel
  3. Follow them:        journalctl -u ebpfsentinel -u ebpfsentinel-warden -f

The control API authenticates. With no method configured the agent draws a key
for itself at first start and keeps it at $STATE/auth/api-key.
MESSAGE
