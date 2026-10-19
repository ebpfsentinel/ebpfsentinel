#!/bin/sh
# Runs after the files go, on both package formats.
#
# What is deliberately NOT deleted on a plain removal: the configuration, the
# state directory and the API key. A removal that takes an operator's rules
# with it is a removal nobody dares run. `dpkg --purge` is the explicit ask
# and it is honoured; rpm has no purge, so `/var/lib/ebpfsentinel` survives an
# erase and the uninstall script is what removes it.
set -eu

STATE=/var/lib/ebpfsentinel

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

case "${1:-}" in
  purge)
    rm -rf "$STATE"
    rm -f /etc/ebpfsentinel/config.yaml
    rmdir /etc/ebpfsentinel 2>/dev/null || true
    ;;
  0)
    echo "ebpfsentinel: $STATE is left in place; remove it by hand to drop the stored state and the API key." >&2
    ;;
esac

# A pin surviving the agent keeps a program loaded with nothing managing it.
# The agent unpins on shutdown, so this only catches a host where it was
# killed; it is a directory the package owns the name of either way.
case "${1:-}" in
  remove|purge|0)
    for pin in /sys/fs/bpf/ebpfsentinel /sys/fs/bpf/ebpfsentinel-dlp; do
      [ -e "$pin" ] || continue
      if mountpoint -q "$pin" 2>/dev/null; then
        umount "$pin" || true
      fi
      rm -rf "$pin" 2>/dev/null || true
    done
    ;;
esac
