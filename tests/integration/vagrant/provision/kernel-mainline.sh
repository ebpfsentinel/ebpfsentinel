#!/usr/bin/env bash
# kernel-mainline.sh - choose the kernel the next boot runs.
#
# MAINLINE_KERNEL names a kernel.ubuntu.com/mainline build by its directory
# ("6.18.5", "7.3.5", "7.4-rc4"): that exact build is installed and made the
# default, built from the stable tree with Ubuntu's own configuration, BTF and
# module BTF included. Empty, the VM goes back to the HWE kernel: the newest
# kernel that is not a mainline build is pinned, since a mainline kernel left
# installed by an earlier run sorts above it and would otherwise be the
# default. The caller reboots (vagrant `reboot: true`).
#
# Only the image and the modules are installed: the mainline header package may
# want a newer libc than 24.04 has. bpftool is a userspace tool with no mainline
# package, so the running kernel's tools directory is pointed at the HWE one,
# which is where the /usr/sbin/bpftool wrapper looks.
#
# Used by the agent VM here (AGENT_KERNEL) and by the enterprise nodes
# (NODE_KERNEL), so both lanes boot a version the same way; the versions run
# are listed in tests/integration/kernels.toml.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
conf=/etc/default/grub.d/92-agent-kernel.cfg
want="${MAINLINE_KERNEL:-}"

if [ -z "${want}" ]; then
  hwe="$(ls /boot/vmlinuz-*-generic | sed 's|^/boot/vmlinuz-||' \
    | grep -vE -- '-[0-9]{6}(rc[0-9]+)?-generic$' | sort -V | tail -1)"
  test -n "$hwe"
  printf 'GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux %s"\n' "$hwe" > "$conf"
  update-grub
  echo "MAINLINE_KERNEL unset: next boot is the HWE kernel ${hwe}"
  exit 0
fi

base="https://kernel.ubuntu.com/mainline/v${want}/amd64"
listing="$(curl -fsSL --retry 3 "${base}/")"
image="$(grep -oE 'linux-image-unsigned-[^"]*-generic_[^"]*_amd64\.deb' <<<"$listing" | head -1)"
modules="$(grep -oE 'linux-modules-[^"]*-generic_[^"]*_amd64\.deb' <<<"$listing" | head -1)"
if [ -z "$image" ] || [ -z "$modules" ]; then
  echo "no amd64 image and modules under ${base}: pick a point release that built" >&2
  exit 1
fi
release="${image#linux-image-unsigned-}"
release="${release%%_*}"

if [ ! -e "/boot/vmlinuz-${release}" ]; then
  dir="$(mktemp -d)"
  curl -fsSL --retry 3 -o "${dir}/${modules}" "${base}/${modules}"
  curl -fsSL --retry 3 -o "${dir}/${image}" "${base}/${image}"
  # Newer mainline packaging hands run-parts two directories, the second
  # under /usr/share/kernel; run-parts on 24.04 takes one and that directory
  # does not exist here, so the operand is dropped.
  if [ ! -d /usr/share/kernel ]; then
    dpkg-deb -R "${dir}/${image}" "${dir}/unpacked"
    sed -i -E 's| /usr/share/kernel/[a-z]+[.]d$||' "${dir}"/unpacked/DEBIAN/{preinst,postinst,prerm,postrm}
    dpkg-deb -b "${dir}/unpacked" "${dir}/${image}"
    rm -rf "${dir}/unpacked"
  fi
  apt-get install -y --no-install-recommends "${dir}/${modules}" "${dir}/${image}"
  rm -rf "$dir"
fi

hwe_tools="$(ls -d /usr/lib/linux-tools/*-generic 2>/dev/null | grep -v "/${release}$" | sort -V | tail -1)"
if [ -n "$hwe_tools" ] && [ ! -e "/usr/lib/linux-tools/${release}" ]; then
  ln -s "$hwe_tools" "/usr/lib/linux-tools/${release}"
fi
test -e "/boot/vmlinuz-${release}"

printf 'GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux %s"\n' "$release" > "$conf"
update-grub
echo "next boot: ${release}"
