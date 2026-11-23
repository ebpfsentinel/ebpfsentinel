# Which distributions boot with the BPF LSM, 2026-11-23

The warden's refusal of an unsigned load, the network executables list and the
self-protection guard all need `bpf` among the LSMs the kernel initialised at
boot. A kernel started without `lsm=` on its command line initialises the list
in its build's `CONFIG_LSM`; this record reads that list for every distribution
and node image the compatibility tables call supported.

## How

`scripts/lsm-defaults.py`, run as `python3 -I tests/integration/scripts/lsm-defaults.py`
on 2026-11-23. Where the distribution publishes the kernel it installs as a
package, the configuration is read out of the package (Ubuntu from the newest
`resolute-updates` headers package, Amazon Linux 2023 from the newest
`kernel6.18-devel` rpm); elsewhere from the configuration its packaging
repository builds from. NixOS passes `lsm=` itself, from `security.lsm`, so its
module is read. The host the script ran on, Ubuntu 26.04.1 on
`7.0.0-43-generic` with no `lsm=` on its command line, lists
`lockdown,capability,landlock,yama,apparmor,bpf,ima,evm` in
`/sys/kernel/security/lsm`, matching its package.

## Answers

| Distribution or node image | Read from | `bpf` at boot |
|---|---|---|
| Ubuntu 26.04, 24.04 HWE (generic) | `linux-headers-7.0.0-44-generic` | Yes |
| Ubuntu 26.04 on Azure (AKS node image) | `linux-headers-7.0.0-1021-azure` | Yes |
| Debian 13 backports | `debian/latest` kernel config | Yes |
| Fedora | kernel-ark `fedora/generic/CONFIG_LSM` | Yes |
| openSUSE Tumbleweed | `SUSE/kernel-source` `x86_64/default` | Yes |
| Arch Linux | `config.x86_64` | Yes |
| NixOS 26.05 | `security.lsm`, `bpf` appended last | Yes |
| Talos | `siderolabs/pkgs` `config-amd64` | Yes |
| Amazon Linux 2023 on 6.18 (EKS) | `kernel6.18-devel-6.18.62-127.179` | Yes |
| Bottlerocket on 6.18 (EKS) | `kernel-6.18` `config-full-bottlerocket-x86_64-on-x86_64` | Yes |
| Alpine `linux-lts` | `lts.x86_64.config` | No: set `lsm=` |
| Flatcar on 6.18 | `commonconfig-6.18` | No: set `lsm=` |
| Container-Optimized OS (GKE) | not read: its kernel configuration is not published apart from the image | Unknown |

## What this does not show

- A command line that sets `lsm=` or a provider that adds it overrides the build's
  list; the table reads the default, not every image built on it.
  `ebpfsentinel-agent ebpf host-check` answers for a running host.
- Container-Optimized OS is our gap: no image was booted. Reading
  `/sys/kernel/security/lsm` on a GKE node answers it.
- The Ubuntu packaging tree's `debian.master/config/annotations` on the
  `resolute` default branch lists no `bpf`, while the two packages read here and
  the one installed on the host do; the package is what installs, so it is what
  this record reads.
