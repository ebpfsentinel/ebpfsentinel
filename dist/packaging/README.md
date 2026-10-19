# Native packages

A `.deb` and an `.rpm`, built from the same `nfpm.yaml` and the same four
maintainer scripts. The release pipeline builds them for amd64 and arm64 from
the commit the release manifest pins, and they land in the release beside the
tarball, covered by the same `SHA256SUMS` and the same signature.

## Building one by hand

```bash
cargo build --release --bin ebpfsentinel-agent --bin warden
cargo xtask ebpf-build

dist/packaging/build-packages.sh \
  --version 2026.4.1 --arch amd64 \
  --bin-dir target/release \
  --ebpf-dir target/bpfel-unknown-none/release \
  --out-dir dist/out
```

`nfpm` has to be on `PATH`. The script stages everything into a temporary
directory first, so what ends up in the package is exactly what it put there.

## Where the files go, and why it is not where the tarball puts them

The tarball's `install.sh` writes under `/usr/local`, which is the prefix for
software installed outside the package manager. A package may not write there
at all, so the two layouts differ:

| | tarball | package |
|---|---|---|
| binaries | `/usr/local/bin/{ebpfsentinel-agent,warden}` | `/usr/bin/ebpfsentinel-agent`, `/usr/bin/ebpfsentinel-warden` |
| eBPF objects | `/usr/local/lib/ebpfsentinel` | `/usr/lib/ebpfsentinel` |
| units | `/etc/systemd/system` | `/usr/lib/systemd/system` |
| profiles | `/usr/local/share/ebpfsentinel/profiles` | `/usr/share/ebpfsentinel/profiles` |
| configuration | `/etc/ebpfsentinel/config.yaml` | the same, as a conffile |
| state | `/var/lib/ebpfsentinel` | the same, through tmpfiles |

The agent looks for its objects in `/usr/local/lib/ebpfsentinel` first and
`/usr/lib/ebpfsentinel` second, so both layouts work and a host carrying both
uses the one an administrator put there by hand.

The unit files are written once, for the tarball, and the build script
rewrites the two `/usr/local/bin` paths on the way into the staging
directory. A second copy of each unit would be a second thing to keep in
step; a rewrite that silently stopped matching would be worse than either, so
the script fails when a unit still names `/usr/local` afterwards and
`crates/xtask/tests/tree_hygiene.rs` fails when a unit names a path the
rewrite table does not carry.

## What the maintainer scripts do

- `preinst` refuses the install on a kernel below 6.9 or without BTF. The
  agent cannot load its eBPF on either, and a package that installs anyway
  leaves a failed unit and no explanation.
- `postinst` creates the state directories through tmpfiles, reloads systemd,
  loads the AppArmor profile where the host restricts unprivileged user
  namespaces, and restarts on an upgrade only what was already running.
  **Neither unit is enabled or started**: the shipped configuration names
  interfaces this package cannot guess.
- `prerm` stops and disables the units on a removal and does nothing on an
  upgrade.
- `postrm` reloads systemd and removes leftover bpffs pins. The configuration
  and the state survive a removal and go only on `dpkg --purge`; rpm has no
  purge, so `/usr/share/ebpfsentinel/uninstall.sh --purge` is the way there.

## What is deliberately not in the package

- **A sysusers fragment.** Both units run as root, by construction rather
  than by preference: the agent self-unshares a user namespace and maps
  namespace 0 to real root so it can load eBPF through a BPF token, and the
  warden holds the capabilities the kernel will not delegate. A system user
  nothing runs as is configuration that lies about the deployment.
- **The sysctl drop-in**, which is host-wide. It ships in
  `/usr/share/ebpfsentinel/sysctl.d/` and the documentation says when to copy
  it into `/etc/sysctl.d/`. A package widening a host-wide kernel setting
  without being asked is not a package anybody trusts.
- **A `/usr/local` anything**, which is the whole reason this layout exists.
