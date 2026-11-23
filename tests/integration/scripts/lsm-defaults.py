#!/usr/bin/env python3
"""Read the LSM list each supported distribution's kernel boots with.

A kernel started without `lsm=` on its command line initialises the LSMs named
in its build's CONFIG_LSM, in that order. This script fetches the kernel
configuration each distribution builds from (its packaging repository, or the
kernel package itself where the configuration is not published apart) and
prints CONFIG_LSM and whether `bpf` is in it. NixOS sets `lsm=` from its
`security.lsm` option, so its module is read instead.

What it does not see: an image or a host provider adding `lsm=` to the command
line. `ebpfsentinel-agent ebpf host-check` answers for a running host.

Usage: python3 -I tests/integration/scripts/lsm-defaults.py
Needs network access and `zstd` for packages compressed with it.
"""

import gzip
import lzma
import re
import struct
import subprocess
import sys
import urllib.request
import zlib

SOURCES = [
    ("Ubuntu 26.04 and 24.04 HWE (generic)", "ubuntu", "generic"),
    ("Ubuntu 26.04 on Azure, the AKS node image (azure)", "ubuntu", "azure"),
    ("Debian 13 backports (follows unstable)", "config",
     "https://salsa.debian.org/kernel-team/linux/-/raw/debian/latest/debian/config/config"),
    ("Fedora", "config",
     "https://gitlab.com/cki-project/kernel-ark/-/raw/os-build/redhat/configs/fedora/generic/CONFIG_LSM"),
    ("openSUSE Tumbleweed", "config",
     "https://raw.githubusercontent.com/SUSE/kernel-source/master/config/x86_64/default"),
    ("Arch Linux", "config",
     "https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config.x86_64"),
    ("Alpine linux-lts", "config",
     "https://gitlab.alpinelinux.org/alpine/aports/-/raw/master/main/linux-lts/lts.x86_64.config"),
    ("NixOS (security.lsm)", "nixos",
     "https://raw.githubusercontent.com/NixOS/nixpkgs/release-26.05/nixos/modules/security/default.nix"),
    ("Talos", "config",
     "https://raw.githubusercontent.com/siderolabs/pkgs/main/kernel/build/config-amd64"),
    ("Flatcar 6.18", "config",
     "https://raw.githubusercontent.com/flatcar/scripts/main/sdk_container/src/third_party/coreos-overlay/sys-kernel/coreos-modules/files/commonconfig-6.18"),
    ("Bottlerocket 6.18", "config",
     "https://raw.githubusercontent.com/bottlerocket-os/bottlerocket-kernel-kit/develop/packages/kernel-6.18/config-full-bottlerocket-x86_64-on-x86_64"),
    ("Amazon Linux 2023 kernel6.18", "al2023", None),
]

UBUNTU = "http://archive.ubuntu.com/ubuntu"
AL2023_MIRROR = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(request, timeout=300) as r:
        return r.read()


def lsm_of_config(text):
    m = re.search(r'^CONFIG_LSM="([^"]*)"', text, re.M)
    return m.group(1) if m else None


def lsm_of_nixos(text):
    # The module appends bpf after every LSM another module adds to the list.
    if 'mkAfter [ "bpf" ]' in text:
        return "landlock,yama,bpf"
    return None


def al2023_config():
    base = get(AL2023_MIRROR).decode().split()[0].rstrip("/")
    repomd = get(f"{base}/repodata/repomd.xml").decode()
    primary = re.search(r'<data type="primary">.*?href="([^"]+)"', repomd, re.S).group(1)
    xml = gzip.decompress(get(f"{base}/{primary}")).decode()
    hrefs = re.findall(r'href="([^"]*kernel6\.18-devel-[^"]*\.x86_64\.rpm)"', xml)
    href = sorted(hrefs, key=lambda h: [int(x) for x in re.findall(r"\d+", h.split("devel-")[1])])[-1]
    url = urllib.request.urljoin(base + "/", href)
    return url.rsplit("/", 1)[1], rpm_member(get(url), "/.config").decode()


def ubuntu_config(flavour):
    """The configuration shipped in the newest resolute-updates headers package
    of a flavour: the kernel Ubuntu installs, not its packaging tree."""
    index = lzma.decompress(get(f"{UBUNTU}/dists/resolute-updates/main/binary-amd64/Packages.xz")).decode()
    found = []
    for stanza in index.split("\n\n"):
        m = re.search(rf"^Package: linux-headers-([0-9.]+)-([0-9]+)-{flavour}$", stanza, re.M)
        if m:
            key = [int(x) for x in m.group(1).split(".")] + [int(m.group(2))]
            found.append((key, re.search(r"^Filename: (.*)$", stanza, re.M).group(1)))
    path = max(found)[1]
    return path.rsplit("/", 1)[1], deb_member(get(f"{UBUNTU}/{path}"), "/.config").decode()


def deb_member(deb, suffix):
    import io
    import tarfile
    assert deb[:8] == b"!<arch>\n"
    o = 8
    while o < len(deb):
        name = deb[o:o + 16].decode().strip().rstrip("/")
        size = int(deb[o + 48:o + 58])
        body = deb[o + 60:o + 60 + size]
        o = o + 60 + size + (size & 1)
        if name.startswith("data.tar"):
            if name.endswith(".zst"):
                body = subprocess.run(["zstd", "-dc"], input=body, capture_output=True, check=True).stdout
            elif name.endswith(".xz"):
                body = lzma.decompress(body)
            with tarfile.open(fileobj=io.BytesIO(body)) as tar:
                for member in tar:
                    if member.name.endswith(suffix) and member.isfile():
                        return tar.extractfile(member).read()
    raise LookupError(suffix)


def rpm_member(rpm, suffix):
    def header_end(o):
        assert rpm[o:o + 3] == b"\x8e\xad\xe8"
        n, s = struct.unpack(">II", rpm[o + 8:o + 16])
        return o + 16 + 16 * n + s
    o = header_end(96)
    o = header_end((o + 7) // 8 * 8)
    payload = rpm[o:]
    if payload[:6] == b"\xfd7zXZ\x00":
        cpio = lzma.decompress(payload)
    elif payload[:4] == b"\x28\xb5\x2f\xfd":
        cpio = subprocess.run(["zstd", "-dc"], input=payload, capture_output=True, check=True).stdout
    else:
        cpio = zlib.decompress(payload, 31)
    i = 0
    while i < len(cpio):
        fields = [int(cpio[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        size, namesize = fields[6], fields[11]
        name = cpio[i + 110:i + 110 + namesize - 1].decode()
        j = (i + 110 + namesize + 3) // 4 * 4
        if name == "TRAILER!!!":
            break
        if name.endswith(suffix):
            return cpio[j:j + size]
        i = (j + size + 3) // 4 * 4
    raise LookupError(suffix)


def main():
    failed = False
    for name, kind, url in SOURCES:
        try:
            if kind == "ubuntu":
                pkg, text = ubuntu_config(url)
                lsm, where = lsm_of_config(text), pkg
            elif kind == "al2023":
                pkg, text = al2023_config()
                lsm, where = lsm_of_config(text), pkg
            elif kind == "nixos":
                lsm, where = lsm_of_nixos(get(url).decode()), url
            else:
                lsm, where = lsm_of_config(get(url).decode()), url
        except Exception as e:  # one source failing leaves the others readable
            print(f"{name}: unreadable ({e})")
            failed = True
            continue
        has = lsm is not None and "bpf" in lsm.split(",")
        print(f"{name}: bpf {'yes' if has else 'no'}  [{lsm}]  {where}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
