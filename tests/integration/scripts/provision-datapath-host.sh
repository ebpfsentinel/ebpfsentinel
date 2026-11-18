#!/usr/bin/env bash
# provision-datapath-host.sh - install what the single-host datapath suites
# drive their traffic and workloads with.
#
# One list for every machine that runs those suites: the agent VM's
# base-packages provisioner calls it, and so does the CI datapath lane on a
# hosted runner. A tool added for a suite goes here once and reaches both, so
# the strict lane never fails on a machine provisioned from a different list.
#
# Usage: provision-datapath-host.sh [--require-bpftool]
#
#   --require-bpftool  fail when no bpftool installs. The CI lane passes it:
#                      the kernel there is final. The VM omits it, because
#                      its next provisioner replaces the kernel and pulls the
#                      matching tools.
#
# Runs as root.

set -euo pipefail

REQUIRE_BPFTOOL=0
for arg in "$@"; do
    case "$arg" in
        --require-bpftool) REQUIRE_BPFTOOL=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "provision-datapath-host.sh runs as root" >&2
    exit 2
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev libpcap-dev protobuf-compiler llvm-dev \
    iproute2 iptables nftables tcpdump curl wget jq git \
    ca-certificates openssl \
    iperf3 hping3 ncat nmap stress-ng bc \
    wrk tshark dnsutils \
    hydra \
    conntrack \
    util-linux busybox-static \
    python3 python3-yaml python3-jwt python3-cryptography python3-venv python3-pip \
    plocate sqlite3 ffmpeg logrotate rsync zstd samba smbclient
# plocate, sqlite3, ffmpeg, logrotate, rsync and zstd are the ordinary
# workloads the mass encryption verdict and the write refusal must stay quiet
# through: an index rebuild, a database compaction, a media encoder, log
# rotation, a mirror and a compressed backup.
# Samba is the file service a client in the test namespace writes through; the
# suite starts its own smbd, so the packaged one stays off.
systemctl disable --now smbd nmbd samba-ad-dc 2>/dev/null || true

# Real-client tools of the netns scenario suites: dnsperf (19 DNS load), t50
# (22 multi-protocol flood), swaks/lftp (56 L7 SMTP/FTP), ncrack/sshpass (59 SSH
# brute force). Not every mirror carries each one, so a miss is reported here
# and the strict lane then fails the suite that needs it, by name.
for optpkg in dnsperf t50 swaks lftp ncrack sshpass; do
    apt-get install -y --no-install-recommends "$optpkg" \
        || echo "  (tool '$optpkg' unavailable in this archive)"
done

# Headers for the running kernel where the archive has them. A mainline kernel
# has none there; nothing here builds against them.
apt-get install -y --no-install-recommends "linux-headers-$(uname -r)" \
    || echo "  (no headers for $(uname -r) in the archive)"

# bpftool: the distribution package is built against no particular kernel, so
# it installs where `uname -r` has no matching linux-tools; the per-kernel
# packages stay as fallbacks for an image that ships them.
apt-get install -y --no-install-recommends bpftool 2>/dev/null \
    || apt-get install -y --no-install-recommends "linux-tools-$(uname -r)" 2>/dev/null \
    || apt-get install -y --no-install-recommends linux-tools-common linux-tools-generic 2>/dev/null \
    || true
if [ "$REQUIRE_BPFTOOL" = "1" ] && ! bpftool version >/dev/null 2>&1; then
    echo "bpftool did not install for kernel $(uname -r)" >&2
    exit 1
fi

# The conntrack, FOU and xfrm-interface kfuncs are registered by modules a
# fresh host does not load by itself, and a program calling one is refused
# without its module.
cat > /etc/modules-load.d/ebpfsentinel-kfuncs.conf <<'KMODS'
nf_conntrack
fou
fou6
xfrm_interface
KMODS
for kmod in nf_conntrack fou fou6 xfrm_interface; do
    modprobe "$kmod" 2>/dev/null || echo "  (modprobe ${kmod} deferred until reboot)"
done

# Scapy at the version the suites were written against, outside the system
# Python so the distribution's own copy cannot shadow it.
if ! /opt/scapy-venv/bin/python3 -c 'import scapy.all' 2>/dev/null; then
    python3 -m venv /opt/scapy-venv
    /opt/scapy-venv/bin/pip install --quiet --upgrade pip
    /opt/scapy-venv/bin/pip install --quiet "scapy==2.7.0"
fi

systemctl enable --now iperf3 2>/dev/null || iperf3 -s -D

# OpenSSL 3.5 beside the distribution's, for the X25519MLKEM768 handshakes:
# the distribution's predates ML-KEM, and a suite reading the post-quantum
# posture needs both ends to offer it. Built static under /opt, so nothing
# on the host links against it; the suites pick it up by path. A host
# provisioned here claims `openssl-mlkem` (tests/integration/skip-policy.yaml),
# so a build that fails stops the provisioning rather than a suite skipping.
OPENSSL_PQ_VERSION="3.5.4"
OPENSSL_PQ_SHA256="967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99"
OPENSSL_PQ_PREFIX="/opt/openssl-3.5"
if ! "${OPENSSL_PQ_PREFIX}/bin/openssl" list -kem-algorithms 2>/dev/null | grep -qi mlkem768; then
    apt-get install -y --no-install-recommends perl
    ossl_tmp="$(mktemp -d)"
    curl -fsSL --retry 3 -o "${ossl_tmp}/openssl.tar.gz" \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_PQ_VERSION}/openssl-${OPENSSL_PQ_VERSION}.tar.gz"
    echo "${OPENSSL_PQ_SHA256}  ${ossl_tmp}/openssl.tar.gz" | sha256sum -c -
    tar -xzf "${ossl_tmp}/openssl.tar.gz" -C "${ossl_tmp}"
    (
        cd "${ossl_tmp}/openssl-${OPENSSL_PQ_VERSION}"
        ./Configure --prefix="${OPENSSL_PQ_PREFIX}" \
            --openssldir="${OPENSSL_PQ_PREFIX}/ssl" no-shared no-docs >/dev/null
        make -j"$(nproc)" >/dev/null
        make install_sw >/dev/null
    )
    rm -rf "${ossl_tmp}"
    "${OPENSSL_PQ_PREFIX}/bin/openssl" list -kem-algorithms | grep -qi mlkem768 || {
        echo "OpenSSL ${OPENSSL_PQ_VERSION} installed without ML-KEM" >&2
        exit 1
    }
fi

# Ubuntu refuses unprivileged user namespaces through AppArmor by default,
# before seccomp or the agent's own token is consulted; the rootless suites
# create one. A host provisioned here claims `userns`.
cat > /etc/sysctl.d/99-ebpfsentinel.conf <<'SYSCTL'
net.core.bpf_jit_enable=1
kernel.perf_event_paranoid=-1
kernel.apparmor_restrict_unprivileged_userns=0
SYSCTL
sysctl --system >/dev/null
if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" != "0" ]; then
    echo "kernel.apparmor_restrict_unprivileged_userns stayed on" >&2
    exit 1
fi

cat > /etc/security/limits.d/99-ebpfsentinel.conf <<'LIMITS'
*  soft  memlock  unlimited
*  hard  memlock  unlimited
LIMITS

echo "datapath host provisioned on kernel $(uname -r)"
