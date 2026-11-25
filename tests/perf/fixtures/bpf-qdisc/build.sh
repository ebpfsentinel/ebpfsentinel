#!/usr/bin/env bash
# build.sh <out_dir> - build the two BPF qdiscs perf/09 registers, on the
# machine that will load them and against its own kernel.
#
#   fq.bpf.o            the kernel's own bpf_fq selftest (sch_fq written as a
#                       BPF qdisc), fetched at the running kernel's tag and
#                       registered under the name `fq`, so that the agent,
#                       which only stamps departure times where the root
#                       qdisc is fq, stamps for it as it does for sch_fq.
#   bench-shaper.bpf.o  the shaper beside this script, which holds each
#                       cgroup to its rate inside the qdisc, with no tc-qos.
#
# Nothing here is vendored: the selftest and the headers it needs are GPL-2.0
# kernel files, fetched at build time and never committed; libbpf's headers
# come from its release tarball, pinned by digest. The objects stay in
# <out_dir> and are removed with it.
#
# Needs: clang (BPF target), bpftool, python3,
# curl, tar, sha256sum, and a kernel built with CONFIG_NET_SCH_BPF. Each
# missing piece is reported on stderr and the script exits 2, which the suite
# turns into a skip naming it.
set -euo pipefail

OUT="${1:?usage: build.sh <out_dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LIBBPF_VERSION="1.8.0"
LIBBPF_SHA256="b7a1e685f90f6a63ead0dd85d053694b222975da8d09c1a966041cff6f0055ff"
LIBBPF_URL="https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz"
KERNEL_PLAIN="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain"

missing() {
    echo "build.sh: $*" >&2
    exit 2
}

for tool in clang bpftool curl tar sha256sum python3; do
    command -v "$tool" >/dev/null 2>&1 || missing "${tool} not installed"
done

release="$(uname -r)"
config=""
for candidate in "/boot/config-${release}" /proc/config.gz; do
    [ -r "$candidate" ] && { config="$candidate"; break; }
done
[ -n "$config" ] || missing "no kernel configuration readable for ${release}"
if [ "${config%.gz}" != "$config" ]; then
    grep -qx 'CONFIG_NET_SCH_BPF=y' <(zcat "$config") || missing "kernel ${release} built without CONFIG_NET_SCH_BPF"
else
    grep -qx 'CONFIG_NET_SCH_BPF=y' "$config" || missing "kernel ${release} built without CONFIG_NET_SCH_BPF"
fi

# The tag of the kernel line the running release belongs to: 7.0.0-43-generic
# reads as v7.0. A distribution kernel carries its own backports, so the
# override is there for a release whose line has no tag yet.
tag="${KERNEL_TAG:-v$(echo "$release" | awk -F'[.-]' '{print $1"."$2}')}"

mkdir -p "$OUT/include/bpf"
cd "$OUT"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
bpftool -j btf dump file /sys/kernel/btf/vmlinux > btf.json
grep -q '"name":"bpf_qdisc_skb_drop"' btf.json || missing "kernel ${release} has no BPF qdisc kfuncs in its BTF"

curl -fsSL --retry 3 -o libbpf.tar.gz "$LIBBPF_URL"
echo "${LIBBPF_SHA256}  libbpf.tar.gz" | sha256sum -c --quiet - || missing "libbpf ${LIBBPF_VERSION} tarball does not match its pinned digest"
tar xzf libbpf.tar.gz
for header in bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_core_read.h bpf_endian.h; do
    cp "libbpf-${LIBBPF_VERSION}/src/${header}" include/bpf/
done

for path in \
    tools/testing/selftests/bpf/bpf_experimental.h \
    tools/testing/selftests/bpf/progs/bpf_qdisc_common.h \
    tools/testing/selftests/bpf/progs/bpf_qdisc_fq.c; do
    curl -fsSL --retry 3 -o "$(basename "$path")" "${KERNEL_PLAIN}/${path}?h=${tag}" \
        || missing "cannot fetch ${path} at ${tag}"
done

# Registered as `fq`: the name is the only change made to the selftest.
grep -q '\.id[[:space:]]*=[[:space:]]*"bpf_fq"' bpf_qdisc_fq.c || missing "bpf_qdisc_fq.c at ${tag} no longer names itself bpf_fq"
sed 's/\(\.id[[:space:]]*=[[:space:]]*\)"bpf_fq"/\1"fq"/' bpf_qdisc_fq.c > fq.bpf.c

cp "${HERE}/bench-shaper.bpf.c" .

# The selftest includes <errno.h> for its E* constants. libc's header pulls the
# 32-bit stubs under the BPF target, which a 64-bit host does not install; the
# kernel's own list of the constants is all it needs.
printf '#include <asm-generic/errno.h>\n' > include/errno.h

# bpftool writes kfunc prototypes only where the kernel's BTF tags its kfuncs;
# a distribution kernel built without those tags (Ubuntu's 7.0) leaves them
# out, so the ones the sources call are declared from the BTF here.
if ! grep -q 'bpf_qdisc_skb_drop(' vmlinux.h; then
    {
        echo
        echo "/* kfuncs this BTF carries without a bpf_kfunc tag, declared by kfunc-externs.py */"
        python3 "${HERE}/kfunc-externs.py" btf.json vmlinux.h bpf_experimental.h include/bpf/bpf_helper_defs.h \
            -- fq.bpf.c bpf_qdisc_common.h bench-shaper.bpf.c
    } >> vmlinux.h
fi
rm -f btf.json

arch="$(uname -m)"
case "$arch" in
    x86_64) target_arch=x86 ;;
    aarch64) target_arch=arm64 ;;
    *) missing "no BPF target arch for ${arch}" ;;
esac

for name in fq bench-shaper; do
    clang -O2 -g -target bpf -D"__TARGET_ARCH_${target_arch}" \
        -I. -Iinclude -I"/usr/include/${arch}-linux-gnu" \
        -c "${name}.bpf.c" -o "${name}.bpf.o"
done

echo "built ${OUT}/fq.bpf.o and ${OUT}/bench-shaper.bpf.o against ${release} (selftest at ${tag})"
