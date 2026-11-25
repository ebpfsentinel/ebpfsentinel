#!/usr/bin/env bash
# build.sh <out_dir> - build handoff.bpf.o, the programs perf/13 sets side by
# side, on the machine that will load them and against its own kernel's BTF.
#
# Nothing is fetched: the object needs only vmlinux.h, dumped here from
# /sys/kernel/btf/vmlinux, and helpers.h beside this script. Where bpftool
# leaves the kfunc prototypes out of vmlinux.h (a kernel whose BTF does not
# tag its kfuncs), kfunc-externs.py, copied beside this script from
# ../bpf-qdisc by the suite, declares the ones handoff.bpf.c calls.
#
# Needs: clang (BPF target), bpftool, python3, and a kernel whose BTF carries
# bpf_dynptr_from_skb_meta. Each missing piece is reported on stderr and the
# script exits 2, which the suite turns into a skip naming it.
set -euo pipefail

OUT="${1:?usage: build.sh <out_dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

missing() {
    echo "build.sh: $*" >&2
    exit 2
}

for tool in clang bpftool python3; do
    command -v "$tool" >/dev/null 2>&1 || missing "${tool} not installed"
done

release="$(uname -r)"
mkdir -p "$OUT"
cd "$OUT"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
bpftool -j btf dump file /sys/kernel/btf/vmlinux > btf.json
for kfunc in bpf_dynptr_from_skb_meta bpf_dynptr_slice; do
    grep -q "\"name\":\"${kfunc}\"" btf.json || missing "kernel ${release} has no ${kfunc} in its BTF"
done

cp "${HERE}/handoff.bpf.c" "${HERE}/helpers.h" .

if ! grep -q 'bpf_dynptr_from_skb_meta(' vmlinux.h || ! grep -q 'bpf_dynptr_slice(' vmlinux.h; then
    [ -r "${HERE}/kfunc-externs.py" ] || missing "kfunc-externs.py not beside build.sh"
    {
        echo
        echo "/* kfuncs this BTF carries without a bpf_kfunc tag, declared by kfunc-externs.py */"
        python3 "${HERE}/kfunc-externs.py" btf.json vmlinux.h helpers.h -- handoff.bpf.c
    } >> vmlinux.h
fi
rm -f btf.json

arch="$(uname -m)"
case "$arch" in
    x86_64) target_arch=x86 ;;
    aarch64) target_arch=arm64 ;;
    *) missing "no BPF target arch for ${arch}" ;;
esac

clang -O2 -g -target bpf -D"__TARGET_ARCH_${target_arch}" \
    -I. -I"/usr/include/${arch}-linux-gnu" \
    -c handoff.bpf.c -o handoff.bpf.o

echo "built ${OUT}/handoff.bpf.o against ${release}"
