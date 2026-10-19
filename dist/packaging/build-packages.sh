#!/usr/bin/env bash
# Build the .deb and the .rpm for one architecture.
#
# Run from the release pipeline, which has just built the binaries and the
# eBPF objects from the commit the manifest pins. It is deliberately usable by
# hand too - a maintainer checking what a package contains should not have to
# read a workflow to reproduce it:
#
#   dist/packaging/build-packages.sh \
#     --version 2026.4.1 --arch amd64 \
#     --bin-dir target/x86_64-unknown-linux-musl/release \
#     --ebpf-dir target/bpfel-unknown-none/release \
#     --out-dir dist/out
#
# The one transformation that happens here rather than in nfpm.yaml is the
# unit files: they are written for the tarball, which installs under
# /usr/local, and a package installs under /usr. One copy of each unit is
# rewritten on the way into the staging directory, and the rewrite is checked
# rather than assumed, because a unit still pointing at /usr/local/bin would
# install cleanly and fail at the first start.
set -euo pipefail

PACKAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "${PACKAGING_DIR}")"
SOURCE_ROOT="$(dirname "${DIST_DIR}")"

VERSION=""
ARCH=""
BIN_DIR=""
EBPF_DIR=""
OUT_DIR="${SOURCE_ROOT}/dist/out"

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --ebpf-dir) EBPF_DIR="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for required in VERSION ARCH BIN_DIR EBPF_DIR; do
  if [[ -z "${!required}" ]]; then
    echo "missing --${required,,}" | tr '_' '-' >&2
    exit 2
  fi
done

case "${ARCH}" in
  amd64|arm64) ;;
  *) echo "unsupported architecture '${ARCH}': the release builds amd64 and arm64" >&2; exit 2 ;;
esac

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm is not on PATH; it is what turns the staging directory into a .deb and an .rpm" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

mkdir -p "${STAGE}/ebpf" "${STAGE}/systemd" "${STAGE}/profiles" \
  "${STAGE}/tmpfiles.d" "${STAGE}/apparmor.d" "${STAGE}/sysctl.d" "${OUT_DIR}"

install -m 0755 "${BIN_DIR}/ebpfsentinel-agent" "${STAGE}/ebpfsentinel-agent"
install -m 0755 "${BIN_DIR}/warden" "${STAGE}/warden"
cp "${EBPF_DIR}"/* "${STAGE}/ebpf/"
install -m 0640 "${SOURCE_ROOT}/config/ebpfsentinel.yaml" "${STAGE}/config.yaml"
cp "${SOURCE_ROOT}"/config/profiles/*.yaml "${STAGE}/profiles/"
install -m 0644 "${DIST_DIR}/tmpfiles.d/ebpfsentinel.conf" "${STAGE}/tmpfiles.d/ebpfsentinel.conf"
install -m 0644 "${DIST_DIR}/apparmor.d/ebpfsentinel-agent" "${STAGE}/apparmor.d/ebpfsentinel-agent"
install -m 0644 "${DIST_DIR}/sysctl.d/60-ebpfsentinel-userns.conf" "${STAGE}/sysctl.d/60-ebpfsentinel-userns.conf"
install -m 0755 "${DIST_DIR}/uninstall.sh" "${STAGE}/uninstall.sh"
install -m 0644 "${SOURCE_ROOT}/LICENSE" "${STAGE}/LICENSE"

# The rewrite table. Each line is an exact path the units name and the path
# the package installs it at. `warden` gains the product prefix on the way:
# /usr/bin is shared with every other package on the host, and a binary
# called `warden` there says nothing about who owns it.
rewrite() {
  sed \
    -e 's#/usr/local/bin/ebpfsentinel-agent#/usr/bin/ebpfsentinel-agent#g' \
    -e 's#/usr/local/bin/warden#/usr/bin/ebpfsentinel-warden#g' \
    "$1" > "$2"
}

for unit in ebpfsentinel.service ebpfsentinel-warden.service; do
  rewrite "${DIST_DIR}/${unit}" "${STAGE}/systemd/${unit}"
  if grep -q '/usr/local/' "${STAGE}/systemd/${unit}"; then
    echo "${unit} still names /usr/local after the rewrite:" >&2
    grep -n '/usr/local/' "${STAGE}/systemd/${unit}" >&2
    echo "add the new path to the rewrite table in $(basename "${BASH_SOURCE[0]}")" >&2
    exit 1
  fi
  if ! grep -q '^ExecStart=/usr/bin/' "${STAGE}/systemd/${unit}"; then
    echo "${unit} has no ExecStart under /usr/bin after the rewrite" >&2
    exit 1
  fi
done

export STAGE PACKAGING="${PACKAGING_DIR}" PKG_VERSION="${VERSION}" PKG_ARCH="${ARCH}"

for format in deb rpm; do
  nfpm package --config "${PACKAGING_DIR}/nfpm.yaml" --packager "${format}" --target "${OUT_DIR}"
done

ls -l "${OUT_DIR}"
