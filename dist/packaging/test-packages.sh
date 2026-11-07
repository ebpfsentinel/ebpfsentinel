#!/usr/bin/env bash
# Install, upgrade, remove and purge the .deb, the .rpm and the tarball on
# clean hosts.
#
# The packages are built here, twice, by build-packages.sh: a first version
# from the tree as it is, and a second one whose reference configuration
# changed, because that is the upgrade an operator meets - a release that
# moved the reference while their own copy carries their rules. Each format is
# then driven through its whole life in a throwaway container of a
# distribution that installs it, and every step asserts what the
# documentation promises rather than that the package manager exited 0.
#
#   dist/packaging/test-packages.sh \
#     --bin-dir target/release \
#     --ebpf-dir target/bpfel-unknown-none/release
#
# Needs nfpm, docker and readelf. amd64 only: the containers run the
# binaries the packages carry. --require-static fails a dynamically linked
# agent, which is what the release passes: its packages declare no library.
#
# No unit is ever started: a container has no booted systemd, and the agent
# would load its programs into the kernel the test runs on. What systemctl
# does offline - enabling, disabling, reading what is enabled - is asserted.
set -euo pipefail

PACKAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "${PACKAGING_DIR}")"
SOURCE_ROOT="$(dirname "${DIST_DIR}")"

DEB_IMAGE="${DEB_IMAGE:-ubuntu:24.04}"
RPM_IMAGE="${RPM_IMAGE:-fedora:43}"
V1=0.0.1
V2=0.0.2

FAILURES=0

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "ok: $*"
}

check() {
  local what="$1"
  shift
  if "$@"; then pass "${what}"; else fail "${what}"; fi
}

mode_of() {
  stat -c '%a' "$1" 2>/dev/null
}

# ── Inside a container ──────────────────────────────────────────────

installed_files_are_in_place() {
  check "the agent is at /usr/bin, mode 0755" [ "$(mode_of /usr/bin/ebpfsentinel-agent)" = 755 ]
  check "the warden is at /usr/bin under the product name" [ "$(mode_of /usr/bin/ebpfsentinel-warden)" = 755 ]
  # The packages declare systemd as their only dependency because the release
  # binaries are static; a development build linked against the host's
  # libraries cannot run here, and says nothing about the release.
  if [ "$(cat /pkgs/linkage)" = static ]; then
    check "the agent runs on this distribution" /usr/bin/ebpfsentinel-agent --version
    check "the warden runs on this distribution" sh -c '/usr/bin/ebpfsentinel-warden 2>&1 | grep -q usage'
  else
    echo "skip: the binaries are dynamically linked, so whether they run here is not a property of the package"
  fi
  local obj missing=0
  while read -r obj; do
    [ -f "/usr/lib/ebpfsentinel/${obj}" ] || { echo "  missing /usr/lib/ebpfsentinel/${obj}" >&2; missing=1; }
  done </pkgs/ebpf-objects
  check "every eBPF object is under /usr/lib/ebpfsentinel" [ "${missing}" = 0 ]
  check "the configuration is mode 0640" [ "$(mode_of /etc/ebpfsentinel/config.yaml)" = 640 ]
  check "the three host profiles are shipped" [ "$(find /usr/share/ebpfsentinel/profiles -name '*.yaml' | wc -l)" -ge 3 ]
  check "the tmpfiles drop-in is installed" [ -f /usr/lib/tmpfiles.d/ebpfsentinel.conf ]
  check "the AppArmor profile is installed" [ -f /etc/apparmor.d/ebpfsentinel-agent ]
  check "the userns sysctl is shipped, not applied" \
    sh -c '[ -f /usr/share/ebpfsentinel/sysctl.d/60-ebpfsentinel-userns.conf ] && [ ! -e /etc/sysctl.d/60-ebpfsentinel-userns.conf ]'
  check "the uninstall script is shipped" [ -x /usr/share/ebpfsentinel/uninstall.sh ]
  check "the state directory exists with auth/ at 0700" [ "$(mode_of /var/lib/ebpfsentinel/auth)" = 700 ]

  local unit exe
  for unit in ebpfsentinel.service ebpfsentinel-warden.service; do
    check "${unit} is installed" [ -f "/usr/lib/systemd/system/${unit}" ]
    exe="$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "/usr/lib/systemd/system/${unit}")"
    check "${unit} starts ${exe}, which the package installed" [ -x "${exe}" ]
    check "${unit} names nothing under /usr/local" sh -c "! grep -q /usr/local/ /usr/lib/systemd/system/${unit}"
  done
}

units_enabled() {
  [ -e /etc/systemd/system/multi-user.target.wants/ebpfsentinel.service ] &&
    [ -e /etc/systemd/system/multi-user.target.wants/ebpfsentinel-warden.service ]
}

units_not_enabled() {
  [ ! -e /etc/systemd/system/multi-user.target.wants/ebpfsentinel.service ] &&
    [ ! -e /etc/systemd/system/multi-user.target.wants/ebpfsentinel-warden.service ]
}

# The operator's copy: their rules, and a key file the agent drew at first start.
operator_configures() {
  echo "# operator rule kept across upgrades" >>/etc/ebpfsentinel/config.yaml
  printf 'drawn-at-first-start\n' >/var/lib/ebpfsentinel/auth/api-key
  systemctl enable ebpfsentinel-warden.service ebpfsentinel.service >/dev/null 2>&1
  check "the operator could enable both units" units_enabled
}

kept_operator_config() {
  grep -q '^# operator rule kept across upgrades' /etc/ebpfsentinel/config.yaml
}

refused_below_the_floor() {
  local install_cmd="$1"
  local message="${2:-6.12 or newer is required, this host runs 6.11}"
  # rpm runs a scriptlet with its own PATH whatever the caller's, and Fedora
  # merged /usr/sbin into /usr/bin, so the shim takes the real binary's place
  # for the one install and hands it back after.
  mv /usr/bin/uname /usr/bin/uname.real
  cat >/usr/bin/uname <<'SHIM'
#!/bin/sh
[ "${1:-}" = -r ] && { echo 6.11.0-29-generic; exit 0; }
exec /usr/bin/uname.real "$@"
SHIM
  chmod 0755 /usr/bin/uname
  # dnf cuts a scriptlet's lines at eighty columns, so the release is matched
  # by its start.
  local out rc=0
  out="$(sh -c "${install_cmd}" 2>&1)" || rc=$?
  mv /usr/bin/uname.real /usr/bin/uname
  check "an install on a 6.11 kernel fails" [ "${rc}" -ne 0 ]
  check "the refusal names the 6.12 floor and the running release" \
    sh -c 'printf "%s" "$1" | grep -qF "$2"' _ "${out}" "${message}"
  check "nothing of the refused install is left" sh -c '[ ! -e /usr/bin/ebpfsentinel-agent ] && [ ! -e /usr/local/bin/ebpfsentinel-agent ]'
}

inside_deb() {
  export DEBIAN_FRONTEND=noninteractive
  local apt=(apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get update -q >/dev/null
  # The dependency comes from the archive, as on a real host.
  "${apt[@]}" install --no-install-recommends ca-certificates >/dev/null

  echo "# deb: refused below the floor"
  refused_below_the_floor "apt-get -y -q install --no-install-recommends /pkgs/v1/ebpfsentinel_${V1}_amd64.deb"
  check "dpkg does not count it as installed" \
    sh -c "! dpkg-query -W -f='\${Status}' ebpfsentinel 2>/dev/null | grep -q 'install ok installed'"

  echo "# deb: install"
  "${apt[@]}" install --no-install-recommends "/pkgs/v1/ebpfsentinel_${V1}_amd64.deb" >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "apt-get install"; return; }
  check "dpkg reports ${V1}" [ "$(dpkg-query -W -f='${Version}' ebpfsentinel)" = "${V1}" ]
  check "the install says nothing is running yet" grep -q 'Nothing is running yet' /tmp/install.log
  installed_files_are_in_place
  check "installing enabled nothing" units_not_enabled

  echo "# deb: uninstall script on a packaged host"
  local out
  out="$(/usr/share/ebpfsentinel/uninstall.sh --purge 2>&1)" || fail "uninstall.sh exited non-zero"
  check "it names apt-get rather than deleting packaged files" \
    sh -c 'printf "%s" "$1" | grep -q "apt-get remove ebpfsentinel"' _ "${out}"
  # The image excludes /usr/share/doc through dpkg's path-exclude, so the
  # licence is missing from the start; every other file is counted.
  check "dpkg still finds every file it installed" \
    sh -c '! dpkg --verify ebpfsentinel 2>&1 | grep missing | grep -vq /usr/share/doc/'
  check "the binaries are still there" [ -x /usr/bin/ebpfsentinel-agent ]
  check "it leaves the packaged configuration where dpkg put it" [ -f /etc/ebpfsentinel/config.yaml ]
  check "it leaves the state for the purge to remove" [ -d /var/lib/ebpfsentinel/auth ]

  echo "# deb: upgrade over an operator's configuration"
  operator_configures
  "${apt[@]}" install --no-install-recommends "/pkgs/v2/ebpfsentinel_${V2}_amd64.deb" >/tmp/upgrade.log 2>&1 || { cat /tmp/upgrade.log; fail "apt-get upgrade"; return; }
  check "dpkg reports ${V2}" [ "$(dpkg-query -W -f='${Version}' ebpfsentinel)" = "${V2}" ]
  check "the operator's configuration is kept" kept_operator_config
  check "the new reference is set beside it as .dpkg-dist" grep -q '^# reference changed in this release' /etc/ebpfsentinel/config.yaml.dpkg-dist
  check "the stored key survives" [ -f /var/lib/ebpfsentinel/auth/api-key ]
  check "the units the operator enabled stay enabled" units_enabled
  check "an upgrade prints no first-install message" sh -c '! grep -q "Nothing is running yet" /tmp/upgrade.log'
  installed_files_are_in_place

  echo "# deb: remove"
  "${apt[@]}" remove ebpfsentinel >/dev/null 2>&1 || fail "apt-get remove"
  check "the binaries are gone" [ ! -e /usr/bin/ebpfsentinel-agent ]
  check "the eBPF objects are gone" [ ! -e /usr/lib/ebpfsentinel ]
  check "the units are gone" [ ! -e /usr/lib/systemd/system/ebpfsentinel.service ]
  check "the units were disabled, no dangling link left" units_not_enabled
  check "the configuration is kept" kept_operator_config
  check "the state and the key are kept" [ -f /var/lib/ebpfsentinel/auth/api-key ]
  check "dpkg keeps it as config-files" [ "$(dpkg-query -W -f='${db:Status-Status}' ebpfsentinel)" = config-files ]

  echo "# deb: purge"
  "${apt[@]}" purge ebpfsentinel >/dev/null 2>&1 || fail "apt-get purge"
  check "the configuration directory is gone" [ ! -e /etc/ebpfsentinel ]
  check "the state directory is gone" [ ! -e /var/lib/ebpfsentinel ]
  check "dpkg no longer knows the package" sh -c '! dpkg-query -W ebpfsentinel >/dev/null 2>&1'
}

inside_rpm() {
  local dnf=(dnf -y -q --setopt=install_weak_deps=False)

  echo "# rpm: refused below the floor"
  refused_below_the_floor "dnf -y -q --setopt=install_weak_deps=False install /pkgs/v1/ebpfsentinel-${V1}-1.x86_64.rpm"
  check "rpm does not count it as installed" sh -c '! rpm -q ebpfsentinel >/dev/null 2>&1'

  echo "# rpm: install"
  "${dnf[@]}" install "/pkgs/v1/ebpfsentinel-${V1}-1.x86_64.rpm" >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "dnf install"; return; }
  check "rpm reports ${V1}" [ "$(rpm -q --qf '%{VERSION}' ebpfsentinel)" = "${V1}" ]
  installed_files_are_in_place
  check "installing enabled nothing" units_not_enabled

  echo "# rpm: uninstall script on a packaged host"
  local out
  out="$(/usr/share/ebpfsentinel/uninstall.sh --purge 2>&1)" || fail "uninstall.sh exited non-zero"
  check "it names dnf rather than deleting packaged files" \
    sh -c 'printf "%s" "$1" | grep -q "dnf remove ebpfsentinel"' _ "${out}"
  check "rpm still finds every file it installed" sh -c '! rpm -V ebpfsentinel 2>&1 | grep -q missing'
  check "it says what removes the state after the erase" \
    sh -c 'printf "%s" "$1" | grep -q "rm -rf /etc/ebpfsentinel /var/lib/ebpfsentinel"' _ "${out}"

  echo "# rpm: upgrade over an operator's configuration"
  operator_configures
  "${dnf[@]}" install "/pkgs/v2/ebpfsentinel-${V2}-1.x86_64.rpm" >/tmp/upgrade.log 2>&1 || { cat /tmp/upgrade.log; fail "dnf upgrade"; return; }
  check "rpm reports ${V2}" [ "$(rpm -q --qf '%{VERSION}' ebpfsentinel)" = "${V2}" ]
  check "the operator's configuration is kept" kept_operator_config
  check "the new reference is set beside it as .rpmnew" grep -q '^# reference changed in this release' /etc/ebpfsentinel/config.yaml.rpmnew
  check "the stored key survives" [ -f /var/lib/ebpfsentinel/auth/api-key ]
  check "the units the operator enabled stay enabled" units_enabled
  installed_files_are_in_place

  echo "# rpm: erase"
  "${dnf[@]}" remove ebpfsentinel >/tmp/erase.log 2>&1 || fail "dnf remove"
  check "the binaries are gone" [ ! -e /usr/bin/ebpfsentinel-agent ]
  check "the units are gone" [ ! -e /usr/lib/systemd/system/ebpfsentinel.service ]
  check "the units were disabled, no dangling link left" units_not_enabled
  check "the state and the key are kept" [ -f /var/lib/ebpfsentinel/auth/api-key ]
  check "the erase says the state is left in place" grep -q 'is left in place' /tmp/erase.log
  check "the operator's configuration is saved as .rpmsave" grep -q '^# operator rule kept across upgrades' /etc/ebpfsentinel/config.yaml.rpmsave
}

# The tarball has no package manager behind it, so install.sh and
# uninstall.sh are the whole of its life, and what --purge leaves is what an
# administrator finds later and cannot attribute.
inside_tarball() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null
  apt-get -y -q install --no-install-recommends systemd >/dev/null
  # Without a booted systemd, daemon-reload is the one call that cannot run
  # here; everything else systemctl does offline.
  mv /usr/bin/systemctl /usr/bin/systemctl.real
  cat >/usr/bin/systemctl <<'SHIM'
#!/bin/sh
[ "${1:-}" = daemon-reload ] && exit 0
exec /usr/bin/systemctl.real "$@"
SHIM
  chmod 0755 /usr/bin/systemctl
  local dir=/pkgs/tarball

  echo "# tarball: refused below the floor"
  refused_below_the_floor "${dir}/install.sh" "kernel >= 6.12 is required (found 6.11"

  echo "# tarball: install"
  "${dir}/install.sh" >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "install.sh"; return; }
  check "the agent is at /usr/local/bin" [ -x /usr/local/bin/ebpfsentinel-agent ]
  check "the eBPF objects are under /usr/local/lib/ebpfsentinel" [ -n "$(ls -A /usr/local/lib/ebpfsentinel)" ]
  check "the uninstall script is installed where install.sh says" [ -x /usr/local/share/ebpfsentinel/uninstall.sh ]
  check "the configuration is mode 0640" [ "$(mode_of /etc/ebpfsentinel/config.yaml)" = 640 ]
  check "auth/ is 0700" [ "$(mode_of /var/lib/ebpfsentinel/auth)" = 700 ]
  operator_configures

  echo "# tarball: uninstall --purge"
  /usr/local/share/ebpfsentinel/uninstall.sh --purge >/tmp/uninstall.log 2>&1 || { cat /tmp/uninstall.log; fail "uninstall.sh --purge"; }
  local left
  left="$(ls -d /usr/local/bin/ebpfsentinel-agent /usr/local/bin/warden /usr/local/lib/ebpfsentinel \
    /usr/local/share/ebpfsentinel /etc/ebpfsentinel /var/lib/ebpfsentinel \
    /etc/systemd/system/ebpfsentinel.service /etc/systemd/system/ebpfsentinel-warden.service 2>/dev/null || true)"
  check "nothing install.sh wrote is left${left:+ (left: ${left//$'\n'/ })}" [ -z "${left}" ]
  check "the units were disabled, no dangling link left" units_not_enabled
}

# ── On the host ─────────────────────────────────────────────────────

BIN_DIR=""
EBPF_DIR=""
INSIDE=""
REQUIRE_STATIC=no

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --ebpf-dir) EBPF_DIR="$2"; shift 2 ;;
    --inside) INSIDE="$2"; shift 2 ;;
    --require-static) REQUIRE_STATIC=yes; shift ;;
    -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "${INSIDE}" ]]; then
  case "${INSIDE}" in
    deb) inside_deb ;;
    rpm) inside_rpm ;;
    tarball) inside_tarball ;;
    *) echo "unknown format ${INSIDE}" >&2; exit 2 ;;
  esac
  [[ "${FAILURES}" -eq 0 ]] || { echo "${FAILURES} check(s) failed in the ${INSIDE} container" >&2; exit 1; }
  exit 0
fi

for required in BIN_DIR EBPF_DIR; do
  [[ -n "${!required}" ]] || { echo "missing --${required,,}" | tr '_' '-' >&2; exit 2; }
done
BIN_DIR="$(cd "${BIN_DIR}" && pwd)"
EBPF_DIR="$(cd "${EBPF_DIR}" && pwd)"
command -v docker >/dev/null 2>&1 || { echo "docker is not on PATH" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# The second version is built from a copy of the tree whose reference
# configuration gained a line, so the upgrade meets a conffile that changed on
# both sides.
TREE2="${WORK}/tree2"
mkdir -p "${TREE2}"
cp -a "${DIST_DIR}" "${TREE2}/dist"
cp -a "${SOURCE_ROOT}/config" "${TREE2}/config"
cp "${SOURCE_ROOT}/LICENSE" "${TREE2}/LICENSE"
echo "# reference changed in this release" >>"${TREE2}/config/ebpfsentinel.yaml"

"${PACKAGING_DIR}/build-packages.sh" --version "${V1}" --arch amd64 \
  --bin-dir "${BIN_DIR}" --ebpf-dir "${EBPF_DIR}" --out-dir "${WORK}/pkgs/v1" >/dev/null
"${TREE2}/dist/packaging/build-packages.sh" --version "${V2}" --arch amd64 \
  --bin-dir "${BIN_DIR}" --ebpf-dir "${EBPF_DIR}" --out-dir "${WORK}/pkgs/v2" >/dev/null
(cd "${EBPF_DIR}" && ls -1) >"${WORK}/pkgs/ebpf-objects"
if readelf -lW "${BIN_DIR}/ebpfsentinel-agent" | grep -q 'Requesting program interpreter'; then
  echo dynamic >"${WORK}/pkgs/linkage"
  [[ "${REQUIRE_STATIC}" == yes ]] && fail "the agent in ${BIN_DIR} is dynamically linked, the packages declare no library"
else
  echo static >"${WORK}/pkgs/linkage"
fi

# The tarball's layout, as the release stages it.
T="${WORK}/pkgs/tarball"
mkdir -p "${T}/ebpf"
cp "${BIN_DIR}/ebpfsentinel-agent" "${BIN_DIR}/warden" "${T}/"
cp "${SOURCE_ROOT}/config/ebpfsentinel.yaml" "${DIST_DIR}/ebpfsentinel-warden.service" \
  "${DIST_DIR}/ebpfsentinel.service" "${DIST_DIR}/install.sh" "${DIST_DIR}/uninstall.sh" \
  "${SOURCE_ROOT}/LICENSE" "${T}/"
cp -a "${DIST_DIR}/apparmor.d" "${DIST_DIR}/sysctl.d" "${SOURCE_ROOT}/config/profiles" "${T}/"
cp "${EBPF_DIR}"/* "${T}/ebpf/"

# The names the installation documentation tells a reader to download.
for name in "v1/ebpfsentinel_${V1}_amd64.deb" "v1/ebpfsentinel-${V1}-1.x86_64.rpm"; do
  if [[ -f "${WORK}/pkgs/${name}" ]]; then pass "built ${name##*/}"; else fail "no ${name##*/} among: $(ls "${WORK}/pkgs/v1")"; fi
done

chmod -R a+rX "${WORK}/pkgs"
for format in deb rpm tarball; do
  image="${DEB_IMAGE}"
  [[ "${format}" == rpm ]] && image="${RPM_IMAGE}"
  echo "== ${format} on ${image}"
  if ! docker run --rm \
      -v "${WORK}/pkgs:/pkgs:ro" \
      -v "${PACKAGING_DIR}/test-packages.sh:/test-packages.sh:ro" \
      "${image}" bash /test-packages.sh --inside "${format}"; then
    fail "the ${format} lifecycle"
  fi
done

if [[ "${FAILURES}" -ne 0 ]]; then
  echo "${FAILURES} failure(s)" >&2
  exit 1
fi
echo "every package check passed"
