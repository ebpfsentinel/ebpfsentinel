#!/usr/bin/env bash
# run-in-floor-vm.sh - run a command under a kernel at the agent's floor,
# booted with virtme-ng (vng) on the machine this runs on.
#
# A GitHub-hosted runner boots whatever kernel its image ships, and the agent
# refuses to start below its floor (6.18, kernels.toml `floor`, held to
# crates/adapters/src/ebpf/kernel_probe.rs by check-kernel-matrix.py). Every
# hosted job that starts the agent therefore runs its suites through this
# script: vng boots the newest kernel.ubuntu.com/mainline build of the floor
# release under KVM, with the host's root filesystem as the guest's root, so
# what the job installed on the host (bats, grpcurl, the provisioned tools, the
# agent build, the eBPF objects, certificates and keys) is already there.
#
# Usage:
#   run-in-floor-vm.sh floor
#       Print the floor release kernels.toml states.
#   run-in-floor-vm.sh resolve [--kernel <release>]
#       Print the mainline build the floor (or <release>) resolves to, through
#       check-kernel-matrix.py --resolve. Only releases listed in kernels.toml
#       resolve; the list is never repeated here.
#   run-in-floor-vm.sh setup
#       Install what vng needs (qemu, virtiofsd, busybox, virtme-ng pinned in
#       a venv under /opt/virtme-ng) and open /dev/kvm to the runner user.
#   run-in-floor-vm.sh run [options] -- <command> [args...]
#       Boot the kernel and run <command> as root inside it, then exit with its
#       status. Options:
#         --kernel <release>  boot this kernels.toml release instead of the floor
#         --as <user>         run the command as <user> instead of root
#         --docker            start dockerd in the guest on a scratch disk
#         --iperf3-server     start the iperf3 daemon the suites send to
#         --env NAME[=VALUE]  pass NAME into the guest (value from here if absent)
#         --collect <path>    copy <path> (a glob, quoted) out of the guest into
#                             $FLOOR_VM_OUT/collected/<path> after the command
#         --rwdir <dir>       one more host directory the guest writes through to
#
# Environment:
#   FLOOR_VM_KERNEL     release to boot (default: kernels.toml floor)
#   FLOOR_VM_BUILD      mainline build to boot, skips the resolution (the
#                       composite action resolves once and caches by it)
#   FLOOR_VM_HOME       vng's download cache (default ~/.cache/floor-vm)
#   FLOOR_VM_OUT        exchange directory (default $RUNNER_TEMP/floor-vm, or
#                       ./floor-vm-out off CI); the guest entry script, the exit
#                       status and the collected files land there
#   FLOOR_VM_SCRATCH    file backing the Docker scratch disk
#                       (default $FLOOR_VM_OUT/docker.img)
#   FLOOR_VM_DISK_SIZE  its size (default 30G, sparse)
#   FLOOR_VM_CPUS       guest vCPUs (default: every host CPU)
#   FLOOR_VM_MEMORY     guest memory in MiB (default: host memory less 2 GiB)
#   FLOOR_VM_ALLOW_TCG  1 boots without /dev/kvm, emulated and many times slower
#   FLOOR_VM_LSM        the guest's lsm= boot list (default: the agent VM's,
#                       BPF LSM last; empty boots the kernel's built-in list)
#
# The guest boots with the BPF LSM on, as the agent VM does, so the suites
# resting on it (`bpf-lsm` in skip-policy.yaml) run on this lane; the guest
# checks /sys/kernel/security/lsm against the list before any suite starts.
# There is no systemd in the guest (vng's own init is PID 1) and no AppArmor
# policy is loaded, since nothing runs apparmor.service: a suite needing a
# unit or a profile provides it itself or says why it cannot.
#
# Writes inside the guest land in tmpfs overlays and vanish at exit, except in
# the job's workspace, $RUNNER_TEMP, $FLOOR_VM_OUT and every --rwdir, which are
# shared with the host. The host's root filesystem is never written through,
# so this is safe to run on a workstation as well as on a runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KERNELS_TOML="$INTEGRATION_DIR/kernels.toml"
RESOLVER="$SCRIPT_DIR/check-kernel-matrix.py"

VIRTME_NG_VERSION="1.42"
VIRTME_NG_VENV="/opt/virtme-ng"
DEFAULT_LSM="lockdown,landlock,yama,apparmor,ima,evm,bpf"

die() {
  echo "::error::run-in-floor-vm: $*" >&2
  exit 1
}

# The floor is read from kernels.toml, the file check-kernel-matrix.py holds
# to the agent; no release number is written in this script.
floor_release() {
  local floor
  floor="$(sed -n 's/^floor[[:space:]]*=[[:space:]]*"\([0-9.]*\)".*/\1/p' "$KERNELS_TOML" | head -n1)"
  [ -n "$floor" ] || die "no floor in $KERNELS_TOML"
  echo "$floor"
}

resolve_build() {
  local rel="$1" build
  build="$(python3 "$RESOLVER" --resolve "$rel")" || die "kernel.ubuntu.com has no amd64 build of $rel"
  [ -n "$build" ] || die "kernel.ubuntu.com has no amd64 build of $rel"
  echo "$build"
}

cmd_resolve() {
  local rel="${FLOOR_VM_KERNEL:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --kernel) rel="$2"; shift 2 ;;
      *) die "resolve: unknown option $1" ;;
    esac
  done
  [ -n "$rel" ] || rel="$(floor_release)"
  resolve_build "$rel"
}

cmd_setup() {
  # The runner user reaches /dev/kvm only through this rule; without it qemu
  # falls back to emulation, which no suite budget survives.
  if [ -e /dev/kvm ]; then
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
      | sudo tee /etc/udev/rules.d/99-floor-vm-kvm.rules >/dev/null
    sudo udevadm control --reload-rules
    sudo udevadm trigger --name-match=kvm
  fi
  sudo apt-get update -q
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    qemu-system-x86 virtiofsd busybox-static python3-venv e2fsprogs util-linux \
    file binutils kmod zstd
  if [ ! -x "$VIRTME_NG_VENV/bin/vng" ]; then
    sudo python3 -m venv "$VIRTME_NG_VENV"
    sudo "$VIRTME_NG_VENV/bin/pip" install -q "virtme-ng==$VIRTME_NG_VERSION"
  fi
  "$VIRTME_NG_VENV/bin/vng" --version
}

# Written into $FLOOR_VM_OUT and run by the guest: everything the runner's own
# boot would have done for the suites and virtme-init does not.
write_guest_entry() {
  local entry="$1" floor="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -uo pipefail'
    printf 'FLOOR=%q\nOUT=%q\nCWD=%q\nAS_USER=%q\nWITH_DOCKER=%q\nWITH_IPERF3=%q\nLSM=%q\n' \
      "$floor" "$OUT" "$PWD" "$AS_USER" "$WITH_DOCKER" "$WITH_IPERF3" "$LSM"
    printf 'COLLECT=(' ; printf '%q ' "${COLLECT[@]+"${COLLECT[@]}"}" ; echo ')'
    printf 'CMD=(' ; printf '%q ' "${CMD[@]}" ; echo ')'
    # The job's environment, by name: vng starts the guest with an empty one.
    local name
    while IFS= read -r name; do
      printf 'export %s=%q\n' "$name" "${!name}"
    done < <(compgen -e | grep -E '^(EBPFSENTINEL_|GITHUB_|RUNNER_|CARGO_|RUSTUP_|CI$|PATH$|HOME$|LANG$|LC_ALL$|TERM$)' || true)
    local kv
    for kv in "${PASS_ENV[@]+"${PASS_ENV[@]}"}"; do
      if [[ "$kv" == *=* ]]; then
        printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
      else
        printf 'export %s=%q\n' "$kv" "${!kv-}"
      fi
    done
    cat <<'GUEST'
rc_file="$OUT/rc"
rm -f "$rc_file"
finish() { echo "$1" >"$rc_file"; sync; exit "$1"; }

# The agent's floor, checked on the kernel the suites run on.
running="$(uname -r)"
lowest="$(printf '%s\n%s\n' "$FLOOR" "${running%%-*}" | sort -V | head -n1)"
if [ "$lowest" != "$FLOOR" ]; then
  echo "::error::guest kernel $running is below the agent's $FLOOR floor"
  finish 1
fi
echo "floor-vm: kernel $running, floor $FLOOR"

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
active_lsm="$(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "floor-vm: active LSMs ${active_lsm:-none}"
if [ -n "$LSM" ]; then
  for want in ${LSM//,/ }; do
    case ",$active_lsm," in
      *",$want,"*) ;;
      *) echo "::error::floor-vm: lsm=$LSM was asked for and $want is not active ($active_lsm)"; finish 1 ;;
    esac
  done
fi
# The kfunc providers the datapath objects resolve at load, as the agent VM's
# provisioner loads them at boot; a module this build lacks is the probe's call.
modprobe -a nf_conntrack fou fou6 xfrm_interface 2>/dev/null || true
if [ -f /etc/sysctl.d/99-ebpfsentinel.conf ]; then
  sysctl -q -e -p /etc/sysctl.d/99-ebpfsentinel.conf || true
fi
ulimit -l unlimited 2>/dev/null || true
# The host's bpftool wrapper looks for tools built for the running release;
# the mainline kernel has none packaged, so it borrows the host's.
if [ ! -d "/usr/lib/linux-tools/$running" ]; then
  tools="$(ls -d /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -n1)"
  if [ -n "$tools" ]; then
    ln -sfn "$(readlink -f "$(dirname "$tools")")" "/usr/lib/linux-tools/$running"
  fi
fi

if [ "$WITH_IPERF3" = 1 ] && command -v iperf3 >/dev/null; then
  iperf3 -s -D >/dev/null 2>&1 || true
fi

if [ "$WITH_DOCKER" = 1 ]; then
  disk=""
  for b in /sys/block/vd*; do
    [ -e "$b" ] && { disk="/dev/${b##*/}"; break; }
  done
  [ -n "$disk" ] || { echo "::error::floor-vm: no scratch disk for Docker"; finish 1; }
  mkdir -p /var/lib/floor-docker
  mount "$disk" /var/lib/floor-docker || { echo "::error::floor-vm: cannot mount $disk"; finish 1; }
  mkdir -p /run/floor-docker
  dockerd --data-root /var/lib/floor-docker/docker --exec-root /run/floor-docker \
    >/var/lib/floor-docker/dockerd.log 2>&1 &
  for _ in $(seq 1 60); do
    docker info >/dev/null 2>&1 && break
    sleep 1
  done
  if ! docker info >/dev/null 2>&1; then
    echo "::error::floor-vm: dockerd did not start"
    tail -n 50 /var/lib/floor-docker/dockerd.log
    finish 1
  fi
  if [ -f "$OUT/images.tar" ]; then
    docker load -i "$OUT/images.tar" || finish 1
  fi
fi

cd "$CWD" || finish 1
if [ -n "$AS_USER" ]; then
  uid="$(id -u "$AS_USER")" || finish 1
  gid="$(id -g "$AS_USER")" || finish 1
  export HOME
  HOME="$(getent passwd "$AS_USER" | cut -d: -f6)"
  setpriv --reuid "$uid" --regid "$gid" --init-groups -- "${CMD[@]}"
else
  "${CMD[@]}"
fi
rc=$?

if [ "${#COLLECT[@]}" -gt 0 ]; then
  mkdir -p "$OUT/collected"
  shopt -s nullglob
  for pattern in "${COLLECT[@]}"; do
    # shellcheck disable=SC2206 # the pattern is a glob on purpose
    matches=($pattern)
    for path in "${matches[@]}"; do
      cp -a --parents "$path" "$OUT/collected/" 2>/dev/null || true
    done
  done
  chmod -R a+rX "$OUT/collected" 2>/dev/null || true
fi

if [ "$WITH_DOCKER" = 1 ]; then
  pkill dockerd 2>/dev/null || true
fi
finish "$rc"
GUEST
  } >"$entry"
  chmod 0755 "$entry"
}

cmd_run() {
  local rel="${FLOOR_VM_KERNEL:-}"
  AS_USER=""
  WITH_DOCKER=0
  WITH_IPERF3=0
  PASS_ENV=()
  COLLECT=()
  local extra_rw=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --kernel) rel="$2"; shift 2 ;;
      --as) AS_USER="$2"; shift 2 ;;
      --docker) WITH_DOCKER=1; shift ;;
      --iperf3-server) WITH_IPERF3=1; shift ;;
      --env) PASS_ENV+=("$2"); shift 2 ;;
      --collect) COLLECT+=("$2"); shift 2 ;;
      --rwdir) extra_rw+=("$2"); shift 2 ;;
      --) shift; break ;;
      *) die "run: unknown option $1 (the command follows --)" ;;
    esac
  done
  [ $# -gt 0 ] || die "run: no command after --"
  CMD=("$@")

  local vng="$VIRTME_NG_VENV/bin/vng"
  [ -x "$vng" ] || die "virtme-ng is not installed; run '$0 setup' first"
  if [ ! -w /dev/kvm ] && [ "${FLOOR_VM_ALLOW_TCG:-0}" != 1 ]; then
    die "/dev/kvm is not usable here; set FLOOR_VM_ALLOW_TCG=1 to boot emulated"
  fi

  LSM="${FLOOR_VM_LSM-$DEFAULT_LSM}"
  local floor build
  floor="$(floor_release)"
  [ -n "$rel" ] || rel="$floor"
  build="${FLOOR_VM_BUILD:-}"
  [ -n "$build" ] || build="$(resolve_build "$rel")"

  OUT="${FLOOR_VM_OUT:-${RUNNER_TEMP:+$RUNNER_TEMP/floor-vm}}"
  OUT="${OUT:-$PWD/floor-vm-out}"
  mkdir -p "$OUT"
  OUT="$(cd "$OUT" && pwd)"
  rm -rf "$OUT/collected" "$OUT/rc"
  local vm_home="${FLOOR_VM_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/floor-vm}"
  mkdir -p "$vm_home"

  local cpus="${FLOOR_VM_CPUS:-$(nproc)}"
  local mem="${FLOOR_VM_MEMORY:-}"
  if [ -z "$mem" ]; then
    mem=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 - 2048 ))
    [ "$mem" -ge 2048 ] || mem=2048
  fi

  local rw=("$PWD" "$OUT")
  [ -n "${GITHUB_WORKSPACE:-}" ] && rw+=("$GITHUB_WORKSPACE")
  [ -n "${RUNNER_TEMP:-}" ] && rw+=("$RUNNER_TEMP")
  rw+=("${extra_rw[@]+"${extra_rw[@]}"}")

  local args=(-r "v$build" --cpus "$cpus" --memory "${mem}M" --network user)
  [ -n "$LSM" ] && args+=(--append "lsm=$LSM")
  local seen=" " d
  for d in "${rw[@]}"; do
    d="$(cd "$d" && pwd)"
    case "$seen" in *" $d "*) continue ;; esac
    seen="$seen$d "
    args+=(--rwdir "$d")
  done

  if [ "$WITH_DOCKER" = 1 ]; then
    local disk="${FLOOR_VM_SCRATCH:-$OUT/docker.img}"
    rm -f "$disk"
    mkdir -p "$(dirname "$disk")"
    truncate -s "${FLOOR_VM_DISK_SIZE:-30G}" "$disk"
    mkfs.ext4 -q -F "$disk"
    args+=(--disk "$disk")
  fi

  local entry="$OUT/guest-entry.sh"
  write_guest_entry "$entry" "$floor"
  args+=(--exec "bash $entry")

  echo "floor-vm: booting mainline $build (release $rel, floor $floor), ${cpus} vCPU, ${mem} MiB"
  local start=$SECONDS vng_rc=0
  # Root on the host so the guest's root reads what the job wrote as root
  # (keys, provisioned files) and writes the workspace as the job did before.
  # vng runs virtme-run from its own venv, which is on no PATH of its own.
  sudo env HOME="$vm_home" PATH="$VIRTME_NG_VENV/bin:$PATH" "$vng" "${args[@]}" || vng_rc=$?
  echo "floor-vm: guest ran $(( SECONDS - start ))s"

  # The download cache and the exchange directory go back to the caller, so
  # actions/cache can save the one and upload-artifact read the other.
  sudo chown -R "$(id -u):$(id -g)" "$vm_home" "$OUT" 2>/dev/null || true
  [ "$WITH_DOCKER" = 1 ] && rm -f "${FLOOR_VM_SCRATCH:-$OUT/docker.img}" "$OUT/images.tar"

  if [ ! -s "$OUT/rc" ]; then
    die "the guest wrote no exit status (vng exited $vng_rc): it did not boot or was killed"
  fi
  return "$(cat "$OUT/rc")"
}

case "${1:-}" in
  floor) floor_release ;;
  resolve) shift; cmd_resolve "$@" ;;
  setup) shift; cmd_setup "$@" ;;
  run) shift; cmd_run "$@" ;;
  *)
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
