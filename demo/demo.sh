#!/usr/bin/env bash
# eBPFsentinel demo - start and stop the lab in compose.yaml.
#
#   sudo ./demo.sh up       # check the host, start the lab, wait for the agent
#   sudo ./demo.sh down     # stop it, drop the lab network and the agent state
#   sudo ./demo.sh agent ... # run the agent's CLI inside its container
#
# Root because three things it does need root: reading a kernel sysctl that
# gates user namespaces, writing the agent's configuration owned by the
# agent's uid, and talking to the Docker daemon.

set -euo pipefail

cd "$(dirname "$0")"

say() { printf 'demo: %s\n' "$*"; }
fail() {
  printf 'demo: %s\n' "$*" >&2
  exit 1
}

compose() { docker compose "$@"; }

preflight() {
  [ "$(id -u)" -eq 0 ] || fail "run as root: sudo ./demo.sh $*"
  command -v docker >/dev/null 2>&1 || fail "docker is required."
  docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is required."

  local release major minor
  release="$(uname -r)"
  major="${release%%.*}"
  minor="${release#*.}"
  minor="${minor%%.*}"
  if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 9 ]; }; then
    fail "kernel ${release}: the agent loads eBPF through a BPF token, which needs 6.9 or later."
  fi
  [ -r /sys/kernel/btf/vmlinux ] || fail "this kernel exposes no BTF at /sys/kernel/btf/vmlinux."

  # Ubuntu 24.04 and later gate unprivileged user namespaces behind AppArmor.
  # The agent runs as uid 65534 and unshares one, so it cannot start while
  # this is 1. Said rather than changed: it is a host setting, not the demo's.
  local userns=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
  if [ -r "$userns" ] && [ "$(cat "$userns")" = "1" ]; then
    fail "kernel.apparmor_restrict_unprivileged_userns is 1, so the agent cannot create its user namespace.
      Allow it for the session:  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
  fi
}

up() {
  preflight up
  mkdir -p .run
  install -m 0640 -o 65534 -g 65534 agent.yaml .run/agent.yaml
  say "building the lab image and starting the lab"
  compose up -d --build
  say "waiting for the agent to load its programs"
  for _ in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q agent)" 2>/dev/null)" = "healthy" ]; then
      say "agent healthy on esdemo0 - try: sudo ./demo.sh agent status"
      return 0
    fi
    sleep 2
  done
  compose logs --tail 40 agent >&2
  fail "the agent did not become healthy in two minutes; its last lines are above."
}

down() {
  preflight down
  compose down --volumes --remove-orphans
  rm -rf .run
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  agent)
    shift
    compose exec agent ebpfsentinel-agent "$@"
    ;;
  *)
    fail "usage: sudo ./demo.sh up | down | agent <command>"
    ;;
esac
