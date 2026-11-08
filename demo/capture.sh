#!/usr/bin/env bash
# eBPFsentinel demo - record what a scenario prints, as the site replays it.
#
#   sudo ./capture.sh syn-flood    # the flood absorbed and its source blocked
#   sudo ./capture.sh dlp-tls      # a card number caught inside TLS
#   sudo ./capture.sh shadow-ai    # a workload cut off for calling an AI provider
#   sudo ./capture.sh trace        # one packet through every program on the path
#   ./capture.sh host-check        # the host answering for itself, no lab needed
#
# The first four run against the lab `demo.sh up` started, each on a lab of its
# own: a scenario blocks an address, and the next one would read that block.
# `sudo ./demo.sh down && sudo ./demo.sh up` between two of them.
#
# Each writes captures/<id>.json: the agent's version, the kernel, the date,
# and one step per command, holding the argv, what it printed and its exit
# status. Nothing in a capture is typed; a step is the command, run.
#
# Two lower-level verbs record a scenario this script does not know, which is
# how the integration lane records what only its VM can show:
#
#   ./capture.sh begin <id> <agent|host>
#   ./capture.sh step <id> <agent|attacker|app|host> -- <argv...>
#
# `agent`, `attacker` and `app` run inside the lab container of that name.
# `host` runs the argv here as it stands. `begin` reads the agent's version
# from the lab agent or from the `ebpfsentinel-agent` on PATH.
# EBPFSENTINEL_CAPTURE_COMMIT names the commit the agent was built from, when
# this tree is not a git checkout.

set -euo pipefail

cd "$(dirname "$0")"

CAPTURES="${EBPFSENTINEL_CAPTURES:-$PWD/captures}"
# No command a scenario runs waits longer than this, so a capture never hangs.
STEP_TIMEOUT="${EBPFSENTINEL_CAPTURE_TIMEOUT:-120}"

fail() {
  printf 'capture: %s\n' "$*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required."

compose_files=(-f compose.yaml)
if [ -e .run/local ]; then
  compose_files=(-f compose.yaml -f compose.local.yaml)
fi

lab() { docker compose "${compose_files[@]}" exec -T "$@"; }

capture_file() { printf '%s/%s.json' "$CAPTURES" "$1"; }

# The lab scenarios run as root, and a capture lands in a checkout: it is
# handed to whoever owns this directory, so it can be committed without sudo.
own() {
  if [ "$(id -u)" -eq 0 ]; then
    chown --reference=. "$@"
  fi
}

# run_in <where> <argv...> - run the argv where it is meant to run.
run_in() {
  local where="$1"
  shift
  case "$where" in
    agent | attacker | app) timeout "$STEP_TIMEOUT" docker compose "${compose_files[@]}" exec -T "$where" "$@" ;;
    host) timeout "$STEP_TIMEOUT" "$@" ;;
    *) fail "unknown place to run: ${where} (agent, attacker, app or host)" ;;
  esac
}

begin() {
  local id="$1" from="$2" version commit kernel
  case "$id" in
    "" | *[!a-z0-9-]*) fail "a capture id is lowercase letters, digits and hyphens: '${id}'" ;;
  esac
  case "$from" in
    agent) version="$(lab agent ebpfsentinel-agent version)" ;;
    host) version="$(ebpfsentinel-agent version)" ;;
    *) fail "begin reads the version from the lab agent or the host: '${from}'" ;;
  esac
  version="${version##* }"
  commit="${EBPFSENTINEL_CAPTURE_COMMIT:-$(git rev-parse HEAD 2>/dev/null || true)}"
  kernel="$(uname -r)"
  mkdir -p "$CAPTURES"
  jq -n --arg id "$id" --arg version "$version" --arg commit "$commit" \
    --arg kernel "$kernel" --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{id: $id, agent_version: $version, agent_commit: (if $commit == "" then null else $commit end),
      kernel: $kernel, date: $date, steps: []}' >"$(capture_file "$id")"
  own "$CAPTURES" "$(capture_file "$id")"
}

step() {
  local id="$1" where="$2" file argv out err code
  shift 2
  [ "${1:-}" = "--" ] && shift
  [ "$#" -gt 0 ] || fail "step needs a command after --"
  file="$(capture_file "$id")"
  [ -f "$file" ] || fail "no capture named ${id}; begin it first"
  argv="$(mktemp)"
  out="$(mktemp)"
  err="$(mktemp)"
  # NUL-separated, so an argument holding a newline or starting with a dash
  # reaches the capture as it was passed.
  printf '%s\0' "$@" >"$argv"
  code=0
  run_in "$where" "$@" >"$out" 2>"$err" || code=$?
  cat "$out"
  cat "$err" >&2
  jq --arg where "$where" --rawfile argv "$argv" --rawfile stdout "$out" \
    --rawfile stderr "$err" --argjson exit "$code" \
    '.steps += [{where: $where, argv: ($argv | split("\u0000") | .[:-1]),
                 stdout: $stdout, stderr: $stderr, exit: $exit}]' \
    "$file" >"${file}.tmp"
  mv "${file}.tmp" "$file"
  own "$file"
  rm -f "$argv" "$out" "$err"
}

# The scenarios below are the tutorials' commands, in the tutorials' order.

http_code=(curl -s -o /dev/null -w '%{http_code}\n' --max-time 3)
https_code=(curl -sk -o /dev/null -w '%{http_code}\n' --max-time 3)

syn_flood() {
  begin syn-flood agent
  step syn-flood agent -- ebpfsentinel-agent status
  step syn-flood attacker -- "${http_code[@]}" http://172.30.66.1/
  step syn-flood attacker -- timeout 10 hping3 -S -p 80 --flood 172.30.66.1
  # The response policy blocks the source once the attack is declared.
  sleep 3
  step syn-flood agent -- ebpfsentinel-agent ddos attacks
  step syn-flood agent -- ebpfsentinel-agent alerts list --component ddos --limit 1
  step syn-flood agent -- ebpfsentinel-agent ips blacklist
  step syn-flood attacker -- "${http_code[@]}" http://172.30.66.1/
  step syn-flood app -- "${http_code[@]}" http://172.30.66.1/
  step syn-flood agent -- ebpfsentinel-agent audit logs --component responses
}

dlp_tls() {
  begin dlp-tls agent
  step dlp-tls agent -- ebpfsentinel-agent dlp status
  step dlp-tls app -- curl -sk -o /dev/null -w '%{http_code}\n' \
    https://172.30.66.1/orders -d 'card=4111111111111111&name=demo'
  sleep 2
  step dlp-tls agent -- ebpfsentinel-agent alerts list --component dlp
  step dlp-tls agent -- ebpfsentinel-agent audit logs --component dlp
}

shadow_ai() {
  begin shadow-ai agent
  step shadow-ai agent -- ebpfsentinel-agent l7 list
  step shadow-ai app -- "${https_code[@]}" https://172.30.66.1/
  step shadow-ai app -- "${https_code[@]}" https://api.openai.com/v1/models
  sleep 2
  step shadow-ai agent -- ebpfsentinel-agent alerts list --component l7
  step shadow-ai agent -- ebpfsentinel-agent ips blacklist
  step shadow-ai app -- "${https_code[@]}" https://172.30.66.1/
  step shadow-ai agent -- ebpfsentinel-agent audit logs --component responses
}

trace() {
  begin trace agent
  step trace agent -- ebpfsentinel-agent trace 172.30.66.1 --src 172.30.66.66 --dport 80
}

host_check() {
  begin host-check host
  step host-check host -- ebpfsentinel-agent ebpf host-check
}

lab_scenario() {
  [ "$(id -u)" -eq 0 ] || fail "run as root, like demo.sh: sudo ./capture.sh $1"
  [ -n "$(docker compose "${compose_files[@]}" ps -q agent 2>/dev/null)" ] ||
    fail "the lab is not running; start it with: sudo ./demo.sh up"
}

case "${1:-}" in
  syn-flood) lab_scenario "$1" && syn_flood ;;
  dlp-tls) lab_scenario "$1" && dlp_tls ;;
  shadow-ai) lab_scenario "$1" && shadow_ai ;;
  trace) lab_scenario "$1" && trace ;;
  host-check) host_check ;;
  begin)
    [ "$#" -eq 3 ] || fail "usage: ./capture.sh begin <id> <agent|host>"
    begin "$2" "$3"
    ;;
  step)
    [ "$#" -ge 4 ] || fail "usage: ./capture.sh step <id> <where> -- <argv...>"
    shift
    step "$@"
    ;;
  *)
    fail "usage: ./capture.sh syn-flood | dlp-tls | shadow-ai | trace | host-check
       ./capture.sh begin <id> <agent|host>
       ./capture.sh step <id> <agent|attacker|app|host> -- <argv...>"
    ;;
esac
