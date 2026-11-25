#!/usr/bin/env bats
# 158-lockdown-confidentiality.bats - on a kernel booted with
# `lockdown=confidentiality`, the agent's programs load or are refused exactly
# as tests/integration/lockdown-programs.toml says, the agent keeps answering
# for the ones refused, and the warden's guard on program loads still attaches.
#
# Why a list and a suite. Lockdown at `confidentiality` takes
# bpf_probe_read_kernel away from every program type, and the verifier refuses
# a program that can reach a helper the kernel no longer offers. Which of our
# programs that is was read off the source; this suite is where the running
# kernel confirms it. The list is the one the documentation page on the agent
# and the warden prints, so the page and the kernel are held to the same file.
#
# The suite drives the shipped split deployment (warden + agent loading
# through a BPF token), as suites 156 and 157 do, once, with every program
# asked for (fixtures/config-lockdown.yaml), and with
# kernel.unprivileged_bpf_disabled set for the run, so the same run shows the
# token loads unaffected by it.
#
# Where the kernel is not locked down at `confidentiality` every test skips:
# only the agent VM booted by scripts/run-lockdown-lane.sh (the `lockdown`
# provisioner of ../vagrant/Vagrantfile) claims it. The guard test also skips
# where the kernel does not verify program signatures or the BPF LSM is not
# active.
#
# Requires: root, kernel >= 6.18, jq, curl, python3 (tomllib), the eBPF
# objects built by `cargo xtask ebpf-build`, the warden binary.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-lockdown"
IFACE_PEER="veth-lockdown-p"
API="http://127.0.0.1:18099"

_lockdown_level() {
    sed -n 's/.*\[\([a-z]*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null
}

_bpf_lsm_active() {
    tr ',' '\n' </sys/kernel/security/lsm 2>/dev/null | grep -qx bpf
}

# One line per program of the list: name verdict status asked reached_through,
# with `-` for an empty field.
_list() {
    python3 - "${BATS_TEST_DIRNAME}/../lockdown-programs.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    doc = tomllib.load(fh)
for p in doc["program"]:
    print(p["name"], p["verdict"], p.get("status") or "-",
          "true" if p.get("asked") else "false", p.get("reached_through") or "-")
PY
}

# _loaded <status-name> - true, false, or empty when the agent publishes no
# state for it, read from the last /api/v1/ebpf/status answer of the run.
_loaded() {
    jq -r --arg n "$1" \
        '[.programs[] | select((.name | gsub("_"; "-")) == $n) | .loaded][0] | if . == null then empty else . end' \
        "$STATUS_OUT"
}

setup_file() {
    require_bpf_token_env
    require_ebpf_env
    require_tool jq
    require_tool curl
    require_tool python3

    [ "$(_lockdown_level)" = "confidentiality" ] \
        || lane_skip lockdown "the kernel is not locked down at confidentiality (lockdown=confidentiality at boot)"

    export BPF_TOKEN_WARDEN_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || lane_skip agent-build "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || lane_skip agent-build "eBPF objects not found in ${EBPF_DIR}"

    export WORK_DIR="/tmp/ebpfsentinel-lockdown-$$"
    export DATA_DIR="${WORK_DIR}/data"
    mkdir -p "$DATA_DIR"
    chown 65534:65534 "$DATA_DIR"

    ip link add "$IFACE" type veth peer name "$IFACE_PEER" 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
    ip link set "$IFACE_PEER" up 2>/dev/null || true

    local staged_ebpf
    staged_ebpf="$(bpf_token_stage_ebpf_dir "$EBPF_DIR")"
    export PREPARED_CONFIG="${WORK_DIR}/config.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__EBPF_DIR__|${staged_ebpf}|g" \
        -e "s|__IFACE__|${IFACE}|g" \
        "${FIXTURE_DIR}/config-lockdown.yaml" >"$PREPARED_CONFIG"

    # The value is put back in teardown. 2 is what Ubuntu ships; 1 cannot be
    # taken back before a reboot, so a host already at 1 is left at 1.
    export UNPRIV_BEFORE UNPRIV_DURING
    UNPRIV_BEFORE="$(sysctl -n kernel.unprivileged_bpf_disabled)"
    [ "$UNPRIV_BEFORE" != "0" ] || sysctl -qw kernel.unprivileged_bpf_disabled=2
    UNPRIV_DURING="$(sysctl -n kernel.unprivileged_bpf_disabled)"

    export STATUS_OUT="${WORK_DIR}/status.json" POSTURE_OUT="${WORK_DIR}/posture.json"
    export RUN_LOG="${WORK_DIR}/run.log"
    (
        for _i in $(seq 1 80); do
            curl -s --max-time 2 "${API}/api/v1/ebpf/status" -o "${STATUS_OUT}.tmp" 2>/dev/null \
                && jq -e '.programs' "${STATUS_OUT}.tmp" >/dev/null 2>&1 \
                && mv "${STATUS_OUT}.tmp" "$STATUS_OUT"
            curl -s --max-time 2 "${API}/api/v1/crypto/posture" -o "${POSTURE_OUT}.tmp" 2>/dev/null \
                && jq -e '.signing' "${POSTURE_OUT}.tmp" >/dev/null 2>&1 \
                && mv "${POSTURE_OUT}.tmp" "$POSTURE_OUT"
            sleep 0.5
        done
    ) &
    local poller=$!
    # The guard object and the build's certificate where the build wrote them;
    # without them the warden attaches no guard and the guard test says so.
    EBPFSENTINEL_LOAD_GUARD_OBJECT="${EBPF_DIR}/lsm-bpf-load-guard" \
        EBPFSENTINEL_LOADER_CERT="${EBPF_DIR}/loader-signing.der" \
        bpf_token_run "$PREPARED_CONFIG" 40 || true
    kill "$poller" 2>/dev/null || true
    wait "$poller" 2>/dev/null || true
    cp "$BPF_TOKEN_LOG" "$RUN_LOG"
}

teardown_file() {
    if [ -n "${UNPRIV_BEFORE:-}" ] && [ "$UNPRIV_BEFORE" = "0" ]; then
        sysctl -qw kernel.unprivileged_bpf_disabled=0 2>/dev/null || true
    fi
    ip link delete "$IFACE" 2>/dev/null || true
    bpf_token_cleanup
    rm -rf "${WORK_DIR:-/nonexistent}"
}

@test "the kernel is locked down at confidentiality and the agent answered under it" {
    [ "$(_lockdown_level)" = "confidentiality" ]
    [ -s "$STATUS_OUT" ] || { echo "# the agent never answered /api/v1/ebpf/status" >&3; tail -20 "$RUN_LOG" >&3; false; }
    run grep -iE 'panicked|segmentation fault' "$RUN_LOG"
    [ "$status" -ne 0 ]
}

@test "every program the list says loads is loaded" {
    local name verdict st asked reached got bad=()
    while read -r name verdict st asked reached; do
        [ "$verdict" = loads ] && [ "$st" != "-" ] && [ "$reached" = "-" ] || continue
        got="$(_loaded "$st")"
        # A program the fixture does not ask for is published `false` when the
        # agent never tried it, so only an asked one can be read as refused.
        if [ "$asked" = true ] && [ -z "$got" ]; then
            bad+=("${name}: no state")
        elif [ "$asked" = true ] && [ "$got" != true ]; then
            bad+=("${name}: refused")
        fi
    done < <(_list)
    if [ "${#bad[@]}" -gt 0 ]; then
        printf '# %s\n' "${bad[@]}" >&3
        grep -iE 'load failed|verifier' "$RUN_LOG" | tail -20 | cut -c1-400 >&3
        false
    fi
}

@test "every program the list says is refused is reported not loaded" {
    local name verdict st asked reached got bad=()
    while read -r name verdict st asked reached; do
        [ "$verdict" = refused ] && [ "$st" != "-" ] || continue
        got="$(_loaded "$st")"
        if [ "$asked" = true ] && [ -z "$got" ]; then
            bad+=("${name}: no state")
        elif [ "$got" = true ]; then
            bad+=("${name}: loaded, the list says refused")
        fi
    done < <(_list)
    if [ "${#bad[@]}" -gt 0 ]; then
        printf '# %s\n' "${bad[@]}" >&3
        false
    fi
}

@test "the firewall's refusal is the verifier's, and the agent says it runs degraded" {
    # The one refusal the list explains with the conntrack read: the agent
    # names it, and the verifier's words are the missing helper, not a
    # program the build broke.
    grep -q 'xdp-firewall load failed (degraded mode)' "$RUN_LOG"
    grep -qiE 'unknown func|invalid func|probe_read_kernel' "$RUN_LOG"
}

@test "every program the agent publishes is one the list names" {
    local names published missing=()
    names="$(_list | awk '$3 != "-" {print $3}')"
    while read -r published; do
        [ -n "$published" ] || continue
        echo "$names" | grep -qx "$published" || missing+=("$published")
    done < <(jq -r '.programs[].name | gsub("_"; "-")' "$STATUS_OUT")
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "# not in lockdown-programs.toml: ${missing[*]}" >&3
        false
    fi
}

@test "the warden's guard on program loads attaches under lockdown" {
    ! grep -q 'the kernel does not check BPF program signatures here' "$RUN_LOG" \
        || env_skip "the kernel does not verify BPF program signatures here"
    _bpf_lsm_active || lane_skip bpf-lsm "the BPF LSM is not active on this host (lsm=bpf at boot)"
    [ -f "${EBPF_DIR}/lsm-bpf-load-guard" ] \
        || lane_skip agent-build "no signed loaders beside the objects in ${EBPF_DIR}: build them with cargo xtask ebpf-build"
    [ -s "$POSTURE_OUT" ]
    jq -e '.signing.load_guard_attached == true' "$POSTURE_OUT" >/dev/null
    jq -e '.signing.state == "enforced"' "$POSTURE_OUT" >/dev/null
}

@test "token loads hold with kernel.unprivileged_bpf_disabled set" {
    [ "$UNPRIV_DURING" != "0" ]
    grep -q 'eBPF tc-dns active' "$RUN_LOG"
    [ "$(_loaded tc-dns)" = true ]
}
