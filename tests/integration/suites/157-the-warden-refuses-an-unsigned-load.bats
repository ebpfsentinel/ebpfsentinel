#!/usr/bin/env bats
# 157-the-warden-refuses-an-unsigned-load.bats - the warden's guard on program
# loads refuses a load through the agent's BPF token that is not signed
# against the warden's keyring, and the crypto posture says `enforced` only
# while it holds.
#
# The suite drives the shipped split deployment, as suite 156 does, four
# times:
#
#   Guarded half (the guard object the build wrote, the BPF LSM at boot):
#     * With the build's certificate in the keyring: the warden attaches its
#       guard after making the keyring, every program loads through a signed
#       loader, and the posture reads `enforced`, the guard attached, nothing
#       refused.
#     * With a certificate of another key in the keyring: the kernel refuses
#       each signed loader (ENOKEY), the unsigned fallback through the token
#       is refused by the guard (EPERM), the agent says so, counts the
#       refusals on the posture and keeps answering its API.
#
#   Unguarded half (the warden pointed at no guard object):
#     * The same signed loads pass, and the posture reads
#       `verified_not_enforced`, names why it is not enforced, and reports
#       the guard detached.
#
# Where the kernel does not verify program signatures every test skips; the
# guarded half also skips where the BPF LSM is not active.
#
# Requires: root, kernel >= 6.18, jq, openssl, curl, the eBPF objects built
# and signed by `cargo xtask ebpf-build` (the `.loaders` bundles,
# `loader-signing.der` and `lsm-bpf-load-guard` beside them), the warden
# binary. VM-only (Vagrant agent, whose bpf-lsm provisioner boots with
# `lsm=...,bpf`).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-guard-test"
IFACE_PEER="veth-guard-peer"
POSTURE_URL="http://127.0.0.1:18099/api/v1/crypto/posture"

# _run_with_posture <config> <log_out> <posture_out> - one warden + agent run,
# keeping the run's log and the last crypto posture the agent answered.
_run_with_posture() {
    local config="$1" log_out="$2" posture_out="$3"
    rm -f "$posture_out"
    (
        for _i in $(seq 1 60); do
            curl -s --max-time 2 "$POSTURE_URL" -o "${posture_out}.tmp" 2>/dev/null \
                && jq -e '.signing' "${posture_out}.tmp" >/dev/null 2>&1 \
                && mv "${posture_out}.tmp" "$posture_out"
            sleep 0.5
        done
    ) &
    local poller=$!
    bpf_token_run "$config" 18 || true
    kill "$poller" 2>/dev/null || true
    wait "$poller" 2>/dev/null || true
    cp "$BPF_TOKEN_LOG" "$log_out"
}

_bpf_lsm_active() {
    tr ',' '\n' </sys/kernel/security/lsm 2>/dev/null | grep -qx bpf
}

setup_file() {
    require_bpf_token_env
    require_ebpf_env
    require_tool jq
    require_tool openssl
    require_tool curl

    export BPF_TOKEN_WARDEN_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || lane_skip agent-build "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || lane_skip agent-build "eBPF objects not found in ${EBPF_DIR}"
    [ -f "${EBPF_DIR}/loader-signing.der" ] && [ -f "${EBPF_DIR}/xdp-firewall.loaders" ] \
        && [ -f "${EBPF_DIR}/lsm-bpf-load-guard" ] \
        || lane_skip agent-build "no signed loaders beside the objects in ${EBPF_DIR}: build them with cargo xtask ebpf-build"

    export WORK_DIR="/tmp/ebpfsentinel-load-guard-$$"
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
        "${FIXTURE_DIR}/config-bpf-token.yaml" >"$PREPARED_CONFIG"

    export CERT_SHA256
    CERT_SHA256="$(sha256sum "${EBPF_DIR}/loader-signing.der" | cut -d' ' -f1)"
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 -subj "/CN=not the build" \
        -keyout "${WORK_DIR}/other.key.pem" -out "${WORK_DIR}/other.crt.pem" >/dev/null 2>&1
    openssl x509 -in "${WORK_DIR}/other.crt.pem" -outform DER -out "${WORK_DIR}/other.der"

    # Guarded half: the warden reads the guard object the build wrote. The
    # warden is root in the initial namespaces, so it reads it in place.
    export GUARDED_LOG="${WORK_DIR}/guarded.log" GUARDED_POSTURE="${WORK_DIR}/guarded.json"
    EBPFSENTINEL_LOAD_GUARD_OBJECT="${EBPF_DIR}/lsm-bpf-load-guard" \
        EBPFSENTINEL_LOADER_CERT="${EBPF_DIR}/loader-signing.der" \
        _run_with_posture "$PREPARED_CONFIG" "$GUARDED_LOG" "$GUARDED_POSTURE"
    export REFUSED_LOG="${WORK_DIR}/refused.log" REFUSED_POSTURE="${WORK_DIR}/refused.json"
    EBPFSENTINEL_LOAD_GUARD_OBJECT="${EBPF_DIR}/lsm-bpf-load-guard" \
        EBPFSENTINEL_LOADER_CERT="${WORK_DIR}/other.der" \
        _run_with_posture "$PREPARED_CONFIG" "$REFUSED_LOG" "$REFUSED_POSTURE"

    # Unguarded half: no guard object, so the warden attaches nothing.
    export OPEN_LOG="${WORK_DIR}/open.log" OPEN_POSTURE="${WORK_DIR}/open.json"
    EBPFSENTINEL_LOAD_GUARD_OBJECT=/nonexistent \
        EBPFSENTINEL_LOADER_CERT="${EBPF_DIR}/loader-signing.der" \
        _run_with_posture "$PREPARED_CONFIG" "$OPEN_LOG" "$OPEN_POSTURE"
}

teardown_file() {
    ip link delete "$IFACE" 2>/dev/null || true
    bpf_token_cleanup
    rm -rf "$WORK_DIR"
}

_require_verifying_kernel() {
    ! grep -q 'the kernel does not check BPF program signatures here' "$OPEN_LOG" \
        || env_skip "the kernel does not verify BPF program signatures here"
}

_require_guard_conditions() {
    _require_verifying_kernel
    _bpf_lsm_active || lane_skip bpf-lsm "the BPF LSM is not active on this host (lsm=bpf at boot)"
}

# ── Guarded half ───────────────────────────────────────────────────

@test "the warden attaches its guard once the agent has run its probes, held to its keyring" {
    _require_guard_conditions
    local serial
    serial="$(grep -oE '\[warden\] loader keyring [0-9]+' "$GUARDED_LOG" | grep -oE '[0-9]+$' | head -1)"
    [ -n "$serial" ]
    grep -qE "\[warden\] guard on program loads read from .*loader keyring ${serial}\$" "$GUARDED_LOG"
    grep -qE "\[warden\] guard on program loads attached from .*loader keyring ${serial}\$" "$GUARDED_LOG"
    grep -q "the warden's guard on program loads is attached" "$GUARDED_LOG"
}

@test "a signed load through the token passes the guard and every program loads" {
    _require_guard_conditions
    grep -q 'programs load through loaders signed at build' "$GUARDED_LOG"
    run grep -iE 'signed loader refused|refused by the warden.s guard|load failed|api-only mode' "$GUARDED_LOG"
    [ "$status" -ne 0 ]
    grep -q 'eBPF tc-dns active' "$GUARDED_LOG"
}

@test "the posture reads enforced while the guard holds" {
    _require_guard_conditions
    [ -s "$GUARDED_POSTURE" ]
    jq -e '.signing.state == "enforced"' "$GUARDED_POSTURE" >/dev/null
    jq -e '.signing.load_guard_attached == true' "$GUARDED_POSTURE" >/dev/null
    jq -e '.signing.bpf_lsm_active == true' "$GUARDED_POSTURE" >/dev/null
    jq -e '.signing.not_enforced_because == null' "$GUARDED_POSTURE" >/dev/null
    jq -e '.signing.signed_programs > 0' "$GUARDED_POSTURE" >/dev/null
    jq -e '.signing.refused_programs == 0' "$GUARDED_POSTURE" >/dev/null
    [ "$(jq -r '.signing.certificate_sha256' "$GUARDED_POSTURE")" = "$CERT_SHA256" ]
}

@test "an unsigned load through the token is refused with EPERM, and the agent keeps running" {
    _require_guard_conditions
    grep -q 'signed loader refused, the program loads unsigned' "$REFUSED_LOG"
    grep -q "refused by the warden's guard on program loads" "$REFUSED_LOG"
    run grep -iE 'panicked|segmentation fault' "$REFUSED_LOG"
    [ "$status" -ne 0 ]
    [ -s "$REFUSED_POSTURE" ]
    jq -e '.signing.state == "enforced"' "$REFUSED_POSTURE" >/dev/null
    jq -e '.signing.refused_programs > 0' "$REFUSED_POSTURE" >/dev/null
    jq -e '.signing.signed_programs == 0' "$REFUSED_POSTURE" >/dev/null
}

# ── Unguarded half ─────────────────────────────────────────────────

@test "without the guard the warden says why, and the signed loads still pass" {
    _require_verifying_kernel
    grep -q '\[warden\] no guard on program loads:' "$OPEN_LOG"
    grep -q 'programs load through loaders signed at build' "$OPEN_LOG"
    grep -q 'eBPF tc-dns active' "$OPEN_LOG"
}

@test "without the guard the posture reads verified_not_enforced and names the missing condition" {
    _require_verifying_kernel
    [ -s "$OPEN_POSTURE" ]
    jq -e '.signing.state == "verified_not_enforced"' "$OPEN_POSTURE" >/dev/null
    jq -e '.signing.load_guard_attached == false' "$OPEN_POSTURE" >/dev/null
    jq -e '.signing.refused_programs == 0' "$OPEN_POSTURE" >/dev/null
    if _bpf_lsm_active; then
        jq -e '.signing.not_enforced_because | test("did not attach its guard")' \
            "$OPEN_POSTURE" >/dev/null
    else
        jq -e '.signing.not_enforced_because | test("lsm=")' "$OPEN_POSTURE" >/dev/null
    fi
}
