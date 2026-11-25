#!/usr/bin/env bats
# 156-signed-program-loaders.bats - the agent's programs load through loaders
# signed at build, checked by the kernel against the keyring the warden made.
#
# The suite drives the shipped split deployment twice, as suite 57 does:
#
#   * With the certificate the build wrote beside the objects: the warden
#     makes its keyring and names the serial, every program loads through a
#     signed loader, and the crypto posture reports state
#     `verified_not_enforced`, the same serial, the certificate's SHA-256 and
#     a count of signed programs.
#   * With a certificate of another key in the keyring: the kernel refuses
#     each loader because its signer is not in the keyring (ENOKEY), the
#     agent says so, loads the program unsigned and keeps running, and the
#     posture counts unsigned programs and no signed one.
#
# Where the kernel does not verify program signatures, the signed-load tests
# skip, and the posture is asserted to say `unsupported` with every program
# loaded unsigned.
#
# Both runs point the warden at no guard object, so its guard on program loads
# stays off and an unsigned fallback still loads: the posture never reads
# `enforced` here. Suite 157 runs the same deployment with the guard on.
#
# Requires: root, kernel >= 6.18, jq, openssl, curl, the eBPF objects built
# and signed by `cargo xtask ebpf-build` (the `.loaders` bundles and
# `loader-signing.der` beside them), the warden binary. VM-only (Vagrant agent).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-sig-test"
IFACE_PEER="veth-sig-peer"
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

setup_file() {
    require_bpf_token_env
    require_ebpf_env
    require_tool jq
    require_tool openssl
    require_tool curl

    export BPF_TOKEN_WARDEN_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE
    # No guard on program loads in this suite: the refused signer's fallback
    # must load unsigned.
    export EBPFSENTINEL_LOAD_GUARD_OBJECT=/nonexistent

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || lane_skip agent-build "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || lane_skip agent-build "eBPF objects not found in ${EBPF_DIR}"
    [ -f "${EBPF_DIR}/loader-signing.der" ] && [ -f "${EBPF_DIR}/xdp-firewall.loaders" ] \
        || lane_skip agent-build "no signed loaders beside the objects in ${EBPF_DIR}: build them with cargo xtask ebpf-build"

    export WORK_DIR="/tmp/ebpfsentinel-signed-loaders-$$"
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

    # The certificate the build signed with, as the image ships it.
    export CERT_SHA256
    CERT_SHA256="$(sha256sum "${EBPF_DIR}/loader-signing.der" | cut -d' ' -f1)"
    export SIGNED_LOG="${WORK_DIR}/signed.log" SIGNED_POSTURE="${WORK_DIR}/signed.json"
    EBPFSENTINEL_LOADER_CERT="${EBPF_DIR}/loader-signing.der" \
        _run_with_posture "$PREPARED_CONFIG" "$SIGNED_LOG" "$SIGNED_POSTURE"

    # A certificate of a key that signed nothing here.
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 -subj "/CN=not the build" \
        -keyout "${WORK_DIR}/other.key.pem" -out "${WORK_DIR}/other.crt.pem" >/dev/null 2>&1
    openssl x509 -in "${WORK_DIR}/other.crt.pem" -outform DER -out "${WORK_DIR}/other.der"
    export OTHER_LOG="${WORK_DIR}/other.log" OTHER_POSTURE="${WORK_DIR}/other.json"
    EBPFSENTINEL_LOADER_CERT="${WORK_DIR}/other.der" \
        _run_with_posture "$PREPARED_CONFIG" "$OTHER_LOG" "$OTHER_POSTURE"
}

teardown_file() {
    ip link delete "$IFACE" 2>/dev/null || true
    bpf_token_cleanup
    rm -rf "$WORK_DIR"
}

_kernel_verifies() {
    ! grep -q 'the kernel does not check BPF program signatures here' "$SIGNED_LOG"
}

_require_verifying_kernel() {
    _kernel_verifies || env_skip "the kernel does not verify BPF program signatures here"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "the warden puts the build's certificate in a keyring and names its serial" {
    grep -qE '\[warden\] loader keyring [0-9]+ holds the certificate' "$SIGNED_LOG"
}

@test "every program loads through a signed loader, and nothing degrades" {
    _require_verifying_kernel
    grep -q 'programs load through loaders signed at build' "$SIGNED_LOG"
    run grep -iE 'signed loader refused|loader bundle unreadable|load failed|api-only mode' "$SIGNED_LOG"
    [ "$status" -ne 0 ]
    grep -q 'eBPF tc-dns active' "$SIGNED_LOG"
}

@test "the posture reports the keyring serial the warden named and the certificate digest" {
    _require_verifying_kernel
    [ -s "$SIGNED_POSTURE" ]
    local serial
    serial="$(grep -oE '\[warden\] loader keyring [0-9]+' "$SIGNED_LOG" | grep -oE '[0-9]+$' | head -1)"
    jq -e '.signing.state == "verified_not_enforced"' "$SIGNED_POSTURE" >/dev/null
    [ "$(jq -r '.signing.keyring_serial' "$SIGNED_POSTURE")" = "$serial" ]
    [ "$(jq -r '.signing.certificate_sha256' "$SIGNED_POSTURE")" = "$CERT_SHA256" ]
    jq -e '.signing.signed_programs > 0' "$SIGNED_POSTURE" >/dev/null
    jq -e '.signing.unsigned_programs == 0' "$SIGNED_POSTURE" >/dev/null
    jq -e '.signing.load_guard_attached == false' "$SIGNED_POSTURE" >/dev/null
    jq -e '.signing.not_enforced_because | length > 0' "$SIGNED_POSTURE" >/dev/null
}

@test "a loader whose signer is not in the keyring is refused, and the program loads unsigned" {
    _require_verifying_kernel
    grep -qE '\[warden\] loader keyring [0-9]+ holds the certificate' "$OTHER_LOG"
    grep -q 'signed loader refused, the program loads unsigned' "$OTHER_LOG"
    grep -q 'the signing certificate is not in the keyring' "$OTHER_LOG"
    run grep -iE 'load failed|api-only mode' "$OTHER_LOG"
    [ "$status" -ne 0 ]
    grep -q 'eBPF tc-dns active' "$OTHER_LOG"
    [ -s "$OTHER_POSTURE" ]
    jq -e '.signing.state == "unsigned"' "$OTHER_POSTURE" >/dev/null
    jq -e '.signing.signed_programs == 0' "$OTHER_POSTURE" >/dev/null
    jq -e '.signing.unsigned_programs > 0' "$OTHER_POSTURE" >/dev/null
}

@test "the posture's state follows the kernel, every program loads, and nothing claims enforcement" {
    [ -s "$SIGNED_POSTURE" ]
    if _kernel_verifies; then
        jq -e '.signing.state == "verified_not_enforced"' "$SIGNED_POSTURE" >/dev/null
    else
        jq -e '.signing.state == "unsupported"' "$SIGNED_POSTURE" >/dev/null
        jq -e '.signing.keyring_serial == null' "$SIGNED_POSTURE" >/dev/null
        jq -e '.signing.signed_programs == 0' "$SIGNED_POSTURE" >/dev/null
    fi
    grep -q 'eBPF tc-dns active' "$SIGNED_LOG"
    run grep -iE 'load failed|api-only mode' "$SIGNED_LOG"
    [ "$status" -ne 0 ]
    jq -e '.signing.state != "enforced" and .signing.load_guard_attached == false' \
        "$SIGNED_POSTURE" >/dev/null
    jq -e '.signing.state != "enforced" and .signing.load_guard_attached == false' \
        "$OTHER_POSTURE" >/dev/null
    grep -q 'no guard on program loads' "$SIGNED_LOG"
}
