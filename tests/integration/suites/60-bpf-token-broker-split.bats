#!/usr/bin/env bats
# 60-bpf-token-broker-split.bats — the split-broker layout: the privileged bpffs
# delegation + module-BTF/pcap fd provisioning run in a separate `--broker-serve`
# process, while the agent runs through `--broker-connect` as a NON-ROOT,
# capability-less user that creates its own user namespace and obtains the
# delegated bpffs over a unix socket. This is the deployment where the agent
# container holds no CAP_SYS_ADMIN — driving the real launcher binary means CI
# validates the privilege-isolated path we ship.
#
# Requires: root (to run the broker), kernel >= 6.9, local eBPF build, the
# launcher binary, and `setpriv` (util-linux). VM-only (Vagrant agent).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-tokbrk"
IFACE_PEER="veth-tokbrkp"

setup_file() {
    require_bpf_token_env
    require_ebpf_env
    require_tool setpriv

    # bats runs setup_file and every @test in separate processes, so the helper's
    # `$$`-derived defaults differ per process. Pin them to fixed paths and export
    # once here so every test reads the same captured log / socket / staging.
    BPF_TOKEN_LOG="/tmp/ebpfsentinel-tokbrk.log"
    BPF_TOKEN_BROKER_SOCK="/run/ebpfsentinel-tokbrk.sock"
    BPF_TOKEN_AGENT_STAGE="/tmp/ebpfsentinel-tokbrk-agent"
    BPF_TOKEN_EBPF_STAGE="/tmp/ebpfsentinel-tokbrk-ebpf"
    export BPF_TOKEN_LAUNCHER_BIN BPF_TOKEN_LOG BPF_TOKEN_AGENT_STAGE \
        BPF_TOKEN_EBPF_STAGE BPF_TOKEN_BROKER_SOCK BPF_TOKEN_SPLIT_BPFFS \
        BPF_TOKEN_AGENT_UID BPF_TOKEN_BROKER_PID

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || skip "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || skip "eBPF objects not found in ${EBPF_DIR}"

    # The non-root agent writes its audit DB here, so it must own the directory.
    export DATA_DIR="/tmp/ebpfsentinel-tokbrk-data-$$"
    mkdir -p "$DATA_DIR"
    chown "${BPF_TOKEN_AGENT_UID}:${BPF_TOKEN_AGENT_UID}" "$DATA_DIR"

    ip link add "$IFACE" type veth peer name "$IFACE_PEER" 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
    ip link set "$IFACE_PEER" up 2>/dev/null || true

    export BPF_TOKEN_CT_BTF=0 BPF_TOKEN_FOU_BTF=0
    bpf_token_module_btf_available nf_conntrack && export BPF_TOKEN_CT_BTF=1
    bpf_token_module_btf_available fou && export BPF_TOKEN_FOU_BTF=1

    local staged_ebpf
    staged_ebpf="$(bpf_token_stage_ebpf_dir "$EBPF_DIR")"

    # Reuse the token fixture but point bpffs_path at the split pin path (the
    # agent mounts the delegated bpffs there and pins its maps there).
    export PREPARED_CONFIG="/tmp/ebpfsentinel-tokbrk-$$.yaml"
    # The non-root agent's control API is unauthenticated here, so bind it to
    # loopback (the agent refuses a non-loopback bind with auth disabled).
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__EBPF_DIR__|${staged_ebpf}|g" \
        -e "s|__IFACE__|${IFACE}|g" \
        -e "s|/run/etok|${BPF_TOKEN_SPLIT_BPFFS}|g" \
        -e 's|0.0.0.0|127.0.0.1|g' \
        "${FIXTURE_DIR}/config-bpf-token.yaml" >"$PREPARED_CONFIG"

    bpf_token_broker_run "$PREPARED_CONFIG" 9 || skip "broker split produced no output"
}

teardown_file() {
    bpf_token_broker_cleanup
    ip link delete "$IFACE" 2>/dev/null || true
    bpf_token_cleanup
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "broker serves the bpffs delegation + fds" {
    bpf_token_log_has 'broker.* serving on'
}

@test "the unprivileged agent loads eBPF through the broker-delegated token" {
    bpf_token_log_has 'eBPF loading via BPF token'
}

@test "module BTF fds reach the agent over the socket (no CAP_SYS_ADMIN)" {
    bpf_token_log_has 'registered module BTF fd'
}

@test "no program load failed and nothing degraded in the split layout" {
    run grep -iE 'load failed|degraded mode|api-only mode|token unavailable' "$BPF_TOKEN_LOG"
    [ "$status" -ne 0 ]
}

@test "tc-dns loads and attaches via the broker token" {
    bpf_token_log_has 'eBPF tc-dns active'
}

@test "tc-threatintel loads and attaches via the broker token" {
    bpf_token_log_has 'eBPF tc-threatintel active'
}

@test "uprobe-dlp loads via the broker token" {
    bpf_token_log_has 'eBPF uprobe-dlp active'
}

@test "xdp-firewall loads via the broker token using the conntrack module kfunc" {
    [ "${BPF_TOKEN_CT_BTF}" = "1" ] || skip "no nf_conntrack module BTF on this kernel"
    bpf_token_log_has 'eBPF xdp-firewall active'
}

@test "tc-ids loads via the broker token using the fou module kfunc" {
    [ "${BPF_TOKEN_FOU_BTF}" = "1" ] || skip "no fou module BTF on this kernel"
    bpf_token_log_has 'eBPF tc-ids active'
}
