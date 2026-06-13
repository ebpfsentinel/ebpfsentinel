#!/usr/bin/env bats
# 57-bpf-token-only-load.bats — every eBPF program loads + attaches through a
# BPF token alone, with no CAP_BPF / CAP_SYS_ADMIN / CAP_PERFMON.
#
# The shipped launcher (ebpfsentinel-token-launch) delegates a bpffs and passes
# module BTF fds — exactly what runs in production under systemd / Docker / K8s —
# then execs the agent in a capability-less user namespace. The agent must create
# a BPF token and load/attach the full program set through it. Driving the real
# launcher means CI validates the binary we actually ship.
#
# Requires: root, kernel >= 6.9, local eBPF build, the launcher binary (prebuilt
# next to the agent or built on demand). VM-only (Vagrant agent).

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-tok-test"
IFACE_PEER="veth-tok-peer"

setup_file() {
    require_bpf_token_env
    require_ebpf_env

    # bats runs setup_file and every @test in separate processes, so the helper's
    # `$$`-derived defaults differ per process. Pin and export them once here so
    # every test reads the same captured log / launcher / staging paths.
    export BPF_TOKEN_LAUNCHER_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || skip "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || skip "eBPF objects not found in ${EBPF_DIR}"

    export DATA_DIR="/tmp/ebpfsentinel-bpf-token-data-$$"
    mkdir -p "$DATA_DIR"

    # A veth the agent can attach XDP/TC to. The harness shares the host network
    # namespace, so an interface created here is visible to the agent.
    ip link add "$IFACE" type veth peer name "$IFACE_PEER" 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
    ip link set "$IFACE_PEER" up 2>/dev/null || true

    # Record whether module-kfunc BTF is available so the conntrack/fou-dependent
    # programs can be asserted (or skipped on a kernel without module BTF).
    export BPF_TOKEN_CT_BTF=0 BPF_TOKEN_FOU_BTF=0
    bpf_token_module_btf_available nf_conntrack && export BPF_TOKEN_CT_BTF=1
    bpf_token_module_btf_available fou && export BPF_TOKEN_FOU_BTF=1

    # Stage the eBPF objects somewhere the user-namespace agent can read them.
    local staged_ebpf
    staged_ebpf="$(bpf_token_stage_ebpf_dir "$EBPF_DIR")"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-bpf-token-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__EBPF_DIR__|${staged_ebpf}|g" \
        -e "s|__IFACE__|${IFACE}|g" \
        "${FIXTURE_DIR}/config-bpf-token.yaml" >"$PREPARED_CONFIG"

    bpf_token_run "$PREPARED_CONFIG" 9 || skip "launcher produced no output"
}

teardown_file() {
    ip link delete "$IFACE" 2>/dev/null || true
    bpf_token_cleanup
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "agent loads eBPF through a BPF token (no capabilities)" {
    bpf_token_log_has 'eBPF loading via BPF token'
}

@test "module BTF fds are registered from the privileged helper" {
    bpf_token_log_has 'registered module BTF fd'
}

@test "no program load failed and nothing degraded" {
    # The whole point: the token path loads everything cleanly. A non-zero grep
    # exit means none of these failure markers appear in the agent log.
    run grep -iE 'load failed|degraded mode|api-only mode|token unavailable' "$BPF_TOKEN_LOG"
    [ "$status" -ne 0 ]
}

@test "tc-threatintel loads and attaches via token" {
    bpf_token_log_has 'eBPF tc-threatintel active'
}

@test "tc-dns loads and attaches via token" {
    bpf_token_log_has 'eBPF tc-dns active'
}

@test "uprobe-dlp loads and attaches via uprobe_multi link (token)" {
    bpf_token_log_has 'eBPF uprobe-dlp active'
    bpf_token_log_has 'uprobe_multi link'
}

@test "tc-ids loads via token using the fou module kfunc" {
    [ "${BPF_TOKEN_FOU_BTF}" = "1" ] || skip "no fou module BTF on this kernel"
    bpf_token_log_has 'eBPF tc-ids active'
}

@test "xdp-firewall loads via token using the conntrack module kfunc" {
    [ "${BPF_TOKEN_CT_BTF}" = "1" ] || skip "no nf_conntrack module BTF on this kernel"
    bpf_token_log_has 'eBPF xdp-firewall active'
}

@test "xdp-firewall reject tail-call is wired through the token loader" {
    [ "${BPF_TOKEN_CT_BTF}" = "1" ] || skip "no nf_conntrack module BTF on this kernel"
    bpf_token_log_has 'firewall .* reject wired'
}
