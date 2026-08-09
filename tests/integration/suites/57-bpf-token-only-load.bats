#!/usr/bin/env bats
# 57-bpf-token-only-load.bats — every eBPF program loads + attaches through a
# BPF token alone, with no CAP_BPF / CAP_SYS_ADMIN / CAP_PERFMON.
#
# The shipped `warden` broker delegates a bpffs and passes module BTF fds —
# exactly what runs in production under systemd / Docker / K8s — and the agent,
# started against it over the socket, self-unshares a capability-less user
# namespace, creates a BPF token, and loads/attaches the full program set through
# it. Driving the real warden + agent means CI validates the binaries we ship.
#
# Requires: root, kernel >= 6.9, local eBPF build, the warden binary (prebuilt
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
    export BPF_TOKEN_WARDEN_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    [ -x "$AGENT_BIN" ] || env_skip "agent binary not found: ${AGENT_BIN}"

    bpf_token_build_launcher

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ] || env_skip "eBPF objects not found in ${EBPF_DIR}"

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

    bpf_token_run "$PREPARED_CONFIG" 9 || soft_skip "launcher produced no output"
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

@test "the kernel helper probe reports not-probed rather than a false gap" {
    # The probe issues a plain BPF_PROG_LOAD, which needs CAP_BPF — exactly what
    # this path deliberately does not hold. "Not probed" is the only honest
    # answer: reporting a helper as missing here would be a false negative, and
    # refusing to start on it would break every rootless deployment. The
    # preceding test already asserts the agent did not fall back to API-only
    # mode, so a passing pair means the probe stayed out of the way.
    bpf_token_log_has 'kernel helper probe not run \(load mode bpf-token\)'
    run grep -iE 'required BPF helper unavailable' "$BPF_TOKEN_LOG"
    [ "$status" -ne 0 ]
}

@test "tc-threatintel loads and attaches via token" {
    bpf_token_log_has 'eBPF tc-threatintel active'
}

@test "tc-dns loads and attaches via token" {
    bpf_token_log_has 'eBPF tc-dns active'
}

@test "uprobe-dlp loads through the token" {
    # Load only. Under the warden posture the attach is deliberately kept off
    # the startup path — `try_load_uprobe_dlp` arms the module and the
    # lifecycle watcher does the /proc scan and every BPF_LINK_CREATE
    # asynchronously, because the brokered scan can be slow on a busy node.
    # Whether a link is created therefore depends on a TLS process existing
    # and on the watcher's poll landing inside this suite's short run window
    # — neither of which this suite controls. The attach itself is asserted
    # by suites 27 and 60, which run a full agent against real TLS traffic.
    bpf_token_log_has 'eBPF uprobe-dlp active'
}

@test "tc-ids loads via token using the fou module kfunc" {
    [ "${BPF_TOKEN_FOU_BTF}" = "1" ] || env_skip "no fou module BTF on this kernel"
    bpf_token_log_has 'eBPF tc-ids active'
}

@test "xdp-firewall loads via token using the conntrack module kfunc" {
    [ "${BPF_TOKEN_CT_BTF}" = "1" ] || env_skip "no nf_conntrack module BTF on this kernel"
    bpf_token_log_has 'eBPF xdp-firewall active'
}

@test "xdp-firewall reject tail-call is wired through the token loader" {
    [ "${BPF_TOKEN_CT_BTF}" = "1" ] || env_skip "no nf_conntrack module BTF on this kernel"
    bpf_token_log_has 'firewall .* reject wired'
}
