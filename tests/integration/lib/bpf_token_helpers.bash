# bpf_token_helpers.bash — helpers for the BPF-token-only loading suite (61).
#
# These drive the privileged-runtime stand-in (fixtures/bpf-token/delegate-and-run)
# that delegates a bpffs + passes module BTF fds, then runs the agent token-only
# and captures its log so tests can assert on what loaded/attached.

BPF_TOKEN_HARNESS_SRC="${BPF_TOKEN_HARNESS_SRC:-${FIXTURE_DIR}/bpf-token/delegate-and-run.c}"
BPF_TOKEN_HARNESS_BIN="${BPF_TOKEN_HARNESS_BIN:-/tmp/ebpfsentinel-bpf-token-harness-$$}"
BPF_TOKEN_LOG="${BPF_TOKEN_LOG:-/tmp/ebpfsentinel-bpf-token-$$.log}"
# The agent runs inside a user namespace, where any path component owned by an
# unmapped uid (e.g. a 0750 home directory) is inaccessible — to both exec and
# read. Stage the agent binary and the eBPF object files under /tmp
# (world-traversable, root-owned) so they are always reachable regardless of
# where the build tree lives.
BPF_TOKEN_AGENT_STAGE="${BPF_TOKEN_AGENT_STAGE:-/tmp/ebpfsentinel-bpf-token-agent-$$}"
BPF_TOKEN_EBPF_STAGE="${BPF_TOKEN_EBPF_STAGE:-/tmp/ebpfsentinel-bpf-token-ebpf-$$}"
# Must match `bpf_token.bpffs_path` in config-bpf-token.yaml and BPFFS_MOUNTPOINT
# in the harness.
BPF_TOKEN_BPFFS="${BPF_TOKEN_BPFFS:-/run/etok}"

# require_bpf_token_env — skip unless this host can exercise token delegation.
require_bpf_token_env() {
    require_root
    # BPF token delegation (BPF_TOKEN_CREATE + delegated bpffs) is kernel 6.9+.
    require_kernel 6 9
    require_tool cc
    if [ ! -r "$BPF_TOKEN_HARNESS_SRC" ]; then
        skip "harness source missing: ${BPF_TOKEN_HARNESS_SRC}"
    fi
}

# bpf_token_compile_harness — build the C harness; skip the suite if it fails.
bpf_token_compile_harness() {
    if ! cc -O2 -o "$BPF_TOKEN_HARNESS_BIN" "$BPF_TOKEN_HARNESS_SRC" 2>"${BPF_TOKEN_HARNESS_BIN}.cc.log"; then
        skip "harness failed to compile (missing kernel headers?): $(cat "${BPF_TOKEN_HARNESS_BIN}.cc.log")"
    fi
}

# bpf_token_stage_ebpf_dir <src_dir> — copy the eBPF object files to a
# world-traversable /tmp dir and echo its path, so the user-namespace agent can
# read them even when the build tree sits under a 0750 home directory.
bpf_token_stage_ebpf_dir() {
    local src="${1:?usage: bpf_token_stage_ebpf_dir <src_dir>}"
    rm -rf "$BPF_TOKEN_EBPF_STAGE"
    mkdir -p "$BPF_TOKEN_EBPF_STAGE"
    # Object files are named after the programs (no extension); copy regular
    # files only (skip build subdirectories).
    find "$src" -maxdepth 1 -type f -exec cp {} "$BPF_TOKEN_EBPF_STAGE/" \;
    chmod 755 "$BPF_TOKEN_EBPF_STAGE"
    chmod a+r "$BPF_TOKEN_EBPF_STAGE"/* 2>/dev/null || true
    echo "$BPF_TOKEN_EBPF_STAGE"
}

# bpf_token_module_btf_available <module> — 0 if the module's split BTF exists.
# Module kfuncs (conntrack, fou) only resolve when the kernel exposes per-module
# BTF (CONFIG_DEBUG_INFO_BTF_MODULES) and the module is loaded.
bpf_token_module_btf_available() {
    local module="${1:?usage: bpf_token_module_btf_available <module>}"
    modprobe "$module" 2>/dev/null || true
    [ -r "/sys/kernel/btf/${module}" ]
}

# bpf_token_run <config> [seconds] — run the agent token-only via the harness
# for N seconds (default 9), capturing combined stdout+stderr to $BPF_TOKEN_LOG.
# The agent is a daemon, so `timeout` reaping it (exit 124) is the success path;
# the assertions inspect the captured log rather than an exit code.
bpf_token_run() {
    local config="${1:?usage: bpf_token_run <config> [seconds]}"
    local secs="${2:-9}"
    chmod 640 "$config"
    # Stage the agent under /tmp so the user-namespace exec can reach it.
    install -m755 "$AGENT_BIN" "$BPF_TOKEN_AGENT_STAGE"
    : >"$BPF_TOKEN_LOG"
    # Close inherited fds (>=3) before the harness. bats holds its TAP stream on
    # fd 3, which the harness would otherwise inherit — pushing the module BTF
    # fds it opens to higher numbers and colliding with the fds the agent's token
    # loader allocates, so map creation fails with a bare -1. Running the harness
    # with a clean fd table makes the module BTF fds start at 3 as they do
    # outside bats.
    (
        for _fd in $(seq 3 30); do eval "exec ${_fd}>&-" 2>/dev/null || true; done
        exec timeout "$secs" "$BPF_TOKEN_HARNESS_BIN" "$BPF_TOKEN_AGENT_STAGE" \
            --config "$config" >"$BPF_TOKEN_LOG" 2>&1
    ) || true
    [ -s "$BPF_TOKEN_LOG" ]
}

# bpf_token_log — echo the captured log (for assertion `run` blocks).
bpf_token_log() {
    cat "$BPF_TOKEN_LOG" 2>/dev/null || true
}

# bpf_token_log_has <extended-regex> — grep the captured agent log.
bpf_token_log_has() {
    grep -qiE "${1:?usage: bpf_token_log_has <regex>}" "$BPF_TOKEN_LOG"
}

# bpf_token_cleanup — remove harness binary, log, prepared config, leftover mount.
bpf_token_cleanup() {
    umount "$BPF_TOKEN_BPFFS" 2>/dev/null || true
    rm -f "$BPF_TOKEN_HARNESS_BIN" "${BPF_TOKEN_HARNESS_BIN}.cc.log" "$BPF_TOKEN_LOG" \
        "$BPF_TOKEN_AGENT_STAGE"
    rm -rf "$BPF_TOKEN_EBPF_STAGE"
}
