# bpf_token_helpers.bash — helpers for the BPF-token-only loading suite (61).
#
# These drive the *shipped* privileged launcher (crates/warden →
# warden-token) that delegates a bpffs + passes module BTF fds,
# then runs the agent token-only in a capability-less user namespace. The log
# is captured so tests can assert on what loaded/attached. Exercising the real
# launcher (not a test-only stand-in) means CI validates the exact binary we
# ship in the tarball / container image.

# Resolved lazily (needs $AGENT_BIN / $PROJECT_ROOT from the suite's setup_file).
BPF_TOKEN_LAUNCHER_BIN="${BPF_TOKEN_LAUNCHER_BIN:-}"
BPF_TOKEN_LOG="${BPF_TOKEN_LOG:-/tmp/ebpfsentinel-bpf-token-$$.log}"
# The agent runs inside a user namespace, where any path component owned by an
# unmapped uid (e.g. a 0750 home directory) is inaccessible — to both exec and
# read. Stage the agent binary and the eBPF object files under /tmp
# (world-traversable, root-owned) so they are always reachable regardless of
# where the build tree lives.
BPF_TOKEN_AGENT_STAGE="${BPF_TOKEN_AGENT_STAGE:-/tmp/ebpfsentinel-bpf-token-agent-$$}"
BPF_TOKEN_EBPF_STAGE="${BPF_TOKEN_EBPF_STAGE:-/tmp/ebpfsentinel-bpf-token-ebpf-$$}"
# Must match `bpf_token.bpffs_path` in config-bpf-token.yaml (passed to the
# launcher via --bpffs).
BPF_TOKEN_BPFFS="${BPF_TOKEN_BPFFS:-/run/etok}"

# require_bpf_token_env — skip unless this host can exercise token delegation.
require_bpf_token_env() {
    require_root
    # BPF token delegation (BPF_TOKEN_CREATE + delegated bpffs) is kernel 6.9+.
    require_kernel 6 9
}

# bpf_token_build_launcher — resolve (or build) the shipped launcher binary and
# export its path. Prefers a prebuilt binary next to the agent (as CI's build
# job produces); falls back to `cargo build` from the project tree; skips the
# suite if neither yields a binary.
bpf_token_build_launcher() {
    if [ -n "$BPF_TOKEN_LAUNCHER_BIN" ] && [ -x "$BPF_TOKEN_LAUNCHER_BIN" ]; then
        return 0
    fi
    # Same directory as the agent binary the suite already located.
    local candidate="$(dirname "$AGENT_BIN")/warden-token"
    if [ -x "$candidate" ]; then
        BPF_TOKEN_LAUNCHER_BIN="$candidate"
        export BPF_TOKEN_LAUNCHER_BIN
        return 0
    fi
    require_tool cargo
    if ! (cd "$PROJECT_ROOT" && cargo build --release --bin warden-token) \
        >/tmp/warden-token-build-$$.log 2>&1; then
        skip "launcher failed to build: $(cat /tmp/warden-token-build-$$.log)"
    fi
    BPF_TOKEN_LAUNCHER_BIN="${PROJECT_ROOT}/target/release/warden-token"
    [ -x "$BPF_TOKEN_LAUNCHER_BIN" ] || skip "launcher binary not found after build"
    export BPF_TOKEN_LAUNCHER_BIN
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

# bpf_token_run <config> [seconds] — run the agent token-only via the launcher
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
    # Close inherited fds (>=3) before the launcher. bats holds its TAP stream on
    # fd 3, which the launcher would otherwise inherit — pushing the module BTF
    # fds it opens to higher numbers and colliding with the fds the agent's token
    # loader allocates, so map creation fails with a bare -1. Running the launcher
    # with a clean fd table makes the module BTF fds start at 3 as they do
    # outside bats.
    (
        for _fd in $(seq 3 30); do eval "exec ${_fd}>&-" 2>/dev/null || true; done
        exec timeout "$secs" "$BPF_TOKEN_LAUNCHER_BIN" --bpffs "$BPF_TOKEN_BPFFS" \
            "$BPF_TOKEN_AGENT_STAGE" --config "$config" >"$BPF_TOKEN_LOG" 2>&1
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

# bpf_token_cleanup — remove log, staged agent, leftover mount. The launcher is
# a build artifact (target/release or next to the agent), so it is never removed.
bpf_token_cleanup() {
    umount "$BPF_TOKEN_BPFFS" 2>/dev/null || true
    rm -f "$BPF_TOKEN_LOG" "$BPF_TOKEN_AGENT_STAGE" \
        "/tmp/warden-token-build-$$.log"
    rm -rf "$BPF_TOKEN_EBPF_STAGE"
}
