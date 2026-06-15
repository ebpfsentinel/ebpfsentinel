# bpf_token_helpers.bash — helpers for the BPF-token-only loading suite (61).
#
# These drive the *shipped* split deployment: the privileged `warden` broker
# (crates/warden → warden) delegates a bpffs + passes module BTF fds, and the
# agent — started against it over the socket — loads its own eBPF token-only in a
# capability-less user namespace. The log is captured so tests can assert on what
# loaded/attached. Exercising the real warden + agent (not a test-only stand-in)
# means CI validates the exact binaries we ship.

# Resolved lazily (needs $AGENT_BIN / $PROJECT_ROOT from the suite's setup_file).
BPF_TOKEN_WARDEN_BIN="${BPF_TOKEN_WARDEN_BIN:-}"
BPF_TOKEN_WARDEN_PID=""
BPF_TOKEN_LOG="${BPF_TOKEN_LOG:-/tmp/ebpfsentinel-bpf-token-$$.log}"
# The agent runs inside a user namespace, where any path component owned by an
# unmapped uid (e.g. a 0750 home directory) is inaccessible — to both exec and
# read. Stage the agent binary and the eBPF object files under /tmp
# (world-traversable, root-owned) so they are always reachable regardless of
# where the build tree lives.
BPF_TOKEN_AGENT_STAGE="${BPF_TOKEN_AGENT_STAGE:-/tmp/ebpfsentinel-bpf-token-agent-$$}"
BPF_TOKEN_EBPF_STAGE="${BPF_TOKEN_EBPF_STAGE:-/tmp/ebpfsentinel-bpf-token-ebpf-$$}"
# Must match `bpf_token.bpffs_path` in config-bpf-token.yaml (passed to the agent
# via the EBPFSENTINEL_BPFFS env var — its bpffs mount target).
BPF_TOKEN_BPFFS="${BPF_TOKEN_BPFFS:-/run/etok}"
# Per-run warden control socket the launcher starts the broker on.
BPF_TOKEN_WARDEN_SOCK="${BPF_TOKEN_WARDEN_SOCK:-/tmp/ebpfsentinel-warden-$$.sock}"

# require_bpf_token_env — skip unless this host can exercise token delegation.
require_bpf_token_env() {
    require_root
    # BPF token delegation (BPF_TOKEN_CREATE + delegated bpffs) is kernel 6.9+.
    require_kernel 6 9
}

# bpf_token_build_launcher — resolve (or build) the shipped `warden` broker binary
# and export its path. The split deployment runs the warden alongside the agent;
# this resolves the warden the suite drives. Prefers a prebuilt binary next to the
# agent (as CI's build job produces); falls back to `cargo build` from the project
# tree; skips the suite if neither yields it.
bpf_token_build_launcher() {
    if [ -n "$BPF_TOKEN_WARDEN_BIN" ] && [ -x "$BPF_TOKEN_WARDEN_BIN" ]; then
        return 0
    fi
    # Same directory as the agent binary the suite already located.
    local candidate="$(dirname "$AGENT_BIN")/warden"
    if [ -x "$candidate" ]; then
        BPF_TOKEN_WARDEN_BIN="$candidate"
        export BPF_TOKEN_WARDEN_BIN
        return 0
    fi
    require_tool cargo
    if ! (cd "$PROJECT_ROOT" && cargo build --release --bin warden) \
        >/tmp/warden-build-$$.log 2>&1; then
        skip "warden failed to build: $(cat /tmp/warden-build-$$.log)"
    fi
    BPF_TOKEN_WARDEN_BIN="${PROJECT_ROOT}/target/release/warden"
    [ -x "$BPF_TOKEN_WARDEN_BIN" ] || skip "warden binary not found after build"
    export BPF_TOKEN_WARDEN_BIN
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

# bpf_token_run <config> [seconds] — start the warden broker, then run the agent
# token-only against it for N seconds (default 9), capturing combined stdout+stderr
# to $BPF_TOKEN_LOG. The agent is a daemon, so `timeout` reaping it (exit 124) is
# the success path; the assertions inspect the captured log rather than an exit
# code. The warden is killed when the agent's window ends.
bpf_token_run() {
    local config="${1:?usage: bpf_token_run <config> [seconds]}"
    local secs="${2:-9}"
    chmod 640 "$config"
    # Stage the agent under /tmp so the user-namespace exec can reach it.
    install -m755 "$AGENT_BIN" "$BPF_TOKEN_AGENT_STAGE"
    : >"$BPF_TOKEN_LOG"
    rm -f "$BPF_TOKEN_WARDEN_SOCK"

    # Start the privileged warden broker. --uid 0: the test agent runs as root and
    # maps namespace-0 to real root, so it presents uid 0 over SO_PEERCRED.
    "$BPF_TOKEN_WARDEN_BIN" serve "$BPF_TOKEN_WARDEN_SOCK" --uid 0 \
        >>"$BPF_TOKEN_LOG" 2>&1 &
    BPF_TOKEN_WARDEN_PID=$!
    export BPF_TOKEN_WARDEN_PID
    # The agent's bootstrap connects once (no retry); wait for the socket.
    local _i
    for _i in $(seq 1 100); do
        [ -S "$BPF_TOKEN_WARDEN_SOCK" ] && break
        sleep 0.1
    done

    # Close inherited fds (>=3) before the agent. bats holds its TAP stream on fd
    # 3, which the agent would otherwise inherit — colliding with the module-BTF
    # fds it receives from the warden and the fds its token loader allocates. A
    # clean fd table keeps the received fds at low numbers as outside bats.
    (
        for _fd in $(seq 3 30); do eval "exec ${_fd}>&-" 2>/dev/null || true; done
        export EBPFSENTINEL_BPFFS="$BPF_TOKEN_BPFFS"
        export EBPFSENTINEL_WARDEN_SOCK="$BPF_TOKEN_WARDEN_SOCK"
        exec timeout "$secs" "$BPF_TOKEN_AGENT_STAGE" --config "$config" >>"$BPF_TOKEN_LOG" 2>&1
    ) || true

    kill "$BPF_TOKEN_WARDEN_PID" 2>/dev/null || true
    wait "$BPF_TOKEN_WARDEN_PID" 2>/dev/null || true
    BPF_TOKEN_WARDEN_PID=""
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

# bpf_token_cleanup — stop a stray warden, remove log, staged agent, socket,
# leftover mount. The warden is a build artifact (target/release or next to the
# agent), so it is never removed.
bpf_token_cleanup() {
    [ -n "$BPF_TOKEN_WARDEN_PID" ] && kill "$BPF_TOKEN_WARDEN_PID" 2>/dev/null || true
    umount "$BPF_TOKEN_BPFFS" 2>/dev/null || true
    rm -f "$BPF_TOKEN_LOG" "$BPF_TOKEN_AGENT_STAGE" "$BPF_TOKEN_WARDEN_SOCK" \
        "/tmp/warden-build-$$.log"
    rm -rf "$BPF_TOKEN_EBPF_STAGE"
}
