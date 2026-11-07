#!/usr/bin/env bats
# 133-every-object-both-loaders.bats - every object this build ships is loaded
# by the kernel through both ways the loader has into it.
#
# Suite 67 asks the agent, and the agent loads what its configuration names:
# the LSM objects, the signal and the two health tracepoints, the crypto
# uprobe and the two connect redirections are not in that set, so a verifier
# refusal in one of them shows up nowhere. `xtask ebpf-load` takes the list
# the build itself uses and hands each object to the agent's own loader -
# kfunc call sites prepatched, BTF sanitized, maps created, every program to
# BPF_PROG_LOAD - and reports program by program.
#
# Twice: once on the process's own capabilities, and once through a BPF token
# the shipped warden delegates, from a user namespace that holds no capability
# the kernel checks. The two are not the same load: the token run creates its
# BTF and maps under the token and reaches the module kfuncs through the BTF
# fds the warden hands over, so an object can pass one and fail the other.
#
# The privileged run also reads each program's translated instructions back
# and counts the kfunc calls in them, which is the kernel's own word that the
# prepatched call sites reached the verifier as kfunc calls. That run binds
# the XDP objects to a veth, the way the agent binds them to the interface it
# attaches to: unbound, the loader turns the receive metadata kfuncs into
# `-EOPNOTSUPP` before the verifier sees them, and veth answers both.
#
# Requires: root, kernel >= 6.12, local eBPF build, cargo or a prebuilt xtask.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/bpf_token_helpers'

IFACE="veth-load-test"
IFACE_PEER="veth-load-peer"

setup_file() {
    require_bpf_token_env
    require_ebpf_env

    export BPF_TOKEN_WARDEN_BIN BPF_TOKEN_LOG BPF_TOKEN_BPFFS \
        BPF_TOKEN_AGENT_STAGE BPF_TOKEN_EBPF_STAGE BPF_TOKEN_WARDEN_SOCK

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    bpf_token_build_launcher

    export XTASK_BIN="${XTASK_BIN:-${PROJECT_ROOT}/target/release/xtask}"
    if [ ! -x "$XTASK_BIN" ]; then
        (cd "$PROJECT_ROOT" && cargo build --release --bin xtask) >&2
    fi
    [ -x "$XTASK_BIN" ]

    export EBPF_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
    [ -f "${EBPF_DIR}/xdp-firewall" ]

    # The objects calling into a module carry its kfuncs, and the kernel
    # resolves them only against a module that is loaded.
    local module
    for module in nf_conntrack nf_nat fou xfrm_interface; do
        modprobe "$module" 2>/dev/null || true
    done

    # Somewhere the user-namespace run can read, both binary and objects.
    export STAGED_EBPF
    STAGED_EBPF="$(bpf_token_stage_ebpf_dir "$EBPF_DIR")"
    export XTASK_STAGE="/tmp/ebpfsentinel-xtask-$$"
    install -m755 "$XTASK_BIN" "$XTASK_STAGE"

    ip link add "$IFACE" type veth peer name "$IFACE_PEER" 2>/dev/null || true
    ip link set "$IFACE" up
    ip link set "$IFACE_PEER" up

    export LOAD_LOG="/tmp/ebpfsentinel-ebpf-load-$$.log"
}

teardown_file() {
    bpf_token_cleanup
    ip link del "$IFACE" 2>/dev/null || true
    rm -f "$XTASK_STAGE" "$LOAD_LOG"
}

# Report lines for fd 3, as TAP comments: a line of the report starts with
# `ok`, which bats would otherwise count as a test.
_note() {
    sed 's/^/# /' >&3
}

# The refusals in a report, with the verifier's own words cut to fit.
_refusals() {
    grep -A3 '^REFUSED' "$LOAD_LOG" | cut -c1-400
}

# Every object in the build list reported, none refused.
_assert_every_object_loaded() {
    local summary
    summary="$(grep '^loader: .*objects refused' "$LOAD_LOG" || true)"
    if [ -z "$summary" ] || ! echo "$summary" | grep -q 'objects refused: 0$'; then
        echo "# ${summary:-no summary line}" >&3
        _refusals | _note
        tail -5 "$LOAD_LOG" | _note
        false
    fi
    [ "$(grep -c '^ok ' "$LOAD_LOG")" -ge 1 ]
    grep -E '^(loader|optional) ' "$LOAD_LOG" | _note
}

@test "every object loads on the process's own capabilities" {
    "$XTASK_STAGE" ebpf-load --dir "$STAGED_EBPF" >"$LOAD_LOG" 2>&1 || true
    _assert_every_object_loaded
}

@test "bound to a device, every object loads and the kernel counts its kfunc calls" {
    "$XTASK_STAGE" ebpf-load --dir "$STAGED_EBPF" --dev-bound "$IFACE" \
        >"$LOAD_LOG" 2>&1 || true
    _assert_every_object_loaded

    # An object with call sites must come out of the verifier with calls in
    # one of its programs at least: sites rewritten into something other than
    # a kfunc call would load as plain instructions and count zero here.
    local per_object silent
    per_object="$(awk '$1 == "ok" {
            sites = $0; sub(/.*kfunc_sites=/, "", sites); sub(/ .*/, "", sites)
            calls = $0; sub(/.*kfunc_calls=/, "", calls)
            if (sites + 0 > 0) { has[$2] = 1; if (calls + 0 > 0) seen[$2] += calls }
        }
        END { for (o in has) print o, seen[o] + 0 }' "$LOAD_LOG" | sort)"
    echo "$per_object" | sed 's/^/kfunc calls in /' | _note
    [ -n "$per_object" ]
    silent="$(echo "$per_object" | awk '$2 == 0 {print $1}')"
    if [ -n "$silent" ]; then
        echo "# call sites with no kfunc call in the kernel: ${silent}" >&3
        false
    fi
}

@test "every object loads through a BPF token from a user namespace, bound to a device" {
    : >"$LOAD_LOG"
    rm -f "$BPF_TOKEN_WARDEN_SOCK"
    "$BPF_TOKEN_WARDEN_BIN" serve "$BPF_TOKEN_WARDEN_SOCK" --uid 0 >>"$LOAD_LOG" 2>&1 &
    BPF_TOKEN_WARDEN_PID=$!
    local _i
    for _i in $(seq 1 100); do
        [ -S "$BPF_TOKEN_WARDEN_SOCK" ] && break
        sleep 0.1
    done

    (
        for _fd in $(seq 3 30); do eval "exec ${_fd}>&-" 2>/dev/null || true; done
        export EBPFSENTINEL_BPFFS="$BPF_TOKEN_BPFFS"
        export EBPFSENTINEL_WARDEN_SOCK="$BPF_TOKEN_WARDEN_SOCK"
        exec timeout 300 "$XTASK_STAGE" ebpf-load --dir "$STAGED_EBPF" \
            --dev-bound "$IFACE" >>"$LOAD_LOG" 2>&1
    ) || true

    kill "$BPF_TOKEN_WARDEN_PID" 2>/dev/null || true
    wait "$BPF_TOKEN_WARDEN_PID" 2>/dev/null || true
    BPF_TOKEN_WARDEN_PID=""

    grep -q '^loader: token ' "$LOAD_LOG" || {
        echo "# the run never reached the token loader" >&3
        tail -20 "$LOAD_LOG" | _note
        false
    }
    _assert_every_object_loaded
}
