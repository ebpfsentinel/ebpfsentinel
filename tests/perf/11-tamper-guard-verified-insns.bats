#!/usr/bin/env bats
# 11-tamper-guard-verified-insns.bats - how many instructions the verifier
# walks to accept each lsm-tamper-guard program, now and before the cgroup
# file name comparison moved to the bpf_strcmp kfunc.
#
# The guard compared the name of a cgroup file a write aims at by copying it
# with bpf_probe_read_kernel_str and walking the bytes in a bounded loop. It
# now makes two bpf_strcmp calls instead. The claim worth checking is that
# the verifier has less to walk, since a bounded loop is walked once per
# iteration it could take: verified_insns, the count bpf_prog_info returns
# for a loaded program (the field `bpftool prog show -j` prints), answers it
# for a given kernel. It is a perf suite and not an integration suite because
# it measures a cost (the verifier's work at every start of the agent, and
# its distance from the kernel's one-million-instruction ceiling) and keeps a
# dated result, where the integration suites assert what the product does.
# Nothing here attaches: loading is enough for the verifier to run, so the
# kernel does not need the BPF LSM active, only the program type.
#
# Two trees, one kernel, one loader:
#   current   the objects the agent VM runs (EBPF_PROGRAM_DIR, else
#             /usr/local/lib/ebpfsentinel, else the tree's release build)
#   baseline  lsm-tamper-guard built at the commit before the change
#             (33c5e585^), in TAMPER_GUARD_BASELINE_DIR on the agent VM
# Each tree is loaded LOADS times, by up to two loaders:
#   xtask     `cargo xtask ebpf-load --dir <dir>` (XTASK_BIN), the agent's own
#             loader. It prints verified=<n> per program from bpf_prog_info.
#             It loads every object it knows, so it is pointed at a directory
#             holding only lsm-tamper-guard and the other objects' refusals
#             are expected; it closes each program after reading it, which is
#             why bpftool cannot be asked about them afterwards.
#   bpftool   `bpftool prog loadall <obj> <bpffs dir>` then `bpftool prog show
#             pinned` per program, then the pins removed.
# The criteria read one loader for both trees, never one loader per tree:
# xtask where it loaded both, else bpftool where it loaded both.
#
# Pass criteria (asserted by the last test):
#   stable     every load of a tree gave the same count per program (the
#              verifier is deterministic for one object on one kernel; a
#              difference means something else changed between loads)
#   not_worse  each program's current count is at most its baseline count
#              plus TAMPER_GUARD_MAX_GROWTH_INSNS (default 0)
#   present    the same five programs in both trees
# The difference per program and in total is reported; a reduction is the
# expectation, not asserted, so a kernel whose verifier prunes the old loop
# well does not fail the suite.
#
# Limits: the count is a property of one kernel's verifier; it says nothing
# of run time (perf/07 and the integration suites cover the guard at run
# time). The baseline object lacks the commits since 33c5e585 only where they
# touched the shared helpers, which rustfmt and helper additions did not
# change in this program's code.
#
# Requires: the local lane on the agent VM (root), kernel >= 6.18, jq, and
# the baseline object (tests/perf/README.md says how to build it). bpftool or
# the xtask binary, at least one of them loading both trees. Writes
# /tmp/ebpfsentinel-tamper-guard-verified-insns.json and
# results/<date>-tamper-guard-verified-insns/ (report.json, raw/).

load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

TG_REPORT="/tmp/ebpfsentinel-tamper-guard-verified-insns.json"
TG_OBJECT="lsm-tamper-guard"
TG_PROGRAMS="tamper_guard_task_kill tamper_guard_ptrace tamper_guard_unlink tamper_guard_rename tamper_guard_file_open"
TAMPER_GUARD_BASELINE_DIR="${TAMPER_GUARD_BASELINE_DIR:-/var/tmp/ebpfsentinel-tamper-guard-baseline}"
TAMPER_GUARD_MAX_GROWTH_INSNS="${TAMPER_GUARD_MAX_GROWTH_INSNS:-0}"
LOADS="${LOADS:-3}"

setup_file() {
    # The verifier runs where the object is loaded; from the traffic VM this
    # would count against the wrong kernel.
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "the verifier count is read on the agent host itself (local lane only)"
    fi
    require_root
    require_kernel 6 18
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export XTASK_BIN="${XTASK_BIN:-${PROJECT_ROOT}/target/debug/xtask}"

    export CURRENT_DIR="${TAMPER_GUARD_CURRENT_DIR:-}"
    if [ -z "$CURRENT_DIR" ]; then
        local d
        for d in "${EBPF_PROGRAM_DIR:-}" /usr/local/lib/ebpfsentinel "${PROJECT_ROOT}/target/bpfel-unknown-none/release"; do
            if [ -n "$d" ] && [ -s "${d}/${TG_OBJECT}" ]; then
                CURRENT_DIR="$d"
                break
            fi
        done
    fi
    [ -n "$CURRENT_DIR" ] && [ -s "${CURRENT_DIR}/${TG_OBJECT}" ] \
        || soft_skip "no current ${TG_OBJECT} object (set TAMPER_GUARD_CURRENT_DIR)"
    [ -s "${TAMPER_GUARD_BASELINE_DIR}/${TG_OBJECT}" ] \
        || soft_skip "no baseline ${TG_OBJECT} in ${TAMPER_GUARD_BASELINE_DIR}: build it as tests/perf/README.md says"

    export RESULTS_DIR
    RESULTS_DIR="${PERF_RESULTS_DIR:-${BATS_TEST_DIRNAME}/results}/$(date +%F)-tamper-guard-verified-insns"
    mkdir -p "${RESULTS_DIR}/raw"
    export WORK_DIR="/tmp/ebpfsentinel-tamper-guard-insns-$$"
    rm -rf "$WORK_DIR"
    mkdir -p "${WORK_DIR}/current" "${WORK_DIR}/baseline"
    cp "${CURRENT_DIR}/${TG_OBJECT}" "${WORK_DIR}/current/"
    cp "${TAMPER_GUARD_BASELINE_DIR}/${TG_OBJECT}" "${WORK_DIR}/baseline/"

    local baseline_commit
    baseline_commit="$(head -1 "${TAMPER_GUARD_BASELINE_DIR}/COMMIT" 2>/dev/null)"
    jq -n --arg kernel "$(uname -r)" --arg lsm "$(cat /sys/kernel/security/lsm 2>/dev/null)" \
        --arg current_dir "$CURRENT_DIR" --arg baseline_dir "$TAMPER_GUARD_BASELINE_DIR" \
        --arg baseline_commit "${baseline_commit:-unrecorded}" \
        --arg current_sha "$(sha256sum "${CURRENT_DIR}/${TG_OBJECT}" | cut -d' ' -f1)" \
        --arg baseline_sha "$(sha256sum "${TAMPER_GUARD_BASELINE_DIR}/${TG_OBJECT}" | cut -d' ' -f1)" \
        --argjson loads "$LOADS" \
        '{kernel: $kernel, active_lsms: $lsm, loads: $loads,
          trees: {current: {dir: $current_dir, sha256: $current_sha},
                  baseline: {dir: $baseline_dir, commit: $baseline_commit, sha256: $baseline_sha}},
          counts: {}, status: {}}' > "$TG_REPORT"
}

teardown_file() {
    _bpftool_unpin 2>/dev/null || true
    [ -n "${RESULTS_DIR:-}" ] && [ -s "$TG_REPORT" ] && cp "$TG_REPORT" "${RESULTS_DIR}/report.json"
    rm -rf "${WORK_DIR:-/tmp/ebpfsentinel-tamper-guard-insns-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_report() {
    local tmp
    tmp="$(jq "$@" "$TG_REPORT")" && printf '%s\n' "$tmp" > "$TG_REPORT"
}

PIN_DIR="/sys/fs/bpf/ebpfsentinel-perf-tamper-guard"

_bpftool_unpin() {
    rm -rf "$PIN_DIR"
}

# _xtask_counts <tree> <load> - one load through the agent's loader, printing
# {"<program>": <verified>} or nothing when the object was refused.
_xtask_counts() {
    local out="${RESULTS_DIR}/raw/xtask-$1-$2.txt"
    # Non-zero on purpose: every other object is absent from the directory.
    "$XTASK_BIN" ebpf-load --dir "${WORK_DIR}/$1" > "$out" 2>&1 || true
    awk -v obj="$TG_OBJECT" '
        $1 == "ok" && $2 == obj {
            for (i = 3; i <= NF; i++) if ($i ~ /^verified=/) { sub(/^verified=/, "", $i); v = $i }
            printf "%s\t%s\n", $3, v
        }' "$out" \
        | jq -c -R -s 'split("\n") | map(select(length > 0) | split("\t") | {key: .[0], value: (.[1] | tonumber)})
                    # The loader prints 0 where bpf_prog_info was unreadable.
                    | map(select(.value > 0))
                    | if length == 0 then empty else from_entries end'
}

# _bpftool_counts <tree> <load> - one load through libbpf, each program read
# back by its pin. Keyed by the name bpftool prints, which is the kernel's
# 15-byte name unless bpftool rebuilt the full one from BTF; the report maps
# either onto the full name, the five names differing within 15 bytes.
_bpftool_counts() {
    local out="${RESULTS_DIR}/raw/bpftool-$1-$2.txt" pin counts='{}' v
    _bpftool_unpin
    mkdir -p "$PIN_DIR"
    if ! bpftool prog loadall "${WORK_DIR}/$1/${TG_OBJECT}" "$PIN_DIR" > "$out" 2>&1; then
        _bpftool_unpin
        return 0
    fi
    for pin in "$PIN_DIR"/*; do
        [ -e "$pin" ] || continue
        v="$(bpftool -j prog show pinned "$pin" 2>>"$out" \
            | jq -c 'select(.verified_insns != null) | {(.name): .verified_insns}')"
        [ -n "$v" ] && counts="$(jq -c --argjson v "$v" '. + $v' <<< "$counts")"
    done
    _bpftool_unpin
    [ "$counts" = "{}" ] || echo "$counts"
}

# _measure <loader> - LOADS loads of each tree, every count kept.
_measure() {
    local loader="$1" tree i counts
    for tree in baseline current; do
        for i in $(seq 1 "$LOADS"); do
            counts="$("_${loader}_counts" "$tree" "$i")"
            if [ -z "$counts" ]; then
                _report --arg l "$loader" --arg t "$tree" \
                    --arg r "${loader} could not load the ${tree} object (raw/${loader}-${tree}-${i}.txt)" \
                    '.status[$l + "_" + $t] = $r'
                echo "${loader}: ${tree} refused, see raw/${loader}-${tree}-${i}.txt" >&3
                break
            fi
            _report --arg l "$loader" --arg t "$tree" --argjson c "$counts" '.counts[$l][$t] += [$c]'
            echo "${loader} ${tree} load ${i}: ${counts}" >&3
        done
    done
}

# ── Tests ───────────────────────────────────────────────────────────

@test "xtask ebpf-load: verified instructions per program, both trees" {
    [ -x "$XTASK_BIN" ] || env_skip "no xtask binary at ${XTASK_BIN} (cargo build -p xtask, or set XTASK_BIN)"
    _measure xtask
}

@test "bpftool prog loadall: verified instructions per program, both trees" {
    command -v bpftool >/dev/null 2>&1 || env_skip "bpftool not installed"
    _measure bpftool
}

@test "report: per-program counts, differences and the criteria" {
    _report --argjson growth "$TAMPER_GUARD_MAX_GROWTH_INSNS" --arg want "$TG_PROGRAMS" '
        def both(l): (.counts[l].baseline | length) > 0 and (.counts[l].current | length) > 0;
        ($want | split(" ")) as $names
        # A key is the full name or the first 15 bytes of it.
        | def norm: . as $m | [$names[] as $w
              | {key: $w, value: ([$m | to_entries[] | select(.key as $k | $w | startswith($k)) | .value] | first)}]
            | from_entries;
        .counts |= with_entries(.value |= with_entries(.value |= map(norm)))
        | (if both("xtask") then "xtask" elif both("bpftool") then "bpftool" else null end) as $l
        | .loader = $l
        | if $l == null then .criteria = null else
            .counts[$l] as $c
            | ($c.baseline[0]) as $b | ($c.current[0]) as $n
            | .programs = [$names[] | {program: ., baseline: $b[.], current: $n[.],
                  delta: (if $b[.] != null and $n[.] != null then $n[.] - $b[.] else null end)}]
            | .total = (if ([$b[], $n[]] | all(. != null))
                        then {baseline: ([$b[]] | add), current: ([$n[]] | add),
                              delta: (([$n[]] | add) - ([$b[]] | add))}
                        else null end)
            | .criteria = {
                stable: (($c.baseline | unique | length) == 1 and ($c.current | unique | length) == 1),
                present: ([$b[], $n[]] | all(. != null)),
                not_worse: ([.programs[] | .delta != null and .delta <= $growth] | all)
              }
          end
        | .threshold = {max_growth_insns: $growth}
    '
    cp "$TG_REPORT" "${RESULTS_DIR}/report.json"
    echo "loader: $(jq -r '.loader' "$TG_REPORT")" >&3
    echo "programs: $(jq -c '.programs' "$TG_REPORT")" >&3
    echo "total: $(jq -c '.total' "$TG_REPORT")" >&3
    echo "status: $(jq -c '.status' "$TG_REPORT")" >&3
    echo "criteria: $(jq -c '.criteria' "$TG_REPORT")" >&3
    echo "written to ${RESULTS_DIR}" >&3
    jq -e '.loader != null' "$TG_REPORT" >/dev/null || {
        echo "no loader loaded both trees: $(jq -c '.status' "$TG_REPORT")" >&2
        return 1
    }
    jq -e '[.criteria[] | select(. == false)] | length == 0' "$TG_REPORT" >/dev/null || {
        echo "criteria not met: $(jq -c '.criteria | with_entries(select(.value == false))' "$TG_REPORT")" >&2
        return 1
    }
}
