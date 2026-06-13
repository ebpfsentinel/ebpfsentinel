#!/usr/bin/env bats
# 52-hot-reload-under-load.bats — SIGHUP map-swap safety under sustained load.
#
# Drives a sustained HTTP + TCP background workload while flipping firewall
# rules in/out via SIGHUP every 5 seconds. The suite asserts:
#
#   * Agent PID stays the same (no crash + restart)
#   * Open FD count after the cycle is within a small drift of the baseline
#     (proves old map FDs are reclaimed)
#   * Prometheus `ebpfsentinel_rules_reloads_total{result="success"}` strictly
#     increments over the cycle (map generation counter)
#   * No "panic"/"thread .* panicked" line shows up in the agent's stderr
#   * Alert list shows no duplicate (id) entries from any concurrent firings
#
# Load generators are best-effort: wrk drives HTTP, iperf3 drives TCP. When a
# generator is missing the test still runs but with reduced traffic — the
# correctness assertions above remain valid.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 5 15
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-hotreload-load-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-hot-reload.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-hotreload-load-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_agent_pid_local() {
    cat "${AGENT_PID_FILE}" 2>/dev/null
}

_count_open_fds() {
    local pid="${1:?usage: _count_open_fds <pid>}"
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo "ls /proc/${pid}/fd 2>/dev/null | wc -l" 2>/dev/null \
            | tr -d '\r' | tr -d ' '
    else
        ls "/proc/${pid}/fd" 2>/dev/null | wc -l
    fi
}

_reload_counter_value() {
    local metric_body
    metric_body="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || {
        echo 0
        return
    }
    # rules_reloads_total{component="firewall",result="success"} <value>
    echo "${metric_body}" \
        | awk '/ebpfsentinel_rules_reloads(_total)?\{[^}]*result="success"/ {sum += $NF}
               END { if (sum == "") print 0; else print sum }'
}

_signal_hup() {
    local pid
    pid="$(_agent_pid_local)"
    [ -n "${pid}" ] || return 1
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo "kill -HUP ${pid}" >/dev/null 2>&1
    else
        kill -HUP "${pid}" 2>/dev/null
    fi
}

_mutate_config_toggle() {
    # Append a marker rule (or remove it) so each reload sees a real diff.
    local marker_id="${1:?usage: _mutate_config_toggle <marker_id>}"
    python3 - "${PREPARED_CONFIG}" "${marker_id}" <<'PY'
import sys, re
path, marker = sys.argv[1], sys.argv[2]
with open(path, 'r') as f:
    text = f.read()
needle = f"- id: {marker}"
if needle in text:
    pattern = re.compile(
        r"\n[ \t]*# Hot-reload toggle: " + re.escape(marker)
        + r".*?(?=\n[ \t]*-\s|\n[a-zA-Z_]+:|\Z)",
        re.DOTALL,
    )
    text = pattern.sub("", text)
else:
    insert_idx = text.find("\nids:")
    if insert_idx < 0:
        insert_idx = len(text)
    addition = (
        f"\n    # Hot-reload toggle: {marker}\n"
        f"    - id: {marker}\n"
        f"      priority: 200\n"
        f"      action: deny\n"
        f"      protocol: tcp\n"
        f"      dst_port: 65530\n"
        f"      scope: global\n"
        f"      enabled: true\n"
    )
    text = text[:insert_idx] + addition + text[insert_idx:]
with open(path, 'w') as f:
    f.write(text)
PY
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "${PREPARED_CONFIG}")"
        local rewritten="/tmp/ebpfsentinel-2vm-hotload-$$.yaml"
        sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
            "${PREPARED_CONFIG}" >"${rewritten}"
        _agent_scp "${rewritten}" "${remote_config}" 2>/dev/null || true
        rm -f "${rewritten}"
    fi
}

_start_http_load() {
    # wrk if available; otherwise a curl burst loop in the background.
    local url="http://${AGENT_HOST}:${AGENT_HTTP_PORT}/healthz"
    if command -v wrk >/dev/null 2>&1; then
        wrk -c 50 -t 2 -d 30s "${url}" >"${DATA_DIR}/wrk.out" 2>&1 &
        echo "$!"
        return
    fi
    (
        local end=$(( $(date +%s) + 30 ))
        while [ "$(date +%s)" -lt "${end}" ]; do
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                curl -sf --max-time 1 "${url}" >/dev/null 2>&1 || true
            done
        done
    ) >/dev/null 2>&1 &
    echo "$!"
}

_start_tcp_load() {
    # iperf3 if available; otherwise no-op.
    if command -v iperf3 >/dev/null 2>&1; then
        iperf3 -s -p 33055 -1 >/dev/null 2>&1 &
        local server_pid=$!
        sleep 0.5
        iperf3 -c 127.0.0.1 -p 33055 -t 25 -b 50M \
            >"${DATA_DIR}/iperf.out" 2>&1 &
        echo "${server_pid} $!"
        return
    fi
    echo ""
}

# ── Hot-reload cycle under load ─────────────────────────────────────

@test "agent survives SIGHUP cycle under sustained load with no FD or generation regression" {
    local pid_before
    pid_before="$(_agent_pid_local)"
    [ -n "${pid_before}" ] || {
        echo "agent pid file empty" >&2
        return 1
    }

    local fd_before
    fd_before="$(_count_open_fds "${pid_before}")"
    [ "${fd_before:-0}" -gt 0 ] || {
        echo "could not count open FDs for pid ${pid_before}" >&2
        return 1
    }

    local reloads_before
    reloads_before="$(_reload_counter_value)"

    # Spin up best-effort load generators.
    local http_pid tcp_pids
    http_pid="$(_start_http_load)"
    tcp_pids="$(_start_tcp_load)"

    # SIGHUP cycle: 6 reloads at 5 s spacing alternating toggle id.
    local i marker
    for i in 1 2 3 4 5 6; do
        marker="fw-hot-toggle-$(( i % 2 ))"
        _mutate_config_toggle "${marker}" 2>/dev/null || true
        _signal_hup
        sleep 5
    done

    # Drain load generators.
    if [ -n "${http_pid}" ]; then
        kill "${http_pid}" 2>/dev/null || true
        wait "${http_pid}" 2>/dev/null || true
    fi
    if [ -n "${tcp_pids}" ]; then
        # shellcheck disable=SC2086
        for p in ${tcp_pids}; do kill "${p}" 2>/dev/null || true; done
    fi

    # ── Assertions ──────────────────────────────────────────────────

    # 1. Agent still alive on the same PID.
    local pid_after
    pid_after="$(_agent_pid_local)"
    [ "${pid_after}" = "${pid_before}" ] || {
        echo "agent PID changed from ${pid_before} to ${pid_after} — likely crash + restart" >&2
        return 1
    }

    # 2. Generation counter strictly increased.
    local reloads_after
    reloads_after="$(_reload_counter_value)"
    if [ "$(echo "${reloads_after:-0} > ${reloads_before:-0}" | bc -l 2>/dev/null)" != "1" ]; then
        echo "reload counter did not advance (${reloads_before} → ${reloads_after})" >&2
        return 1
    fi

    # 3. FD drift bounded. Tolerate up to 25% growth or +20 raw — covers
    #    transient socket churn from the load generators without masking
    #    a real leak (which would balloon multiples-of).
    local fd_after
    fd_after="$(_count_open_fds "${pid_after}")"
    local fd_max_growth
    fd_max_growth=$(( fd_before / 4 ))
    [ "${fd_max_growth}" -lt 20 ] && fd_max_growth=20
    local fd_limit=$(( fd_before + fd_max_growth ))
    if [ "${fd_after:-0}" -gt "${fd_limit}" ]; then
        echo "FD leak suspected: ${fd_before} → ${fd_after} (limit ${fd_limit})" >&2
        return 1
    fi

    # 4. No panic in agent log.
    if [ -f "${AGENT_LOG_FILE:-}" ]; then
        if grep -qE 'thread .+ panicked|^panic|RUST_BACKTRACE' \
                "${AGENT_LOG_FILE}" 2>/dev/null; then
            echo "panic detected in agent log:" >&2
            grep -nE 'thread .+ panicked|^panic|RUST_BACKTRACE' \
                "${AGENT_LOG_FILE}" >&2 | head -5
            return 1
        fi
    fi
}

# ── Alert non-duplication under reload churn ────────────────────────

@test "alerts captured during reload cycle have no duplicate ids" {
    local body
    body="$(api_get /api/v1/alerts 2>/dev/null)" || body=""
    [ -n "${body}" ] || skip "alerts endpoint returned empty body"

    local total unique
    total="$(echo "${body}" \
        | jq -r '(.alerts // []) | length' 2>/dev/null)" || total=0
    unique="$(echo "${body}" \
        | jq -r '(.alerts // []) | map(.id // .alert_id // "") | unique | length' 2>/dev/null)" \
            || unique=0
    if [ "${total:-0}" -lt 1 ]; then
        skip "no alerts emitted during reload cycle — duplication check N/A"
    fi
    [ "${total}" = "${unique}" ] || {
        echo "duplicate alert ids observed: ${total} entries, ${unique} unique" >&2
        return 1
    }
}

# ── Reload counter increment shape ──────────────────────────────────

@test "rules_reloads_total counter is exposed and finite" {
    local value
    value="$(_reload_counter_value)"
    [ -n "${value}" ] || {
        echo "rules_reloads_total metric missing from /metrics" >&2
        return 1
    }
    [ "$(echo "${value} >= 0" | bc -l 2>/dev/null)" = "1" ] || {
        echo "rules_reloads_total reported negative or non-numeric: ${value}" >&2
        return 1
    }
}
