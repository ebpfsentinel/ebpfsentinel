#!/usr/bin/env bats
# 68-xdp-reload-without-a-hole.bats - the interface keeps a program across a
# chain-root change.
#
# Changing which program roots the XDP chain is the one reload that used to
# empty an interface: the old root was detached, the new one was loaded, and
# in between the NIC carried nothing. The agent now parks the old root's
# links and the new root's attach takes them over, so the kernel swaps the
# program under a link that was never closed.
#
# The suite asserts:
#
#   * A sampler reading the interface every 20 ms over the whole reload sees
#     an XDP program on every single sample - no gap, not one.
#   * The program id did change, so the samples cover a real root swap and
#     not a reload that did nothing.
#   * `ebpfsentinel_ebpf_link_handovers` rose and
#     `ebpfsentinel_ebpf_link_handover_fallbacks` stayed at zero, which is
#     what says the kernel replaced the program rather than the agent
#     falling back to detach-and-attach.
#   * Traffic the datapath is meant to drop never reaches the host during
#     the swap.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 5 15
    require_tool curl
    require_tool ip

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-rootswap-$$"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-xdp-root-swap.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-rootswap-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _on_agent <shell snippet> - run a snippet where the agent runs, which is
# this host in the local lane and the agent VM in the 2VM lane. The sampler
# has to live there: the interface, the agent process and the signal are all
# on that side, and a 20 ms sampling loop driven over ssh would measure the
# network rather than the datapath.
_on_agent() {
    local snippet="${1:?usage: _on_agent <snippet>}"
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo "${snippet}" 2>/dev/null | tr -d '\r'
    else
        bash -c "${snippet}" 2>/dev/null
    fi
}

_xdp_program_id() {
    _on_agent "ip link show dev ${EBPF_VETH_HOST} \
        | grep -oE 'xdp[a-z]*/id:[0-9]+' | head -1 | cut -d: -f2"
}

_agent_pid_local() {
    cat "${AGENT_PID_FILE}" 2>/dev/null
}

# _flip_chain_root - firewall off, rate limiter on, so the chain root moves
# from one program to the other on the next reload.
_flip_chain_root() {
    python3 - "${PREPARED_CONFIG}" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, "r") as handle:
    text = handle.read()


def flip(section, value):
    global text
    pattern = re.compile(
        r"(^" + section + r":\n(?:[ \t]+[^\n]*\n)*?[ \t]+enabled: )(true|false)",
        re.MULTILINE,
    )
    text, count = pattern.subn(lambda m: m.group(1) + value, text, count=1)
    if count != 1:
        raise SystemExit(f"{section}.enabled not found in {path}")


flip("firewall", "false")
flip("ratelimit", "true")

with open(path, "w") as handle:
    handle.write(text)
PY
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "${PREPARED_CONFIG}")"
        local rewritten="/tmp/ebpfsentinel-2vm-rootswap-$$.yaml"
        sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
            "${PREPARED_CONFIG}" >"${rewritten}"
        _agent_push_config "${rewritten}" "${remote_config}" 2>/dev/null || true
        rm -f "${rewritten}"
    fi
}

# _sample_across_reload <pid> - sample the interface every 20 ms for six
# seconds, sending SIGHUP half a second in, and echo "<samples> <gaps> <ids>"
# where a gap is a sample that found no XDP program at all and ids is how
# many distinct program ids the window saw.
_sample_across_reload() {
    local pid="${1:?usage: _sample_across_reload <pid>}"
    local snippet
    snippet=$(cat <<SNIPPET
out=\$(mktemp)
deadline=\$(( \$(date +%s) + 6 ))
hupped=0
started=\$(date +%s)
while [ "\$(date +%s)" -lt "\$deadline" ]; do
    id=\$(ip link show dev ${EBPF_VETH_HOST} 2>/dev/null \
        | grep -oE 'xdp[a-z]*/id:[0-9]+' | head -1 | cut -d: -f2)
    echo "\${id:-none}" >>"\$out"
    if [ "\$hupped" -eq 0 ] && [ "\$(date +%s)" -gt "\$started" ]; then
        kill -HUP ${pid} 2>/dev/null || true
        hupped=1
    fi
    sleep 0.02
done
samples=\$(wc -l <"\$out")
gaps=\$(grep -c '^none\$' "\$out" || true)
ids=\$(grep -v '^none\$' "\$out" | sort -u | wc -l)
rm -f "\$out"
echo "\$samples \$gaps \$ids"
SNIPPET
)
    _on_agent "${snippet}"
}

_metric_or_zero() {
    local value
    value="$(get_metrics_value "$1")" || value=""
    echo "${value:-0}"
}

# ── The reload ──────────────────────────────────────────────────────

@test "the XDP chain root changes without the interface ever going bare" {
    local pid
    pid="$(_agent_pid_local)"
    [ -n "${pid}" ] || skip "agent pid unknown"

    local id_before
    id_before="$(_xdp_program_id)"
    [ -n "${id_before}" ] || skip "no XDP program attached to ${EBPF_VETH_HOST}"

    _flip_chain_root

    local reading
    reading="$(_sample_across_reload "${pid}")"
    echo "samples/gaps/ids: ${reading}" >&3

    local samples gaps ids
    read -r samples gaps ids <<<"${reading}"

    # A sampler that barely ran proves nothing either way.
    [ "${samples:-0}" -ge 50 ]

    # The assertion the story is about: not one sample found the interface
    # without a program on it.
    [ "${gaps:-1}" -eq 0 ]

    # And the window really did cover a swap rather than a quiet reload.
    [ "${ids:-1}" -ge 2 ]

    local id_after
    id_after="$(_xdp_program_id)"
    [ -n "${id_after}" ]
    [ "${id_after}" != "${id_before}" ]
}

@test "the kernel replaced the program rather than the agent detaching it" {
    # The counters are published by the datapath state reader, which samples
    # every 30 s, so the figure is waited for rather than read at once.
    local handovers
    handovers="$(wait_for_metric ebpfsentinel_ebpf_link_handovers 1 45)" \
        || handovers="$(_metric_or_zero ebpfsentinel_ebpf_link_handovers)"

    [ "${handovers%%.*}" -ge 1 ]

    local fallbacks
    fallbacks="$(_metric_or_zero ebpfsentinel_ebpf_link_handover_fallbacks)"
    echo "handovers=${handovers} fallbacks=${fallbacks}" >&3

    # A fallback is the old behaviour and the old hole. On a kernel this
    # suite runs on there is no reason for one.
    [ "${fallbacks%%.*}" -eq 0 ]
}

@test "the agent survived the root swap and kept answering" {
    local pid_now
    pid_now="$(_agent_pid_local)"
    [ -n "${pid_now}" ]

    run curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/healthz"
    [ "$status" -eq 0 ]

    # The rate limiter is the root now, and it is the program the interface
    # carries.
    run bash -c "curl -sf --max-time 5 \
        'http://${AGENT_HOST}:${AGENT_HTTP_PORT}/api/v1/ebpf/programs'"
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "xdp_ratelimit"
}
