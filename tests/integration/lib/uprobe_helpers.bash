#!/usr/bin/env bash
# uprobe_helpers.bash - is a probe program attached, read from the kernel.
#
# /healthz answers 200 with no probe attached at all, and the program status
# gauge says the object loaded, not that any library was found to attach to.
# The kernel's link table is what holds an attached uprobe: one link per
# attach, each naming the program it runs. On the remote lanes the bpftool
# wrapper from vm_helpers runs on the agent VM, which is where the links live.
#
# Where the BPF LSM is on, the agent's bpf guard refuses every other task a
# handle on its links, root included, so the link table answers with an error
# and the links are pinned with no descriptor left to read in /proc. The
# agent's uprobe inventory is then the reading: an entry enters it only once
# the kernel has handed back the link for that probe.
#
# Load after ebpf_helpers.

# uprobe_link_count <program-name> - links in the kernel running a program of
# that name (the kernel keeps the first 15 bytes of a program name). Prints 0
# when none, fails when bpftool or jq cannot answer.
uprobe_link_count() {
    local name="${1:?usage: uprobe_link_count <program-name>}"
    local progs links ids
    links="$(bpftool -j link show 2>/dev/null)" || links=""
    if [ -n "${links}" ] && echo "${links}" | jq -e 'all(.[]; has("error") | not)' >/dev/null 2>&1; then
        progs="$(bpftool -j prog show 2>/dev/null)" || return 1
        ids="$(echo "${progs}" | jq -c --arg n "${name:0:15}" \
            '[.[] | select(.name == $n) | .id]')" || return 1
        echo "${links}" | jq --argjson ids "${ids}" \
            '[.[] | select(.prog_id as $p | any($ids[]; . == $p))] | length'
        return
    fi
    # The link table is refused: read what the agent recorded the kernel
    # accepting.
    local body
    body="$(api_get /api/v1/ebpf/uprobes 2>/dev/null)" || return 1
    echo "${body}" | jq --arg n "${name}" '[.probes[]? | select(.program == $n)] | length'
}

# wait_for_uprobe_link <program-name> [max_seconds] - wait until at least one
# link runs the named program. Attaching to the libraries already mapped runs
# after start-up on the lifecycle watcher, so the first reading may precede it.
wait_for_uprobe_link() {
    local name="${1:?usage: wait_for_uprobe_link <program-name> [max_seconds]}"
    local max="${2:-20}" i count=0
    for i in $(seq 1 "${max}"); do
        count="$(uprobe_link_count "${name}")" || count=0
        [ "${count:-0}" -ge 1 ] && return 0
        sleep 1
    done
    echo "no kernel link runs ${name} after ${max}s" >&2
    bpftool link show 2>&1 | head -20 >&2 || true
    api_get /api/v1/ebpf/uprobes >&2 2>/dev/null || true
    return 1
}
