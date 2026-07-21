#!/usr/bin/env bash
# local_lane.bash — agent-drive helpers for the single-VM lane.
#
# `vm_helpers.bash` teaches the fleet to drive an agent that lives on
# another machine: `_agent_ssh`, `_agent_ssh_sudo` and `_agent_scp` reach it
# over SSH. helpers.bash only sources that file when EBPF_2VM_MODE=true.
#
# In the local lane the suite runs *on* the agent host, so those functions
# were simply undefined — and because nearly every call site ends in
# `|| true` (they are best-effort setup steps), the failure was invisible:
# directories were never created, services never started, and the tests that
# depended on them degraded into skips. This file supplies the local
# equivalents so the same suite text means the same thing in both lanes.
#
# Sourced by helpers.bash on the else-branch of the 2-VM check, so it never
# competes with vm_helpers.bash.

# _local_exec <command...> — mirror SSH argument semantics.
#
# Callers use two shapes: separate argv (`_agent_ssh test -x /path`) and a
# single string carrying a whole shell command (`_agent_ssh_sudo "agent
# capture start --filter 'tcp port 80'"`). SSH re-parses whatever it is
# given through the remote shell, so the single-string form works there;
# running it as argv locally would look for a file whose name is the entire
# command. Re-parse it the same way SSH would.
_local_exec() {
    if [ $# -eq 1 ] && [[ "${1}" == *[[:space:]]* ]]; then
        bash -c "${1}"
    else
        "$@"
    fi
}

# _agent_ssh <command...> — run a command on the agent host (here: locally).
_agent_ssh() {
    if [ $# -eq 0 ]; then
        echo "usage: _agent_ssh <command...>" >&2
        return 1
    fi
    _local_exec "$@"
}

# _agent_ssh_sudo <command...> — same, with privileges.
_agent_ssh_sudo() {
    if [ $# -eq 0 ]; then
        echo "usage: _agent_ssh_sudo <command...>" >&2
        return 1
    fi
    # Already root (the lane runs bats under sudo): skip the sudo hop so the
    # call also works on images without sudo installed.
    if [ "$(id -u)" -eq 0 ]; then
        _local_exec "$@"
    elif [ $# -eq 1 ] && [[ "${1}" == *[[:space:]]* ]]; then
        sudo bash -c "${1}"
    else
        sudo "$@"
    fi
}

# _agent_scp <local_path> <remote_path> — "copy to the agent host". Both
# paths are on this filesystem, so this is a copy, and a no-op when they
# resolve to the same file.
_agent_scp() {
    local src="${1:?usage: _agent_scp <local_path> <remote_path>}"
    local dest="${2:?usage: _agent_scp <local_path> <remote_path>}"

    [ -e "${src}" ] || {
        echo "_agent_scp: source missing: ${src}" >&2
        return 1
    }
    if [ "$(readlink -f "${src}" 2>/dev/null)" = "$(readlink -f "${dest}" 2>/dev/null)" ]; then
        return 0
    fi

    local dest_dir
    dest_dir="$(dirname "${dest}")"
    [ -d "${dest_dir}" ] || _agent_ssh_sudo mkdir -p "${dest_dir}" || return 1

    if [ -w "${dest_dir}" ]; then
        cp -f "${src}" "${dest}"
    else
        _agent_ssh_sudo cp -f "${src}" "${dest}"
    fi
}
