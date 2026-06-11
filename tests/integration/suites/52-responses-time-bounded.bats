#!/usr/bin/env bats
# 52-responses-time-bounded.bats — Time-bounded response action lifecycle.
#
# Exercises the agent's response engine via the REST surface that backs
# the `ebpfsentinel-agent responses {create,list,revoke}` CLI:
#
#   * POST   /api/v1/responses/manual  — create a TTL-bound block_ip action
#   * GET    /api/v1/responses          — list active actions
#   * DELETE /api/v1/responses/{id}     — revoke an action before TTL
#
# The response engine is in-memory (HashMap keyed by id). Manual response
# entries do NOT mirror into the firewall map — that is reserved for the
# auto_response pipeline. Suite 52 therefore asserts engine visibility +
# TTL expiry + early revoke; firewall-map mirroring is out of scope.
#
# CLI shape note: the actual subcommand is
#   responses create --action <block_ip|throttle_ip> --target <ip> --ttl <dur>
# and the early-cancel verb is `responses revoke <id>`. The bats here
# uses --ttl and `revoke` to match the binary.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/responses_helpers'

setup_file() {
    require_kernel 5 15
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-responses-$$"
    mkdir -p "$DATA_DIR"

    # The responses fixture enables xdp-firewall on the netns interface, so the
    # veth must exist before the agent starts — this suite is otherwise
    # self-contained (the response engine is in-memory).
    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-responses.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-responses-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Create + list ───────────────────────────────────────────────────

@test "responses create surfaces a TTL-bound entry in /api/v1/responses" {
    local id
    id="$(create_response block_ip 198.51.100.42 60s)"
    [ -n "${id}" ] || {
        echo "create_response returned empty id (HTTP ${HTTP_STATUS:-?})" >&2
        return 1
    }
    export _RESP_CREATED_ID="${id}"

    local present
    present="$(response_present "${id}")"
    [ "${present}" = "1" ] || {
        echo "created response ${id} not visible in list_responses" >&2
        return 1
    }

    local remaining
    remaining="$(response_remaining_secs "${id}")"
    [ -n "${remaining}" ] || {
        echo "no remaining_secs field for ${id}" >&2
        return 1
    }
    # Fresh entry must have remaining_secs > 0 and <= configured ttl.
    [ "${remaining}" -gt 0 ] && [ "${remaining}" -le 60 ]
}

# ── TTL auto-expire ─────────────────────────────────────────────────

@test "responses TTL auto-expires after configured duration" {
    local id
    id="$(create_response block_ip 198.51.100.43 4s)"
    [ -n "${id}" ] || {
        echo "create_response returned empty id (HTTP ${HTTP_STATUS:-?})" >&2
        return 1
    }

    # Brief check that it is actually active right after creation.
    [ "$(response_present "${id}")" = "1" ]

    # Wait past the TTL plus a small sweep cushion.
    wait_for_response_expired "${id}" 15 1 || {
        echo "response ${id} did not drop from active list within 15s" >&2
        list_responses >&2
        return 1
    }
}

# ── Early revoke via DELETE ─────────────────────────────────────────

@test "responses revoke removes an entry before TTL" {
    local id
    id="$(create_response block_ip 198.51.100.44 300s)"
    [ -n "${id}" ] || {
        echo "create_response returned empty id (HTTP ${HTTP_STATUS:-?})" >&2
        return 1
    }
    [ "$(response_present "${id}")" = "1" ]

    revoke_response "${id}" || {
        echo "revoke_response failed for ${id} (HTTP ${HTTP_STATUS:-?})" >&2
        return 1
    }

    # After revoke the entry must no longer count as active.
    local present
    present="$(response_present "${id}")"
    [ "${present}" = "0" ] || {
        echo "response ${id} still active after revoke" >&2
        list_responses >&2
        return 1
    }
}

# ── CLI parity with REST (skipped when CLI is unavailable) ──────────

@test "responses create via CLI surfaces in REST list_active" {
    if ! _agent_ssh test -x /usr/local/bin/ebpfsentinel-agent 2>/dev/null; then
        skip "ebpfsentinel-agent CLI not installed on agent VM"
    fi

    # CLI uses --ttl (story prose calls it --duration; the binary's clap
    # spec is --ttl, so we use that).
    local out
    out="$(_agent_ssh_sudo /usr/local/bin/ebpfsentinel-agent --output json \
        responses create \
        --action block_ip --target 198.51.100.45 --ttl 60s 2>&1)" || {
        echo "CLI responses create failed: ${out}" >&2
        return 1
    }

    # Extract the id surfaced by the CLI (json output mirrors the REST DTO).
    local id
    id="$(echo "${out}" | jq -r '.id // empty' 2>/dev/null)" || true
    if [ -z "${id}" ]; then
        # Best-effort fallback — list and pick the most recent matching target.
        id="$(list_responses \
            | jq -r '.actions[] | select(.target == "198.51.100.45") | .id' \
            | tail -1)"
    fi
    [ -n "${id}" ] || {
        echo "could not resolve CLI-created response id" >&2
        echo "stdout: ${out}" >&2
        return 1
    }

    [ "$(response_present "${id}")" = "1" ]
}

# ── Audit trail: create + TTL expiry land `responses` audit entries ──

@test "responses create and TTL expiry emit responses audit entries" {
    # A fresh create must land a responses/rule_added audit entry.
    local before_add
    before_add="$(audit_log_count responses rule_added)" || before_add=0

    local id
    id="$(create_response block_ip 198.51.100.46 4s)"
    [ -n "${id}" ] || {
        echo "create_response returned empty id (HTTP ${HTTP_STATUS:-?})" >&2
        return 1
    }

    local after_add
    after_add="$(audit_log_count responses rule_added)" || after_add=0
    [ "${after_add}" -gt "${before_add}" ] || {
        echo "no responses/rule_added audit entry after create (${before_add} -> ${after_add})" >&2
        return 1
    }

    # Once the TTL elapses, the background sweeper must drop the entry and emit
    # a responses/rule_removed audit entry recording the expiry.
    local before_exp
    before_exp="$(audit_log_count responses rule_removed)" || before_exp=0

    wait_for_response_expired "${id}" 15 1 || {
        echo "response ${id} did not expire within 15s" >&2
        return 1
    }

    local i after_exp
    after_exp="${before_exp}"
    for ((i = 0; i < 10; i++)); do
        after_exp="$(audit_log_count responses rule_removed)" || after_exp="${before_exp}"
        [ "${after_exp}" -gt "${before_exp}" ] && break
        sleep 1
    done
    [ "${after_exp}" -gt "${before_exp}" ] || {
        echo "no responses/rule_removed audit entry after expiry (${before_exp} -> ${after_exp})" >&2
        return 1
    }
}
