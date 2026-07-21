#!/usr/bin/env bats
# 63-skip-policy-audit.bats — meta-test keeping skips honest.
#
# A skipped bats test reports as success, so an unclassified skip is a
# regression waiting to hide. This suite enforces the contract that
# lib/skip_policy.bash sets up:
#
#   * no bare `skip "…"` is left in suites/ or lib/ — every call goes
#     through env_skip (capability genuinely absent) or soft_skip (a
#     prerequisite the suite itself owns)
#   * every reason is registered in skip-policy.yaml under the class
#     matching the helper it is called through, and no registered reason
#     has rotted out of use
#   * the helpers actually behave: soft_skip fails rather than skips when
#     EBPFSENTINEL_STRICT_SKIPS=1, env_skip skips either way
#
# Pure introspection: no agent is started, nothing needs root.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_tool python3
    export INTEG_DIR="${BATS_TEST_DIRNAME}/.."
}

# _run_helper <strict> <helper> — invoke a skip helper in a clean bash
# subshell with `skip` stubbed out, so its control flow can be asserted
# without skipping this test.
_run_helper() {
    local strict="${1}" helper="${2}"
    run env EBPFSENTINEL_STRICT_SKIPS="${strict}" bash -c "
        skip() { echo \"STUB-SKIPPED: \$*\"; exit 0; }
        source '${INTEG_DIR}/lib/skip_policy.bash'
        ${helper} 'test reason'
        echo 'RETURNED-NORMALLY'
    "
}

# ── Policy enforcement ─────────────────────────────────────────────

@test "every skip in the fleet is classified and registered" {
    run bash "${INTEG_DIR}/scripts/audit-skips.sh"
    [ "${status}" -eq 0 ] || {
        echo "${output}" >&2
        return 1
    }
}

@test "the audit reports both classes as non-empty" {
    run bash "${INTEG_DIR}/scripts/audit-skips.sh"
    [ "${status}" -eq 0 ]

    local env_calls soft_calls
    env_calls="$(echo "${output}" | sed -n 's/.*env_skip call sites *: *//p')"
    soft_calls="$(echo "${output}" | sed -n 's/.*soft_skip call sites *: *//p')"

    [ "${env_calls:-0}" -ge 1 ] || {
        echo "no env_skip call sites found — did the audit scan anything?" >&2
        echo "${output}" >&2
        return 1
    }
    [ "${soft_calls:-0}" -ge 1 ] || {
        echo "no soft_skip call sites found" >&2
        echo "${output}" >&2
        return 1
    }
}

@test "the policy file is valid YAML with both classes" {
    run python3 -c "
import sys, yaml
d = yaml.safe_load(open('${INTEG_DIR}/skip-policy.yaml'))
assert isinstance(d.get('env'), list) and d['env'], 'env class missing or empty'
assert isinstance(d.get('masking'), list) and d['masking'], 'masking class missing or empty'
overlap = set(d['env']) & set(d['masking'])
assert not overlap, f'reason in both classes: {sorted(overlap)}'
print(len(d['env']), len(d['masking']))
"
    [ "${status}" -eq 0 ] || {
        echo "${output}" >&2
        return 1
    }
}

# ── Helper behaviour ───────────────────────────────────────────────

@test "soft_skip skips when strict mode is off" {
    _run_helper 0 soft_skip
    [ "${status}" -eq 0 ]
    echo "${output}" | grep -q "STUB-SKIPPED: test reason" || {
        echo "soft_skip did not reach skip: ${output}" >&2
        return 1
    }
}

@test "soft_skip fails instead of skipping under strict mode" {
    _run_helper 1 soft_skip
    [ "${status}" -ne 0 ] || {
        echo "soft_skip returned success under strict mode: ${output}" >&2
        return 1
    }
    echo "${output}" | grep -q "STRICT: refusing to skip" || {
        echo "no strict-mode explanation in the output: ${output}" >&2
        return 1
    }
    echo "${output}" | grep -q "STUB-SKIPPED" && {
        echo "soft_skip still called skip under strict mode" >&2
        return 1
    }
    return 0
}

@test "env_skip skips regardless of strict mode" {
    _run_helper 0 env_skip
    [ "${status}" -eq 0 ]
    echo "${output}" | grep -q "STUB-SKIPPED: test reason"

    _run_helper 1 env_skip
    [ "${status}" -eq 0 ] || {
        echo "env_skip must not be affected by strict mode: ${output}" >&2
        return 1
    }
    echo "${output}" | grep -q "STUB-SKIPPED: test reason" || {
        echo "env_skip did not reach skip under strict mode: ${output}" >&2
        return 1
    }
}
