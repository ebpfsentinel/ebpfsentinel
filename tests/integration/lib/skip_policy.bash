#!/usr/bin/env bash
# skip_policy.bash — two kinds of skip, told apart on purpose.
#
# A skipped bats test reports as success. That is correct when the machine
# genuinely cannot run it (no Docker, no second VM, a kernel without the
# module BTF a program needs) and dangerous when the suite's own setup fell
# over: "could not start the TLS server" reads as green, so a regression
# that breaks the TLS server hides forever.
#
# Two helpers, so the difference is written down at the call site:
#
#   env_skip   the capability is absent from this machine or lane. Always
#              skips. Nothing is being hidden — the test could not run.
#
#   soft_skip  a prerequisite the suite itself was supposed to provide is
#              missing, or an earlier step produced nothing to assert on.
#              Skips by default (so a degraded dev box stays usable), but
#              FAILS when EBPFSENTINEL_STRICT_SKIPS=1 — which is what the
#              canonical lane sets, because there the prerequisite is
#              supposed to be there.
#
# Every reason string must be registered in tests/integration/skip-policy.yaml;
# scripts/audit-skips.sh enforces both that and the absence of bare `skip`
# calls in the suites.

# strict_skips_enabled — is the run demanding that soft skips be failures?
strict_skips_enabled() {
    [ "${EBPFSENTINEL_STRICT_SKIPS:-0}" = "1" ]
}

# env_skip <reason> — the capability is absent; skip unconditionally.
env_skip() {
    local reason="${1:?usage: env_skip <reason>}"
    skip "${reason}"
}

# soft_skip <reason> — a prerequisite the suite owns is missing.
# Fails instead of skipping under EBPFSENTINEL_STRICT_SKIPS=1.
soft_skip() {
    local reason="${1:?usage: soft_skip <reason>}"
    if strict_skips_enabled; then
        echo "STRICT: refusing to skip — ${reason}" >&2
        echo "  This prerequisite is provided by the canonical lane; its" >&2
        echo "  absence is a regression, not an environment gap. Unset" >&2
        echo "  EBPFSENTINEL_STRICT_SKIPS to downgrade this to a skip." >&2
        # `exit` rather than `return`: bats runs each test (and setup_file) in
        # its own subshell, so this fails the test outright and stops it from
        # continuing on to assertions whose prerequisite is missing. A bare
        # `return 1` would only fail the test while errexit happens to be on.
        exit 1
    fi
    skip "${reason}"
}
