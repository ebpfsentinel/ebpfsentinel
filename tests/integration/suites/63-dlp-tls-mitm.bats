#!/usr/bin/env bats
# 63-dlp-tls-mitm.bats — DLP TLS-inspection MITM sweep (Enterprise-gated).
#
# Lives in the OSS integration tree so the test fleet has a single
# canonical entry point, but the dataplane under test is the Enterprise
# DLP TLS-inspection proxy (`enterprise_adapters::tls_proxy`), which is
# license-gated. The suite enforces AC #3 explicitly: when the test
# fleet is an OSS-only build (no license file, no enterprise binary)
# every wire-level test is skipped cleanly with a documented rationale.
#
# Detection priority for the enterprise build:
#   1. `EBPFSENTINEL_LICENSE` env var pointing to a readable license file.
#   2. `/etc/ebpfsentinel/enterprise.lic` present on disk.
#   3. `ebpfsentinel-enterprise-agent` binary discoverable via PATH or
#      `${ENTERPRISE_AGENT_BIN}`.
# All three checks must pass for the wire-level scenarios to run.
#
# Coverage gaps (tracked, deferred):
#
#   * mitmproxy + injected-CA topology (AC #1, AC #2). The Enterprise
#     DLP TLS-inspection proxy decrypts client TLS sessions using a
#     locally injected CA and re-encrypts upstream; the malicious-MITM
#     case requires a second attacker VM running mitmproxy with a
#     different CA. The OSS bats fleet runs single-VM and does not
#     provision mitmproxy. Tracked as a 3-VM enablement task.
#   * DLP pattern match on decrypted payload (AC #2). Same gap — the
#     TLS-inspection proxy must be live and a real HTTPS upload must
#     traverse it for the pattern engine to fire on plaintext.

load '../lib/helpers'

_locate_license() {
    if [ -n "${EBPFSENTINEL_LICENSE:-}" ] && [ -r "${EBPFSENTINEL_LICENSE}" ]; then
        echo "${EBPFSENTINEL_LICENSE}"
        return 0
    fi
    if [ -r /etc/ebpfsentinel/enterprise.lic ]; then
        echo /etc/ebpfsentinel/enterprise.lic
        return 0
    fi
    return 1
}

_locate_enterprise_bin() {
    if [ -n "${ENTERPRISE_AGENT_BIN:-}" ] && [ -x "${ENTERPRISE_AGENT_BIN}" ]; then
        echo "${ENTERPRISE_AGENT_BIN}"
        return 0
    fi
    local candidate
    candidate="$(command -v ebpfsentinel-enterprise-agent 2>/dev/null || true)"
    if [ -n "${candidate}" ]; then
        echo "${candidate}"
        return 0
    fi
    if [ -x "${PROJECT_ROOT:-.}/../ebpfsentinel-enterprise/target/release/ebpfsentinel-enterprise-agent" ]; then
        echo "${PROJECT_ROOT:-.}/../ebpfsentinel-enterprise/target/release/ebpfsentinel-enterprise-agent"
        return 0
    fi
    return 1
}

setup_file() {
    require_root
    require_tool curl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"

    LICENSE_PATH="$(_locate_license 2>/dev/null || true)"
    ENT_BIN="$(_locate_enterprise_bin 2>/dev/null || true)"
    MITMPROXY_BIN="$(command -v mitmdump 2>/dev/null || true)"

    export LICENSE_PATH ENT_BIN MITMPROXY_BIN

    if [ -z "${LICENSE_PATH}" ]; then
        export EBPF_DLP_TLS_MITM_SKIP_REASON="OSS-only build (no enterprise license file)"
        return 0
    fi
    if [ -z "${ENT_BIN}" ]; then
        export EBPF_DLP_TLS_MITM_SKIP_REASON="enterprise binary not on PATH or ENTERPRISE_AGENT_BIN"
        return 0
    fi
    if [ -z "${MITMPROXY_BIN}" ]; then
        export EBPF_DLP_TLS_MITM_SKIP_REASON="mitmproxy not installed on test VM"
        return 0
    fi
    # If the full enterprise topology is present, future implementations
    # would boot the proxy + a mitmproxy attacker here. The OSS fleet
    # never lands in this branch; mark for the deferred-AC reporter.
    export EBPF_DLP_TLS_MITM_SKIP_REASON="3-VM mitmproxy + injected-CA topology not provisioned on the OSS bats fleet"
}

teardown_file() {
    :
}

# ── License-gated skip path (AC #3) ────────────────────────────────

@test "suite skips cleanly when no enterprise license is present (AC #3)" {
    if [ -n "${LICENSE_PATH:-}" ]; then
        # Enterprise build detected — this assertion does not apply.
        # The subsequent wire-level tests carry the assertion load.
        skip "enterprise license detected at ${LICENSE_PATH}; AC #3 skip-path inapplicable"
    fi
    # On the OSS fleet, this is the AC #3 verification: the suite must
    # not error out, must not surface a false positive, must emit a
    # documented skip reason on every subsequent test.
    [ -n "${EBPF_DLP_TLS_MITM_SKIP_REASON:-}" ] || {
        echo "OSS skip-path did not surface a documented reason" >&2
        return 1
    }
    [ -z "${LICENSE_PATH:-}" ]
}

# ── Wire-level scenarios (deferred on OSS fleet) ───────────────────

@test "Enterprise DLP TLS proxy detects malicious MITM cert (AC #1)" {
    skip "${EBPF_DLP_TLS_MITM_SKIP_REASON:-OSS build, enterprise topology unavailable}"
}

@test "legitimate proxied HTTPS with correct CA matches DLP patterns on plaintext (AC #2)" {
    skip "${EBPF_DLP_TLS_MITM_SKIP_REASON:-OSS build, enterprise topology unavailable}"
}

@test "wire-level mitmproxy + injected-CA topology is tracked as a coverage gap" {
    skip "AC #1 + AC #2 wire-level path needs a 3-VM topology with mitmproxy on the attacker VM; deferred"
}
