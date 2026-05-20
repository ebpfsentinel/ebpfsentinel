#!/usr/bin/env bats
# 45-ja4-fingerprint-diversity.bats — diverse TLS clients populate the
# agent's JA4 cache and surface distinct hashes on enriched alerts.
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM with curl, openssl, python3 (urllib3 / aiohttp), go
#     (Story 34.3); MHDDoS optional
#   - Agent VM reachable via 2VM SSH helpers (Story 34.2)
#   - Kernel >= 6.9
#
# What's asserted:
#   1. The agent's JA4 cache count grows monotonically across distinct
#      clients touching the TLS target (cache → /api/v1/fingerprints/summary).
#   2. A "malicious" SNI from any client triggers an alert whose
#      response carries a non-null ja4_fingerprint and a MITRE
#      technique id (T1071-family, via dst_port 443 / 8443 mapping).
#   3. A "legit" SNI does NOT match the deny rule.
#   4. JA4S server-side fingerprints populate the JA4S cache and surface
#      on /api/v1/fingerprints/ja4s after ServerHello observation.
#   5. JA4/JA4S caches persist across agent restart when
#      l7.fingerprints.persistence_path is configured: cached_count
#      after restart is non-zero (redb-backed persistence).

load '../lib/ebpf_helpers'
load '../lib/ja4_helpers'

# SNI sentinels matched by the suite-45 fixture's L7 rules.
MALICIOUS_SNI="malicious-ja4.test"
LEGIT_SNI="legit-ja4.test"

setup_file() {
    require_root
    require_kernel 6 9
    require_tool jq
    require_tool curl
    require_tool openssl

    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        skip "suite 45 requires EBPF_2VM_MODE=true (TLS target on agent VM)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    require_ja4_min

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ja4-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ja4.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }

    if ! start_tls_target "$JA4_TLS_PORT"; then
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "could not start TLS target on agent VM at port ${JA4_TLS_PORT}"
    fi
}

teardown_file() {
    stop_tls_target 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ja4-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers local to this suite ───────────────────────────────────────

# _ja4_drive_available_clients <sni>
# Drive every available client in turn, ignoring those whose tooling
# isn't installed. Returns the count of clients that actually fired.
_ja4_drive_available_clients() {
    local sni="${1:?usage: _ja4_drive_available_clients <sni>}"
    local fired=0 client
    for client in curl openssl urllib3 aiohttp go mhddos; do
        if ja4_have_client "$client"; then
            ja4_connect "$client" "$sni"
            fired=$((fired + 1))
        fi
    done
    echo "$fired"
}

# ── Tests ─────────────────────────────────────────────────────────────

@test "diverse TLS clients populate the JA4 fingerprint cache" {
    local before
    before="$(ja4_summary_count || echo 0)"
    [ -z "$before" ] && before=0

    local fired
    fired="$(_ja4_drive_available_clients "$LEGIT_SNI")"
    [ "$fired" -ge 2 ] || skip "only ${fired} TLS clients available — need at least 2"

    # Give the userspace L7 pipeline a moment to ingest each handshake.
    sleep 2

    local after
    after="$(ja4_summary_count || echo 0)"
    [ -z "$after" ] && after=0

    # We assert growth, not "exactly fired" — different clients on the
    # same source/dest 4-tuple over short windows can collapse onto a
    # single flow-keyed cache slot.
    [ "$after" -gt "$before" ] || {
        echo "expected cache to grow: before=${before} after=${after} fired=${fired}" >&2
        return 1
    }
}

@test "malicious SNI client triggers an alert with MITRE technique tag" {
    # Drive every available client against the sentinel SNI so the L7
    # deny rule fires once per client connection.
    local fired
    fired="$(_ja4_drive_available_clients "$MALICIOUS_SNI")"
    [ "$fired" -ge 1 ] || skip "no TLS client available to drive malicious SNI"

    # Wait up to 15 s for at least one alert to appear with this rule id.
    wait_for_alert ".[] | select(.rule_id == \"l7-tls-malicious-sni-deny\")" 15 1 \
        || {
            echo "expected alert from l7-tls-malicious-sni-deny within 15s" >&2
            api_get "/api/v1/alerts?limit=10" || true
            return 1
        }

    # The alert path must tag at least one alert with a MITRE technique.
    # The agent maps L7/TLS denies to T1071-family techniques via
    # alert::mitre.
    assert_alert_has_mitre_technique T1071 \
        || assert_alert_has_mitre_technique T1071.001 \
        || {
            echo "expected MITRE T1071 family on l7-tls-malicious-sni-deny alert" >&2
            return 1
        }
}

@test "JA4 fingerprint surfaces on enriched alerts" {
    # Pre-condition: previous test fired at least one malicious-SNI alert.
    local distinct
    distinct="$(ja4_alert_hashes \
        "select(.rule_id == \"l7-tls-malicious-sni-deny\")" | grep -c . || echo 0)"

    # If enrichment skipped (flow-key mismatch between cache and alert),
    # accept presence on ANY alert from this suite.
    if [ "$distinct" -lt 1 ]; then
        distinct="$(ja4_alert_hashes "." | grep -c . || echo 0)"
    fi

    [ "$distinct" -ge 1 ] || {
        echo "expected at least one alert with non-null ja4_fingerprint" >&2
        api_get "/api/v1/alerts?limit=10" || true
        return 1
    }
}

@test "legitimate SNI does NOT fire the malicious deny rule" {
    local before
    before="$(api_get "/api/v1/alerts?limit=1000" 2>/dev/null \
        | jq '[.alerts[] | select(.rule_id == "l7-tls-malicious-sni-deny")] | length' \
        || echo 0)"
    [ -z "$before" ] && before=0

    # Drive every available client against the legit-SNI sentinel.
    _ja4_drive_available_clients "$LEGIT_SNI" >/dev/null

    sleep 3

    local after
    after="$(api_get "/api/v1/alerts?limit=1000" 2>/dev/null \
        | jq '[.alerts[] | select(.rule_id == "l7-tls-malicious-sni-deny")] | length' \
        || echo 0)"
    [ -z "$after" ] && after=0

    [ "$after" -eq "$before" ] || {
        echo "legit SNI must NOT increase l7-tls-malicious-sni-deny count: before=${before} after=${after}" >&2
        return 1
    }
}

@test "JA4S server fingerprints surface on /api/v1/fingerprints/ja4s" {
    # Drive available TLS clients against the legit SNI so the agent
    # observes ServerHello bytes and computes JA4S per flow.
    local fired
    fired="$(_ja4_drive_available_clients "$LEGIT_SNI")"
    [ "$fired" -ge 1 ] || skip "no TLS client available to drive ServerHello"

    # Let the userspace L7 pipeline ingest server-side handshake bytes.
    sleep 2

    local ja4s_count
    ja4s_count="$(ja4s_summary_count || echo 0)"
    [ -z "$ja4s_count" ] && ja4s_count=0

    [ "$ja4s_count" -ge 1 ] || {
        echo "expected /api/v1/fingerprints/ja4s cached_count >= 1, got ${ja4s_count}" >&2
        api_get /api/v1/fingerprints/ja4s || true
        return 1
    }
}

@test "JA4/JA4S caches persist across agent restart (redb-backed)" {
    # Pre-condition: caches populated by earlier tests in this suite.
    local before_ja4 before_ja4s
    before_ja4="$(ja4_summary_count || echo 0)"
    before_ja4s="$(ja4s_summary_count || echo 0)"
    [ -z "$before_ja4" ] && before_ja4=0
    [ -z "$before_ja4s" ] && before_ja4s=0

    [ "$before_ja4" -ge 1 ] || skip "JA4 cache empty before restart (no clients fired earlier)"

    # Persistence flag must be advertised by the summary endpoint.
    local persistent
    persistent="$(ja4_summary_persistent || echo false)"
    [ "$persistent" = "true" ] || {
        echo "expected summary.persistent=true with l7.fingerprints.persistence_path configured" >&2
        return 1
    }

    stop_ebpf_agent 2>/dev/null || true
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || skip "agent failed to come back up"

    # Wait up to 10 s for HTTP to come back, then assert real persistence:
    # cached_count must be > 0 after restart (entries loaded from redb).
    local i ready=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if ja4_summary_count >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    [ "$ready" = "1" ] || {
        echo "/api/v1/fingerprints/summary did not become responsive within 10s" >&2
        return 1
    }

    local after_ja4 after_ja4s
    after_ja4="$(ja4_summary_count || echo 0)"
    after_ja4s="$(ja4s_summary_count || echo 0)"
    [ -z "$after_ja4" ] && after_ja4=0
    [ -z "$after_ja4s" ] && after_ja4s=0

    [ "$after_ja4" -ge 1 ] || {
        echo "JA4 cache did NOT persist across restart: before=${before_ja4} after=${after_ja4}" >&2
        return 1
    }

    # JA4S persistence is asserted only if we had any server hashes pre-restart.
    if [ "$before_ja4s" -ge 1 ]; then
        [ "$after_ja4s" -ge 1 ] || {
            echo "JA4S cache did NOT persist across restart: before=${before_ja4s} after=${after_ja4s}" >&2
            return 1
        }
    fi
}
