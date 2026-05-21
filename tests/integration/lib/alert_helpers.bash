#!/usr/bin/env bash
# alert_helpers.bash — MITRE ATT&CK assertion helpers for alert-producing suites.
#
# The agent's alert handler (crates/adapters/src/http/alert_handler.rs) flattens
# the domain MitreAttackInfo into three top-level fields on the alert DTO:
#
#   mitre_technique_id    e.g. "T1499.002"
#   mitre_technique_name  e.g. "Service Exhaustion Flood"
#   mitre_tactic          e.g. "impact"
#
# Both helpers below poll /api/v1/alerts via wait_for_alert (defined in
# ebpf_helpers.bash) and assert on the flat field. They are tolerant of older
# nested shapes (.mitre.technique_id, .mitre.techniques[]) so the helpers
# remain valid against the gRPC streaming DTO and the legacy webhook payload.

# assert_alert_has_mitre_technique <technique_id> [max_attempts]
#
# Polls for at least one alert whose flattened `mitre_technique_id` matches
# the given value (case-insensitive). Sub-technique suffixes are honoured —
# pass "T1499" to accept any T1499.* mapping, or "T1499.002" for the exact
# sub-technique. Returns 0 on match, 1 on timeout with a stderr diagnostic.
assert_alert_has_mitre_technique() {
    local technique="${1:?usage: assert_alert_has_mitre_technique <id> [max_attempts]}"
    local max="${2:-30}"
    local upper
    upper="$(echo "${technique}" | tr '[:lower:]' '[:upper:]')"
    local filter
    filter="$(printf '
        .[]
        | (.mitre_technique_id // .mitre.technique_id // empty) as $tid
        | select($tid != null and $tid != "" )
        | select(($tid | ascii_upcase) == "%s"
              or ($tid | ascii_upcase | startswith("%s.")))
        | (.id // .alert_id // .timestamp // $tid)
    ' "${upper}" "${upper}")"
    if wait_for_alert "${filter}" "${max}" 1 >/dev/null 2>&1; then
        return 0
    fi
    echo "No alert tagged with MITRE technique ${technique} after ${max}s" >&2
    return 1
}

# assert_alert_has_any_mitre_technique [max_attempts]
#
# Asserts that AT LEAST one alert in /api/v1/alerts carries a non-empty
# `mitre_technique_id`. Used by suites where the exact technique is fluid
# (e.g. port-aware IDS/threatintel mappings) but the MITRE-mapping pipeline
# must still fire end-to-end. Returns 0 on match, 1 on timeout.
assert_alert_has_any_mitre_technique() {
    local max="${1:-30}"
    local filter='
        .[]
        | (.mitre_technique_id // .mitre.technique_id // empty) as $tid
        | select($tid != null and $tid != "")
        | $tid
    '
    if wait_for_alert "${filter}" "${max}" 1 >/dev/null 2>&1; then
        return 0
    fi
    echo "No alert carries a MITRE technique mapping after ${max}s" >&2
    return 1
}
