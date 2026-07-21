#!/usr/bin/env bats
# 51-mitre-assertions-sweep.bats — Meta-test enforcing MITRE coverage.
#
# Every alert-producing suite must invoke at least one MITRE assertion
# (assert_alert_has_mitre_technique or assert_alert_has_any_mitre_technique
# from lib/alert_helpers.bash). This suite enforces that contract via
# grep-based introspection of the .bats sources — no agent is started.
#
# Suites that only exercise a REST surface are tagged "rest-only" and are
# exempt — but the exemption is itself checked: a rest-only suite that turns
# out to assert alerts fails the audit, so the tag cannot be used to silence
# a suite that grew an attack path.
#
# The suite also emits a coverage report at $DATA_DIR/mitre-coverage.json
# listing (suite, alert_type, expected_technique) triples so reviewers can
# correlate per-suite MITRE expectations against the agent's mapping
# tables in crates/domain/src/alert/mitre.rs.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Suites in scope for MITRE coverage. The list mirrors the alert-producing
# suites enumerated in the integration coverage matrix; adding a new alert
# suite without registering it here is a deliberate audit point.
MITRE_SCOPE_SUITES=(
    "12" "13" "14" "15" "17" "19" "21" "22"
    "25" "27" "29" "30" "33" "38" "39" "40"
    "41" "43" "45" "55" "56" "59"
)

# Per-suite expected technique mapping. The mapping reflects the dominant
# MITRE ATT&CK technique that should land on alerts produced by that
# suite's primary attack vector; suites that exercise REST surfaces only
# (no alert generation) are tagged "rest-only" and skip technique enforcement.
_expected_technique_for_suite() {
    case "${1}" in
        12) echo "ids|T1071" ;;                  # IDS signature match
        13) echo "ips|T1071" ;;                  # IPS auto-blacklist
        14) echo "ratelimit|T1499" ;;            # Endpoint Denial of Service
        15) echo "rest-only|" ;;                 # DDoS REST surface, drives no traffic
        17) echo "rest-only|" ;;                 # ThreatIntel feed/REST surface
        19) echo "rest-only|" ;;                 # DNS observation surface
        21) echo "rest-only|" ;;                 # NAT REST surface, no detector
        22) echo "rest-only|" ;;                 # DDoS REST surface, sub-threshold traffic
        25) echo "ids|T1071" ;;                  # alert end-to-end
        27) echo "dlp|T1041" ;;                  # DLP exfiltration over C2
        29) echo "rest-only|" ;;                 # L7 rule surface; denies audit, no alert
        30) echo "geoip|T1071" ;;                # GeoIP-enriched alerts
        33) echo "threatintel|T1071.001" ;;      # STIX feed IOC match
        38) echo "ratelimit|T1499" ;;            # MHDDoS L7 floods
        39) echo "ratelimit|T1499" ;;            # Slowloris/RUDY/Slowread
        40) echo "ddos|T1498.002" ;;             # Reflection amplification
        41) echo "l7|T1071.001" ;;               # JA4 / TLS client diversity
        43) echo "ddos|T1499.001" ;;             # OS Exhaustion (SYN flood)
        45) echo "dns|T1071.004" ;;              # DoH/DoT encrypted-DNS policy
        55) echo "ids|T1071" ;;                  # IPv6 parity sweep
        56) echo "l7|T1071.003" ;;               # SMTP/FTP/SMB edge cases
        59) echo "ips|T1110.001" ;;              # SSH password guessing
        *)  echo "" ;;
    esac
}

setup_file() {
    require_tool jq
    require_tool grep

    SUITES_DIR="${BATS_TEST_DIRNAME}"
    export SUITES_DIR

    export DATA_DIR="/tmp/ebpfsentinel-test-data-mitre-sweep-$$"
    mkdir -p "${DATA_DIR}"
}

teardown_file() {
    # Preserve the coverage report so the CI workflow can archive it.
    # The /tmp parent dir is harness-cleaned between bats runs.
    true
}

# ── grep-based assertion enforcement ────────────────────────────────

@test "every alert-producing suite invokes a MITRE assertion helper" {
    local missing=()
    local suite_num suite_file mapping alert_type
    for suite_num in "${MITRE_SCOPE_SUITES[@]}"; do
        suite_file="$(ls "${SUITES_DIR}/${suite_num}"-*.bats 2>/dev/null | head -1)"
        if [ -z "${suite_file}" ] || [ ! -f "${suite_file}" ]; then
            missing+=("${suite_num} (file not found)")
            continue
        fi
        mapping="$(_expected_technique_for_suite "${suite_num}")"
        alert_type="${mapping%%|*}"
        # A rest-only suite exercises a REST surface and never drives an
        # attack, so it has no alert to tag.
        [ "${alert_type}" = "rest-only" ] && continue
        if ! grep -qE 'assert_alert_has_(any_)?mitre_technique' "${suite_file}"; then
            missing+=("${suite_num} (${suite_file##*/})")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "MITRE assertion missing from in-scope alert suites:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        return 1
    fi
}

@test "a rest-only tag cannot hide an alert-producing suite" {
    # Otherwise the tag becomes an escape hatch: label a suite rest-only and
    # its alerts stop being checked. A rest-only suite must genuinely make no
    # MITRE claim — and must not be asserting alerts by other means either.
    local liars=()
    local suite_num suite_file mapping alert_type
    for suite_num in "${MITRE_SCOPE_SUITES[@]}"; do
        mapping="$(_expected_technique_for_suite "${suite_num}")"
        alert_type="${mapping%%|*}"
        [ "${alert_type}" = "rest-only" ] || continue

        suite_file="$(ls "${SUITES_DIR}/${suite_num}"-*.bats 2>/dev/null | head -1)"
        [ -f "${suite_file}" ] || continue

        if grep -qE 'assert_alert_has_(any_)?mitre_technique|wait_for_alert' "${suite_file}"; then
            liars+=("${suite_num} (${suite_file##*/})")
        fi
    done

    if [ "${#liars[@]}" -gt 0 ]; then
        echo "suites tagged rest-only that do assert alerts:" >&2
        printf '  - %s\n' "${liars[@]}" >&2
        return 1
    fi
}

# ── coverage report ─────────────────────────────────────────────────

@test "MITRE coverage report enumerates expected techniques" {
    local report="${DATA_DIR}/mitre-coverage.json"
    : >"${report}"
    {
        echo '{'
        echo '  "schema": "ebpfsentinel.mitre-coverage.v1",'
        echo '  "suites": ['
        local first=1 suite_num suite_file mapping alert_type technique
        for suite_num in "${MITRE_SCOPE_SUITES[@]}"; do
            suite_file="$(ls "${SUITES_DIR}/${suite_num}"-*.bats 2>/dev/null | head -1)"
            mapping="$(_expected_technique_for_suite "${suite_num}")"
            alert_type="${mapping%%|*}"
            technique="${mapping##*|}"
            if [ "${first}" -eq 1 ]; then
                first=0
            else
                echo ','
            fi
            printf '    {"suite": "%s", "file": "%s", "alert_type": "%s", "expected_technique": "%s"}' \
                "${suite_num}" "${suite_file##*/}" "${alert_type}" "${technique}"
        done
        echo
        echo '  ]'
        echo '}'
    } >"${report}"

    [ -s "${report}" ]
    jq -e ".suites | length == ${#MITRE_SCOPE_SUITES[@]}" "${report}" >/dev/null || {
        echo "coverage report missing entries" >&2
        cat "${report}" >&2
        return 1
    }

    # Every entry must have either a concrete technique or an explicit
    # "rest-only" alert_type marking the suite as a REST surface without alerts.
    local bad
    bad="$(jq -r '
        .suites[]
        | select(
            (.alert_type == "rest-only" and .expected_technique == "")
            or (.alert_type != "rest-only" and .expected_technique != "")
            | not
          )
        | .suite
    ' "${report}")"
    if [ -n "${bad}" ]; then
        echo "coverage report has malformed entries: ${bad}" >&2
        return 1
    fi
}

# ── helper presence ─────────────────────────────────────────────────

@test "lib/alert_helpers.bash exposes both MITRE assertion helpers" {
    local lib="${SUITES_DIR}/../lib/alert_helpers.bash"
    [ -f "${lib}" ] || {
        echo "lib/alert_helpers.bash missing at ${lib}" >&2
        return 1
    }
    grep -q '^assert_alert_has_mitre_technique()'      "${lib}"
    grep -q '^assert_alert_has_any_mitre_technique()'  "${lib}"
}
