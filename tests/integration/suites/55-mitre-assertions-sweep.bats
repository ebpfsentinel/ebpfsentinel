#!/usr/bin/env bats
# 55-mitre-assertions-sweep.bats — Meta-test enforcing MITRE coverage.
#
# Every alert-producing suite must invoke at least one MITRE assertion
# (assert_alert_has_mitre_technique or assert_alert_has_any_mitre_technique
# from lib/alert_helpers.bash). This suite enforces that contract via
# grep-based introspection of the .bats sources — no agent is started.
#
# The suite also emits a coverage report at $DATA_DIR/mitre-coverage.json
# listing (suite, alert_type, expected_technique) triples so reviewers can
# correlate per-suite MITRE expectations against the agent's mapping
# tables in crates/domain/src/alert/mitre.rs.

load '../lib/helpers'

# Suites in scope for MITRE coverage. The list mirrors the alert-producing
# suites enumerated in the integration coverage matrix; adding a new alert
# suite without registering it here is a deliberate audit point.
MITRE_SCOPE_SUITES=(
    "12" "13" "14" "16" "18" "20" "22" "23"
    "26" "28" "32" "36" "41" "43" "44" "47"
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
        16) echo "rest-only|" ;;                 # DDoS REST API, no alerts fired
        18) echo "threatintel|T1071.001" ;;      # ThreatIntel HTTP IOC match
        20) echo "rest-only|" ;;                 # DNS REST/observation only
        22) echo "rest-only|" ;;                 # NAT REST surface only
        23) echo "ddos|T1499" ;;                 # DDoS detection
        26) echo "ids|T1071" ;;                  # alert end-to-end
        28) echo "dlp|T1041" ;;                  # DLP exfiltration over C2
        32) echo "l7|T1071.001" ;;               # L7 web protocol
        36) echo "rest-only|" ;;                 # STIX feed loader, no alerts
        41) echo "ratelimit|T1499" ;;            # MHDDoS L7 floods
        43) echo "ratelimit|T1499" ;;            # Slowloris/RUDY/Slowread
        44) echo "ddos|T1498.002" ;;             # Reflection amplification
        47) echo "ratelimit|T1499.001" ;;        # OS Exhaustion (SYN flood)
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

@test "every in-scope alert suite invokes a MITRE assertion helper" {
    local missing=()
    local suite_num suite_file
    for suite_num in "${MITRE_SCOPE_SUITES[@]}"; do
        suite_file="$(ls "${SUITES_DIR}/${suite_num}"-*.bats 2>/dev/null | head -1)"
        if [ -z "${suite_file}" ] || [ ! -f "${suite_file}" ]; then
            missing+=("${suite_num} (file not found)")
            continue
        fi
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
    jq -e '.suites | length == 16' "${report}" >/dev/null || {
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
