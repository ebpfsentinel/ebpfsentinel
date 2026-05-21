#!/usr/bin/env bash
# list-suites-by-profile.sh — Resolve coverage-matrix.yaml per-feature
# profile tags down to a flat list of bats suite ids per CI profile
# (pr | nightly | manual). Used by .github/workflows/integration.yml
# to build the matrix without baking the suite list into the workflow.
#
# A suite belongs to a profile P if at least one feature row that
# references it has `profile: P`. A suite that is referenced by both
# `pr` and `nightly` rows is treated as `pr` (PR fast-feedback wins).
#
# Usage:
#   list-suites-by-profile.sh --json         # full mapping
#   list-suites-by-profile.sh --list pr      # space-separated ids
#   list-suites-by-profile.sh --list nightly # space-separated ids
#   list-suites-by-profile.sh --list manual
#   list-suites-by-profile.sh --paths pr     # bats file paths (newline)
#   list-suites-by-profile.sh --paths nightly
#   list-suites-by-profile.sh --help
#
# Requires python3 + PyYAML.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

case "${1:-}" in
  --help|-h|"")
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  --json|--list|--paths) ;;
  *)
    echo "unknown mode: $1" >&2
    exit 2
    ;;
esac

MODE="$1"
PROFILE="${2:-}"

if [[ "${MODE}" == "--list" || "${MODE}" == "--paths" ]]; then
  case "${PROFILE}" in
    pr|nightly|manual) ;;
    *) echo "${MODE} requires profile: pr | nightly | manual" >&2; exit 2 ;;
  esac
fi

exec python3 - "${INTEG_DIR}" "${MODE}" "${PROFILE}" <<'PY'
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML not installed. apt: python3-yaml | pip: pyyaml\n")
    sys.exit(2)

integ_dir = Path(sys.argv[1])
mode = sys.argv[2]
profile_arg = sys.argv[3]

matrix_path = integ_dir / "coverage-matrix.yaml"
suites_dir = integ_dir / "suites"

with matrix_path.open() as fh:
    matrix = yaml.safe_load(fh)

# Source of truth: top-level `suite_profiles:` map, one entry per
# bats suite. Falls back to the feature-row `profile` field when a
# suite id is not pinned explicitly (legacy / planned suites).
explicit: dict[str, str] = {}
for sid, prof in (matrix.get("suite_profiles") or {}).items():
    if prof not in {"pr", "nightly", "manual"}:
        sys.stderr.write(
            f"suite_profiles['{sid}'] has invalid profile '{prof}'\n"
        )
        sys.exit(2)
    explicit[str(sid)] = prof

derived: dict[str, set[str]] = {}
for row in matrix.get("coverage") or []:
    prof = row.get("profile")
    if prof not in {"pr", "nightly", "manual"}:
        continue
    for s in row.get("suites") or []:
        if s == "TBD":
            continue
        derived.setdefault(s, set()).add(prof)

def fallback(profs: set[str]) -> str:
    # Precedence on fallback: pr > nightly > manual so suites not
    # pinned explicitly stay on the fast-feedback path by default.
    if "pr" in profs:
        return "pr"
    if "nightly" in profs:
        return "nightly"
    return "manual"

resolved: dict[str, str] = dict(explicit)
for sid, profs in derived.items():
    resolved.setdefault(sid, fallback(profs))

# Enumerate all suite files on disk so unreferenced suites still get
# a default. Any suite not present in the matrix defaults to `pr`
# (existing behaviour pre-split).
disk_suites: dict[str, str] = {}
if suites_dir.exists():
    for p in sorted(suites_dir.iterdir()):
        if not p.name.endswith(".bats"):
            continue
        prefix = p.name.split("-", 1)[0]
        if not prefix.isdigit() or len(prefix) != 2:
            continue
        disk_suites[prefix] = p.name

final: dict[str, list[str]] = {"pr": [], "nightly": [], "manual": []}
for sid, fname in disk_suites.items():
    prof = resolved.get(sid, "pr")
    final[prof].append(sid)

for k in final:
    final[k].sort()

if mode == "--json":
    print(json.dumps(
        {
            "pr": final["pr"],
            "nightly": final["nightly"],
            "manual": final["manual"],
            "files": {sid: disk_suites[sid] for sid in disk_suites},
        },
        indent=2,
        sort_keys=True,
    ))
elif mode == "--list":
    print(" ".join(final[profile_arg]))
elif mode == "--paths":
    out = []
    for sid in final[profile_arg]:
        fname = disk_suites.get(sid)
        if fname:
            out.append(str((suites_dir / fname).relative_to(integ_dir.parent.parent)))
    print("\n".join(out))
PY
