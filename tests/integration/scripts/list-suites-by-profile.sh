#!/usr/bin/env bash
# list-suites-by-profile.sh - list the bats suites of one CI profile
# (pr | datapath | nightly | manual), read from the `suite_profiles` block of
# coverage-matrix.yaml. Used by .github/workflows/integration.yml to build its
# jobs without baking the suite list into the workflow.
#
# Every suite file under suites/ must carry an entry there, whatever the width
# of its number: a suite with none is an error, not a default, because a
# default is how a suite ends up in a job that skips it.
#
# Usage:
#   list-suites-by-profile.sh --json                  # full mapping
#   list-suites-by-profile.sh --list <profile>        # space-separated ids
#   list-suites-by-profile.sh --list <profile> I/N    # shard I of N (0-based)
#   list-suites-by-profile.sh --paths <profile>       # bats file paths (newline)
#   list-suites-by-profile.sh --lane <id>             # lane the suite runs on
#   list-suites-by-profile.sh --help
#
# --lane prints the first entry of the suite's `lanes` in `attack_suites`
# (2vm, 3vm, runtimes) or `local` when it has no row there.
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
  --json|--list|--paths|--lane) ;;
  *)
    echo "unknown mode: $1" >&2
    exit 2
    ;;
esac

MODE="$1"
PROFILE="${2:-}"
SHARD="${3:-}"

if [[ "${MODE}" == "--lane" && ! "${PROFILE}" =~ ^[0-9]+$ ]]; then
  echo "--lane requires a suite id" >&2
  exit 2
fi

if [[ "${MODE}" == "--list" || "${MODE}" == "--paths" ]]; then
  case "${PROFILE}" in
    pr|datapath|nightly|manual) ;;
    *) echo "${MODE} requires profile: pr | datapath | nightly | manual" >&2; exit 2 ;;
  esac
fi

exec python3 - "${INTEG_DIR}" "${MODE}" "${PROFILE}" "${SHARD}" <<'PY'
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
shard_arg = sys.argv[4]

PROFILES = ("pr", "datapath", "nightly", "manual")

matrix_path = integ_dir / "coverage-matrix.yaml"
suites_dir = integ_dir / "suites"

with matrix_path.open() as fh:
    matrix = yaml.safe_load(fh)

pins: dict[str, str] = {}
for sid, prof in (matrix.get("suite_profiles") or {}).items():
    if prof not in PROFILES:
        sys.stderr.write(f"suite_profiles['{sid}'] has invalid profile '{prof}'\n")
        sys.exit(2)
    pins[str(sid)] = prof

disk_suites: dict[str, str] = {}
for p in sorted(suites_dir.iterdir()):
    if not p.name.endswith(".bats"):
        continue
    prefix = p.name.split("-", 1)[0]
    if not prefix.isdigit():
        sys.stderr.write(f"suite file without a numeric prefix: {p.name}\n")
        sys.exit(2)
    disk_suites[prefix] = p.name

unpinned = sorted((sid for sid in disk_suites if sid not in pins), key=int)
if unpinned:
    sys.stderr.write(
        "suites with no entry in suite_profiles of coverage-matrix.yaml: "
        + " ".join(unpinned)
        + "\n"
    )
    sys.exit(1)

final: dict[str, list[str]] = {k: [] for k in PROFILES}
for sid in disk_suites:
    final[pins[sid]].append(sid)
for k in final:
    final[k].sort(key=int)

selected = final.get(profile_arg, [])
if shard_arg:
    try:
        index, count = (int(x) for x in shard_arg.split("/", 1))
    except ValueError:
        sys.stderr.write(f"shard must read I/N, got '{shard_arg}'\n")
        sys.exit(2)
    if count < 1 or not 0 <= index < count:
        sys.stderr.write(f"shard {shard_arg} out of range\n")
        sys.exit(2)
    selected = selected[index::count]

if mode == "--json":
    out = {k: final[k] for k in PROFILES}
    out["files"] = disk_suites
    print(json.dumps(out, indent=2, sort_keys=True))
elif mode == "--list":
    print(" ".join(selected))
elif mode == "--lane":
    if profile_arg not in disk_suites:
        sys.stderr.write(f"no suite {profile_arg} under suites/\n")
        sys.exit(2)
    lanes = {
        str(row.get("suite")): row.get("lanes") or []
        for row in matrix.get("attack_suites") or []
    }
    print((lanes.get(profile_arg) or ["local"])[0])
elif mode == "--paths":
    print("\n".join(
        str((suites_dir / disk_suites[sid]).relative_to(integ_dir.parent.parent))
        for sid in selected
    ))
PY
