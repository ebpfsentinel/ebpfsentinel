#!/usr/bin/env bash
# audit-skips.sh — keep every skip in the fleet classified and declared.
#
# A skipped bats test reports as success. That is the right answer when the
# capability is genuinely absent, and a silent regression when the suite's
# own prerequisite fell over. `lib/skip_policy.bash` splits the two into
# `env_skip` (always skips) and `soft_skip` (fails under
# EBPFSENTINEL_STRICT_SKIPS=1); this gate enforces that:
#
#   - no bare `skip "…"` call is left in suites/ or lib/
#   - every reason used is registered in skip-policy.yaml, under the same
#     class as the helper it is called through
#   - every registered reason is still used somewhere (no rotting entries)
#
# Modes:
#   audit-skips.sh            check only — exit 1 on any violation
#   audit-skips.sh --report   print the per-class inventory, exit 0
#   audit-skips.sh --help
#
# Requires python3 + PyYAML.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODE="${1:-audit}"
case "${MODE}" in
  --help|-h)
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  --report|audit) ;;
  *)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 required" >&2
  exit 2
fi

exec python3 - "${INTEG_DIR}" "${MODE}" <<'PY'
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML not installed. apt: python3-yaml | pip: pyyaml\n")
    sys.exit(2)

integ_dir = Path(sys.argv[1])
mode = sys.argv[2]

policy_path = integ_dir / "skip-policy.yaml"
if not policy_path.exists():
    sys.stderr.write(f"skip policy missing: {policy_path}\n")
    sys.exit(2)

with policy_path.open() as fh:
    policy = yaml.safe_load(fh) or {}

env_keys = set(policy.get("env") or [])
mask_keys = set(policy.get("masking") or [])

overlap = env_keys & mask_keys
if overlap:
    sys.stderr.write(f"reason registered in both classes: {sorted(overlap)}\n")
    sys.exit(2)


def key(reason: str) -> str:
    """Registry key: the literal head before any shell interpolation."""
    i = reason.find("${")
    head = reason[:i].rstrip() if i != -1 else reason
    return head or reason


files = sorted((integ_dir / "suites").glob("*.bats")) + [
    p for p in sorted((integ_dir / "lib").glob("*.bash"))
    if p.name != "skip_policy.bash"
]

bare: list[str] = []
unregistered: list[str] = []
misclassified: list[str] = []
used_env: set[str] = set()
used_mask: set[str] = set()
counts = {"env": 0, "masking": 0}

call_re = re.compile(r'(?<![\w-])(env_skip|soft_skip|skip)\s+"([^"]*)"')

for path in files:
    rel = path.relative_to(integ_dir)
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for m in call_re.finditer(line):
            helper, reason = m.group(1), m.group(2)
            if helper == "skip":
                bare.append(f"  - {rel}:{lineno}  {reason[:70]}")
                continue
            k = key(reason)
            if helper == "env_skip":
                counts["env"] += 1
                used_env.add(k)
                if k in mask_keys:
                    misclassified.append(
                        f"  - {rel}:{lineno}  env_skip but registered as masking: {k[:60]}"
                    )
                elif k not in env_keys:
                    unregistered.append(f"  - {rel}:{lineno}  [env] {k[:60]}")
            else:
                counts["masking"] += 1
                used_mask.add(k)
                if k in env_keys:
                    misclassified.append(
                        f"  - {rel}:{lineno}  soft_skip but registered as env: {k[:60]}"
                    )
                elif k not in mask_keys:
                    unregistered.append(f"  - {rel}:{lineno}  [masking] {k[:60]}")

stale = sorted((env_keys - used_env) | (mask_keys - used_mask))

print("Skip audit — tests/integration/skip-policy.yaml")
print(f"  files scanned          : {len(files)}")
print(f"  env_skip call sites    : {counts['env']}")
print(f"  soft_skip call sites   : {counts['masking']}")
print(f"  registered reasons     : {len(env_keys)} env / {len(mask_keys)} masking")

if mode == "--report":
    print("\n== masking reasons (fail under EBPFSENTINEL_STRICT_SKIPS=1) ==")
    for k in sorted(used_mask):
        print(f"  - {k}")
    sys.exit(0)

failed = False


def banner(t: str) -> None:
    print(f"\n== {t} ==")


if bare:
    banner("BARE skip calls (use env_skip or soft_skip)")
    print("\n".join(bare))
    failed = True
if unregistered:
    banner("UNREGISTERED reasons (add them to skip-policy.yaml)")
    print("\n".join(unregistered))
    failed = True
if misclassified:
    banner("MISCLASSIFIED reasons (helper disagrees with the policy)")
    print("\n".join(misclassified))
    failed = True
if stale:
    banner("STALE policy entries (registered but no longer used)")
    print("\n".join(f"  - {s}" for s in stale))
    failed = True

sys.exit(1 if failed else 0)
PY
