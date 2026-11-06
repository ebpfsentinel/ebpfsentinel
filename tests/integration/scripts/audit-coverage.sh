#!/usr/bin/env bash
# Coverage audit gate - enumerates the agent's observable surface
# (eBPF programs, CLI subcommands, domain modules, the capabilities of
# capabilities.json and the paths of openapi.json) and verifies that
# every entry has a row in tests/integration/coverage-matrix.yaml, or for
# a path, a suite requesting it.
#
# Modes:
#   audit-coverage.sh             check only - exit 1 on any missing row
#   audit-coverage.sh --render    update the fenced coverage block in
#                                 tests/integration/README.md in-place
#   audit-coverage.sh --check-render
#                                 render to a temp buffer and fail if it
#                                 differs from the current README block
#                                 (used by CI to detect stale tables)
#   audit-coverage.sh --help
#
# Requires python3 + PyYAML (preinstalled on ubuntu-latest runners).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${INTEG_DIR}/../.." && pwd)"

MODE="${1:-audit}"

case "${MODE}" in
  --help|-h)
    sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  --render|--check-render|audit) ;;
  *)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 required" >&2
  exit 2
fi

exec python3 - "${REPO_ROOT}" "${INTEG_DIR}" "${MODE}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "PyYAML not installed. apt: python3-yaml | pip: pyyaml\n"
    )
    sys.exit(2)

repo_root = Path(sys.argv[1])
integ_dir = Path(sys.argv[2])
mode = sys.argv[3]

matrix_path = integ_dir / "coverage-matrix.yaml"
readme_path = integ_dir / "README.md"
suites_dir = integ_dir / "suites"
# Perf suites live in a sibling tree (tests/perf) and are referenced from
# the matrix as `perf/NN`. They run from tests/perf/Makefile, not the
# integration CI matrix, but the audit must still resolve their ids.
perf_dir = integ_dir.parent / "perf"

if not matrix_path.exists():
    sys.stderr.write(f"coverage matrix missing: {matrix_path}\n")
    sys.exit(2)

with matrix_path.open() as fh:
    matrix = yaml.safe_load(fh)

skip_domains = set(matrix.get("skip_domains") or [])
# `nested_cli_subcommands` lists logical CLI surfaces that are nested
# under a parent `Command` variant (e.g. `nat nptv6 ...`). They are
# documented as cli_subcommand rows for traceability but don't appear
# as top-level variants in cli.rs, so the audit must not flag them as
# extras.
allowed_nested_cli = set(matrix.get("nested_cli_subcommands") or [])
rows = matrix.get("coverage") or []
owners = set((matrix.get("owners") or {}).keys())
route_entries = matrix.get("routes") or {}

# ── Enumerate observable surface on disk ────────────────────────────
ebpf_dir = repo_root / "crates" / "ebpf-programs"
disk_ebpf = sorted(
    p.name
    for p in ebpf_dir.iterdir()
    if p.is_dir() and (p / "Cargo.toml").exists()
) if ebpf_dir.exists() else []

domain_dir = repo_root / "crates" / "domain" / "src"
disk_domains = sorted(
    p.name
    for p in domain_dir.iterdir()
    if p.is_dir() and p.name not in skip_domains
) if domain_dir.exists() else []

cli_path = repo_root / "crates" / "agent" / "src" / "cli.rs"
disk_cli = []
if cli_path.exists():
    src = cli_path.read_text()
    m = re.search(r"pub enum Command\s*\{(.*?)\n\}", src, re.DOTALL)
    if not m:
        sys.stderr.write("could not locate `pub enum Command` in cli.rs\n")
        sys.exit(2)
    body = m.group(1)
    variant_re = re.compile(r"^\s*([A-Z][A-Za-z0-9]*)\s*(\(|,|\{)", re.M)
    disk_cli = sorted({v.group(1).lower() for v in variant_re.finditer(body)})

capabilities_path = repo_root / "capabilities.json"
disk_capabilities: list[str] = []
if capabilities_path.exists():
    catalogue = json.loads(capabilities_path.read_text())
    disk_capabilities = [c["id"] for c in catalogue.get("capabilities", [])]

openapi_path = repo_root / "openapi.json"
disk_routes: list[str] = []
if openapi_path.exists():
    disk_routes = sorted(json.loads(openapi_path.read_text()).get("paths", {}).keys())

# ── Index matrix rows by kind ───────────────────────────────────────
by_kind: dict[str, dict[str, dict]] = {}
dups: list[str] = []
for row in rows:
    kind = row.get("kind")
    feat = row.get("feature")
    if not kind or not feat:
        sys.stderr.write(f"row missing kind/feature: {row!r}\n")
        sys.exit(2)
    bucket = by_kind.setdefault(kind, {})
    if feat in bucket:
        dups.append(f"{kind}/{feat}")
    bucket[feat] = row

# ── Compare against disk ────────────────────────────────────────────
groups = [
    ("ebpf_program", disk_ebpf),
    ("cli_subcommand", disk_cli),
    ("domain_module", disk_domains),
    ("capability", disk_capabilities),
]

missing: list[str] = []
extra: list[str] = []
for kind, disk in groups:
    matrix_set = set(by_kind.get(kind, {}).keys())
    disk_set = set(disk)
    for feat in sorted(disk_set - matrix_set):
        missing.append(f"  - kind={kind} feature={feat}")
    for feat in sorted(matrix_set - disk_set):
        if kind == "cli_subcommand" and feat in allowed_nested_cli:
            continue
        extra.append(f"  - kind={kind} feature={feat}")

# ── Cross-check suite ids ───────────────────────────────────────────
known_suites: set[str] = set()
if suites_dir.exists():
    for p in suites_dir.iterdir():
        m = re.match(r"^(\d{2})-", p.name)
        if m:
            known_suites.add(m.group(1))

known_perf_suites: set[str] = set()
if perf_dir.exists():
    for p in perf_dir.iterdir():
        m = re.match(r"^(\d{2})-.*\.bats$", p.name)
        if m:
            known_perf_suites.add(f"perf/{m.group(1)}")
known_suites |= known_perf_suites

stale_suite_refs: list[str] = []
tbd_rows: list[str] = []
bad_owners: list[str] = []
for row in rows:
    feat = row.get("feature")
    kind = row.get("kind")
    suites = row.get("suites") or []
    if suites == ["TBD"]:
        owner = row.get("owner")
        if owner not in owners:
            bad_owners.append(f"  - {kind}/{feat} owner={owner!r}")
        tbd_rows.append(f"  - {kind}/{feat} (owner: {owner})")
        continue
    for s in suites:
        if s not in known_suites:
            stale_suite_refs.append(f"  - {kind}/{feat} references suite {s}")

# ── Routes: found in the suites, or listed with suites or an owner ──
suite_texts: dict[str, str] = {}
if suites_dir.exists():
    for p in sorted(suites_dir.iterdir()):
        m = re.match(r"^(\d{2})-.*\.bats$", p.name)
        if m:
            suite_texts[m.group(1)] = p.read_text()

def route_pattern(path: str) -> re.Pattern:
    rx = re.escape(path)
    rx = re.sub(r"\\\{[^}]*\\\}", r"[^/\\s\"']+", rx)
    return re.compile(rx + r"(?![A-Za-z0-9_/-])")

route_suites: dict[str, list[str]] = {}
for path in disk_routes:
    pat = route_pattern(path)
    route_suites[path] = sorted(s for s, text in suite_texts.items() if pat.search(text))

uncovered_routes: list[str] = []
stale_route_entries: list[str] = []
for path in disk_routes:
    entry = route_entries.get(path)
    found = route_suites[path]
    if entry is None:
        if not found:
            uncovered_routes.append(f"  - {path}")
        continue
    if "owner" in entry:
        if entry["owner"] not in owners:
            bad_owners.append(f"  - route {path} owner={entry['owner']!r}")
        if found:
            stale_route_entries.append(
                f"  - {path} is requested by {', '.join(found)}: drop its `routes` line"
            )
        else:
            tbd_rows.append(f"  - route {path} (owner: {entry['owner']})")
    else:
        for s in entry.get("suites") or []:
            if s not in known_suites:
                stale_suite_refs.append(f"  - route {path} references suite {s}")
        if not entry.get("suites"):
            bad_owners.append(f"  - route {path} lists neither suites nor an owner")
for path in sorted(set(route_entries) - set(disk_routes)):
    stale_route_entries.append(f"  - {path} is not a path of openapi.json")

# ── Validate suite_profiles map ─────────────────────────────────────
suite_profiles_raw = matrix.get("suite_profiles") or {}
valid_profiles = {"pr", "nightly", "manual"}
bad_profile_values: list[str] = []
for sid, prof in suite_profiles_raw.items():
    if prof not in valid_profiles:
        bad_profile_values.append(f"  - {sid} -> '{prof}'")

suite_profile_keys = {str(k) for k in suite_profiles_raw}
missing_profile_for_suite = sorted(known_suites - suite_profile_keys)
extra_profile_for_suite = sorted(suite_profile_keys - known_suites)

# ── Report ──────────────────────────────────────────────────────────
def banner(t: str) -> None:
    print(f"\n== {t} ==")

print("Coverage audit - tests/integration/coverage-matrix.yaml")
print(f"  eBPF programs on disk : {len(disk_ebpf)}")
print(f"  CLI subcommands       : {len(disk_cli)}")
print(f"  Domain modules        : {len(disk_domains)} (skipped: {sorted(skip_domains)})")
print(f"  Capabilities          : {len(disk_capabilities)}")
print(f"  API paths             : {len(disk_routes)}")
print(f"  Matrix rows total     : {len(rows)}")
print(f"  Known suites on disk  : {len(known_suites)}")

failed = False
if dups:
    banner("DUPLICATE matrix rows (same kind+feature)")
    print("\n".join(f"  - {d}" for d in dups))
    failed = True
if missing:
    banner("MISSING matrix rows (on disk but no row)")
    print("\n".join(missing))
    failed = True
if extra:
    banner("EXTRA matrix rows (row exists but not on disk)")
    print("\n".join(extra))
    failed = True
if stale_suite_refs:
    banner("STALE suite references (suite id not under suites/)")
    print("\n".join(stale_suite_refs))
    failed = True

if bad_owners:
    banner("GAPS with no owner (owner must be a key of `owners`)")
    print("\n".join(bad_owners))
    failed = True
if uncovered_routes:
    banner("UNCOVERED routes (no suite requests them, no `routes` line)")
    print("\n".join(uncovered_routes))
    failed = True
if stale_route_entries:
    banner("STALE `routes` lines")
    print("\n".join(stale_route_entries))
    failed = True

if bad_profile_values:
    banner("INVALID suite_profiles values (allowed: pr | nightly | manual)")
    print("\n".join(bad_profile_values))
    failed = True
if missing_profile_for_suite:
    banner("MISSING suite_profiles entries (suite on disk, no profile pin)")
    print("\n".join(f"  - {s}" for s in missing_profile_for_suite))
    failed = True
if extra_profile_for_suite:
    banner("EXTRA suite_profiles entries (profile pin, no suite on disk)")
    print("\n".join(f"  - {s}" for s in extra_profile_for_suite))
    failed = True

if tbd_rows:
    banner(f"No suite yet ({len(tbd_rows)} rows and routes, each with its owner)")
    print("\n".join(tbd_rows))

# ── Markdown render ─────────────────────────────────────────────────
def render_table(kind: str, header: str, disk: list[str]) -> str:
    out = [f"#### {header}", ""]
    out.append("| Feature | Suites | Topology | Kernel | Profile | Notes |")
    out.append("|---|---|---|---|---|---|")
    bucket = by_kind.get(kind, {})
    for feat in sorted(disk):
        row = bucket.get(feat)
        if row is None:
            out.append(f"| `{feat}` | _MISSING_ | - | - | - | - |")
            continue
        suites = row.get("suites") or []
        if suites == ["TBD"]:
            suites_s = f"No suite yet ({row.get('owner', '?')})"
        else:
            suites_s = ", ".join(suites) if suites else "-"
        out.append(
            f"| `{feat}` "
            f"| {suites_s} "
            f"| {row.get('topology', '-')} "
            f"| {row.get('kernel_min', '-')} "
            f"| {row.get('profile', '-')} "
            f"| {row.get('notes', '')} |"
        )
    out.append("")
    return "\n".join(out)

def render_routes() -> str:
    out = [f"#### API paths ({len(disk_routes)})", ""]
    out.append("| Path | Suites |")
    out.append("|---|---|")
    for path in disk_routes:
        entry = route_entries.get(path) or {}
        found = route_suites.get(path) or []
        if found:
            cell = ", ".join(found)
        elif "owner" in entry:
            cell = f"No suite yet ({entry['owner']})"
        else:
            cell = ", ".join(entry.get("suites") or []) or "_MISSING_"
        out.append(f"| `{path}` | {cell} |")
    out.append("")
    return "\n".join(out)

rendered_block = "\n".join(
    [
        "<!-- coverage:start -->",
        "<!-- AUTO-GENERATED by tests/integration/scripts/audit-coverage.sh --render. Do not edit by hand. -->",
        "",
        "_Generated from `coverage-matrix.yaml`. Run `scripts/audit-coverage.sh --render` after adding/removing a feature._",
        "",
        render_table("ebpf_program", f"eBPF programs ({len(disk_ebpf)})", disk_ebpf),
        render_table("cli_subcommand", f"CLI subcommands ({len(disk_cli)})", disk_cli),
        render_table("domain_module", f"Domain modules ({len(disk_domains)})", disk_domains),
        render_table("capability", f"Capabilities above the floor ({len(disk_capabilities)})", disk_capabilities),
        render_routes(),
        "<!-- coverage:end -->",
    ]
)

def splice_block(text: str, block: str) -> tuple[str, bool]:
    pat = re.compile(
        r"<!-- coverage:start -->.*?<!-- coverage:end -->",
        re.DOTALL,
    )
    if not pat.search(text):
        return text, False
    return pat.sub(block, text, count=1), True

if mode == "--render":
    if not readme_path.exists():
        sys.stderr.write(f"README missing: {readme_path}\n")
        sys.exit(2)
    text = readme_path.read_text()
    new_text, found = splice_block(text, rendered_block)
    if not found:
        sys.stderr.write(
            "no <!-- coverage:start --> ... <!-- coverage:end --> markers in README\n"
        )
        sys.exit(2)
    if new_text != text:
        readme_path.write_text(new_text)
        print(f"\nREADME coverage block updated: {readme_path}")
    else:
        print("\nREADME coverage block already up-to-date")

elif mode == "--check-render":
    if not readme_path.exists():
        sys.stderr.write(f"README missing: {readme_path}\n")
        sys.exit(2)
    text = readme_path.read_text()
    new_text, found = splice_block(text, rendered_block)
    if not found:
        sys.stderr.write(
            "no <!-- coverage:start --> ... <!-- coverage:end --> markers in README\n"
        )
        sys.exit(2)
    if new_text != text:
        sys.stderr.write(
            "README coverage block is stale - run "
            "`tests/integration/scripts/audit-coverage.sh --render` and commit.\n"
        )
        failed = True
    else:
        print("\nREADME coverage block is up-to-date")

if failed:
    sys.exit(1)
sys.exit(0)
PY
