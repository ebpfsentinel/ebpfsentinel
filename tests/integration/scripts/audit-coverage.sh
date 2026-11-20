#!/usr/bin/env bash
# Coverage audit gate - enumerates the agent's observable surface
# (eBPF programs, CLI subcommands, domain modules, the capabilities of
# capabilities.json and the paths of openapi.json) and verifies that
# every entry has a row in tests/integration/coverage-matrix.yaml, or for
# a path, a suite requesting it and reading the answer. The last line printed
# is the routes summary the meta runner scripts/audit-surfaces.sh collects.
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
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
# as top-level variants in cli/args.rs, so the audit must not flag them as
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

# The command enum lives in the CLI library's argument module. A missing file
# is an error rather than an empty list: an empty list reads every CLI row as
# extra and every command as covered, which is how a move went unnoticed.
cli_path = repo_root / "crates" / "agent" / "src" / "cli" / "args.rs"
if not cli_path.exists():
    sys.stderr.write(f"CLI argument module not found at {cli_path}\n")
    sys.exit(2)
src = cli_path.read_text()
m = re.search(r"pub enum Command\s*\{(.*?)\n\}", src, re.DOTALL)
if not m:
    sys.stderr.write(f"could not locate `pub enum Command` in {cli_path}\n")
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
        m = re.match(r"^(\d{2,})-", p.name)
        if m:
            known_suites.add(m.group(1))

known_perf_suites: set[str] = set()
if perf_dir.exists():
    for p in perf_dir.iterdir():
        m = re.match(r"^(\d{2,})-.*\.bats$", p.name)
        if m:
            known_perf_suites.add(f"perf/{m.group(1)}")
known_suites |= known_perf_suites

# A surface whose only caller lives in a sibling repository is asserted
# there: `elsewhere` names `<sibling>/<id>` and resolves under that
# sibling's suites directory when it is checked out beside this tree.
sibling_suite_dirs = {
    "ebpfsentinel-enterprise": Path("tests/integration/suites"),
    "ebpfsentinel-operator/coexistence": Path("tests/coexistence/suites"),
}
sibling_root = repo_root.parent

def resolve_elsewhere(ref: str) -> str | None:
    """None when the reference resolves or its sibling is absent, else why not."""
    m = re.match(r"^(.+)/(\d{2,})$", ref)
    if not m or m.group(1) not in sibling_suite_dirs:
        return f"`{ref}` is not <sibling>/<id> with a known sibling"
    repo = m.group(1).split("/")[0]
    if not (sibling_root / repo).is_dir():
        unverified_elsewhere.append(ref)
        return None
    d = sibling_root / repo / sibling_suite_dirs[m.group(1)]
    if d.is_dir() and any(p.name.startswith(m.group(2) + "-") and p.suffix == ".bats" for p in d.iterdir()):
        return None
    return f"`{ref}` names no suite under {repo}/{sibling_suite_dirs[m.group(1)]}"

stale_suite_refs: list[str] = []
tbd_rows: list[str] = []
bad_owners: list[str] = []
unverified_elsewhere: list[str] = []
for row in rows:
    feat = row.get("feature")
    kind = row.get("kind")
    suites = row.get("suites") or []
    elsewhere = row.get("elsewhere") or []
    for ref in elsewhere:
        why = resolve_elsewhere(ref)
        if why:
            stale_suite_refs.append(f"  - {kind}/{feat} elsewhere: {why}")
    if not suites and not elsewhere:
        stale_suite_refs.append(f"  - {kind}/{feat} lists neither suites nor elsewhere")
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
# A route counts where code requests it and reads the answer: a full-line
# comment naming a path requests nothing, a path requested inside a lib helper
# is requested by every suite that calls that helper, directly or through
# another helper, and inside one `@test` an assertion (`assert_*`, `jq -e`, a
# `[ ... ]` test, `grep -q`) must follow the line that requests the route, or
# the helper call that does. A path requested only in `setup_file`, or by a
# test that reads nothing back, is not covered. Tests whose only check is a
# status code are listed after the audit, for a reader to judge.
def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))

func_def_re = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{?\s*$")
lib_funcs: dict[str, str] = {}
lib_dir = integ_dir / "lib"
if lib_dir.exists():
    for p in sorted(lib_dir.glob("*.bash")):
        name, body = None, []
        for line in uncommented(p.read_text()).splitlines():
            m = func_def_re.match(line)
            if m:
                if name:
                    lib_funcs[name] = lib_funcs.get(name, "") + "\n".join(body)
                name, body = m.group(1), []
            elif name:
                body.append(line)
        if name:
            lib_funcs[name] = lib_funcs.get(name, "") + "\n".join(body)

def word_re(name: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])")

def route_pattern(path: str) -> re.Pattern:
    rx = re.escape(path)
    rx = re.sub(r"\\\{[^}]*\\\}", r"[^/\\s\"']+", rx)
    return re.compile(rx + r"(?![A-Za-z0-9_/-])")

TEST_START = re.compile(r"^@test\s+[\"'](.*)[\"']\s*\{\s*$")
ASSERTION = re.compile(
    r"(?<![A-Za-z0-9_])(?:assert_[A-Za-z_]+|jq\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*e[A-Za-z]*\b"
    r"|grep\s+-[A-Za-z]*q|\[\[?\s|\bcmp\s|\bdiff\s)"
)
STATUS_ONLY = re.compile(
    r"^\s*(?:assert_http_status\b|\[\s+\"\$(?:output|status|code|http_code)\"\s+(?:=|-eq)\s+\"?\d{3}\"?\s+\])"
)

def blocks_of(text: str) -> tuple[list[tuple[str, list[str]]], dict[str, list[str]]]:
    """Each `@test` of a suite as its name and body lines, and the functions
    the suite defines for its tests, as their body lines."""
    tests: list[tuple[str, list[str]]] = []
    local: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        test = TEST_START.match(line)
        func = func_def_re.match(line)
        if test:
            current = []
            tests.append((test.group(1), current))
        elif func and not line.startswith((" ", "\t")):
            current = local.setdefault(func.group(1), [])
        elif line.startswith("}"):
            current = None
        elif current is not None:
            current.append(line)
    return tests, local

def calls_of(names) -> re.Pattern | None:
    """One pattern matching a call to any of these functions, as a word."""
    if not names:
        return None
    alternatives = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(r"(?<![A-Za-z0-9_])(" + alternatives + r")(?![A-Za-z0-9_])")

def reads_answer(lines, rx, calls, reading, checking) -> tuple[bool, bool]:
    """Whether these lines request the route, and whether an assertion reads
    the answer: one follows the request, the call that requests it is to a
    function that reads the answer itself, or the path is handed as an
    argument to a function that checks what it gets back. `calls` matches a
    call to a function already known to request the route."""
    requested = False
    for i, line in enumerate(lines):
        direct = rx.search(line)
        called = set(calls.findall(line)) if calls else set()
        if not direct and not called:
            continue
        requested = True
        if called & reading:
            return True, True
        if direct and any(call.search(line) for call in checking.values()):
            return True, True
        if any(ASSERTION.search(rest) for rest in lines[i:]):
            return True, True
    return requested, False

lib_lines = {name: body.splitlines() for name, body in lib_funcs.items()}
lib_text = "\n".join(lib_funcs.values())
parsed_suites: dict[str, tuple[list[tuple[str, list[str]]], dict[str, list[str]]]] = {}
suite_raw: dict[str, str] = {}
if suites_dir.exists():
    for p in sorted(suites_dir.iterdir()):
        m = re.match(r"^(\d{2,})-.*\.bats$", p.name)
        if m:
            suite_raw[m.group(1)] = uncommented(p.read_text())
            parsed_suites[m.group(1)] = blocks_of(suite_raw[m.group(1)])

def checkers(bodies: dict[str, list[str]]) -> dict[str, re.Pattern]:
    """The functions that assert on what they get, as the pattern of a line
    handing them an argument."""
    return {
        name: re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+|!\s+|run\s+)*" + re.escape(name) + r"(?![A-Za-z0-9_])")
        for name, lines in bodies.items()
        if any(ASSERTION.search(line) for line in lines)
    }

def settle(bodies, rx, checking, requesting: dict, reading: set) -> None:
    """Grow the functions that request the route and those that read its
    answer until no body adds one."""
    changed = True
    while changed:
        changed = False
        calls = calls_of(requesting)
        for name, lines in bodies.items():
            did, read = reads_answer(lines, rx, calls, reading, checking)
            if did and name not in requesting:
                requesting[name] = True
                changed = True
            if read and name not in reading:
                reading.add(name)
                changed = True

lib_checking = checkers(lib_lines)
# A suite's own function shadows a library one of the same name.
suite_bodies = {s: {**lib_lines, **local} for s, (_, local) in parsed_suites.items()}
suite_checking = {s: checkers(bodies) for s, bodies in suite_bodies.items()}

def read_back(path: str) -> tuple[list[str], list[str]]:
    """The suites whose tests request the route and read the answer, and
    the tests that request it and read nothing back."""
    rx = route_pattern(path)
    asserted, silent = [], []
    in_lib = bool(rx.search(lib_text))
    lib_requesting: dict[str, bool] = {}
    lib_reading: set[str] = set()
    if in_lib:
        settle(lib_lines, rx, lib_checking, lib_requesting, lib_reading)
    for suite, (blocks, local) in parsed_suites.items():
        # Nothing names the path: no line of this suite can request it.
        if not in_lib and not rx.search(suite_raw[suite]):
            continue
        # The library alone answers part of the question; a suite that
        # shadows none of its functions starts from that answer.
        shadowed = bool(set(local) & set(lib_lines))
        requesting = {} if shadowed else dict(lib_requesting)
        reading = set() if shadowed else set(lib_reading)
        settle(suite_bodies[suite], rx, suite_checking[suite], requesting, reading)
        calls = calls_of(requesting)
        for name, lines in blocks:
            did, read = reads_answer(lines, rx, calls, reading, suite_checking[suite])
            if read:
                if suite not in asserted:
                    asserted.append(suite)
            elif did:
                silent.append(f"{suite}: {name}")
    return sorted(asserted), silent

route_suites: dict[str, list[str]] = {}
route_silent: dict[str, list[str]] = {}
for path in disk_routes:
    route_suites[path], route_silent[path] = read_back(path)

# Tests whose only check is a status code: covered, but for a reader to judge.
status_only_tests: list[str] = []
for suite, (blocks, _) in parsed_suites.items():
    for name, lines in blocks:
        checks = [line for line in lines if ASSERTION.search(line)]
        if checks and all(STATUS_ONLY.match(line) for line in checks) and "/api/" in "\n".join(lines):
            status_only_tests.append(f"  - {suite}: {name}")

uncovered_routes: list[str] = []
stale_route_entries: list[str] = []
routes_by_scan = routes_by_suite = routes_gaps = 0
for path in disk_routes:
    entry = route_entries.get(path)
    found = route_suites[path]
    if entry is None:
        if found:
            routes_by_scan += 1
        elif route_silent[path]:
            uncovered_routes.append(
                f"  - {path} (requested by {'; '.join(route_silent[path])}, and no assertion reads the answer)"
            )
        else:
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
            routes_gaps += 1
            tbd_rows.append(f"  - route {path} (owner: {entry['owner']})")
    else:
        for s in entry.get("suites") or []:
            if s not in known_suites:
                stale_suite_refs.append(f"  - route {path} references suite {s}")
        for ref in entry.get("elsewhere") or []:
            why = resolve_elsewhere(ref)
            if why:
                stale_suite_refs.append(f"  - route {path} elsewhere: {why}")
        if not entry.get("suites") and not entry.get("elsewhere"):
            bad_owners.append(f"  - route {path} lists neither suites, elsewhere nor an owner")
        else:
            routes_by_suite += 1
for path in sorted(set(route_entries) - set(disk_routes)):
    stale_route_entries.append(f"  - {path} is not a path of openapi.json")

# ── Validate suite_profiles map ─────────────────────────────────────
suite_profiles_raw = matrix.get("suite_profiles") or {}
valid_profiles = {"pr", "datapath", "nightly", "manual"}
bad_profile_values: list[str] = []
for sid, prof in suite_profiles_raw.items():
    if prof not in valid_profiles:
        bad_profile_values.append(f"  - {sid} -> '{prof}'")

# A profile is only a promise if a job of the integration workflow lists it:
# a suite pinned to a profile no job asks for is a suite that runs nowhere,
# and a job that lists a profile but skips some of its suites by id hides the
# same thing one level down.
workflow_path = repo_root / ".github" / "workflows" / "integration.yml"
workflow_text = workflow_path.read_text() if workflow_path.exists() else ""
listed_profiles = set(re.findall(r"list-suites-by-profile\.sh --list (\w+)", workflow_text))
unselected_suites = sorted(
    f"  - {sid} -> '{prof}' (no job of integration.yml lists this profile)"
    for sid, prof in suite_profiles_raw.items()
    if prof in valid_profiles and prof not in listed_profiles
)
skipped_in_job = re.findall(r"deferred to nightly|requires kernel/root", workflow_text)
if skipped_in_job:
    unselected_suites.append(
        "  - integration.yml skips suites of a listed profile by id: move them to the profile that runs them"
    )

# A row's `profile` is read as the trigger its verdict comes from, so it must
# be the profile of one of its suites: a row saying `pr` whose suites all run
# nightly promises a pull-request verdict nobody gives.
row_profile_lies: list[str] = []
for row in rows:
    pinned = {
        suite_profiles_raw[str(s)]
        for s in row.get("suites") or []
        if str(s) in suite_profiles_raw
    }
    if pinned and row.get("profile") not in pinned:
        row_profile_lies.append(
            f"  - {row.get('kind')}/{row.get('feature')}: profile '{row.get('profile')}', "
            f"its suites run on {sorted(pinned)}"
        )

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
    banner("INVALID suite_profiles values (allowed: pr | datapath | nightly | manual)")
    print("\n".join(bad_profile_values))
    failed = True
if missing_profile_for_suite:
    banner("MISSING suite_profiles entries (suite on disk, no profile pin)")
    print("\n".join(f"  - {s}" for s in missing_profile_for_suite))
    failed = True
if unselected_suites:
    banner("Suites no job of integration.yml runs")
    print("\n".join(unselected_suites))
    failed = True
if row_profile_lies:
    banner("Rows naming a profile none of their suites runs on")
    print("\n".join(row_profile_lies))
    failed = True
if extra_profile_for_suite:
    banner("EXTRA suite_profiles entries (profile pin, no suite on disk)")
    print("\n".join(f"  - {s}" for s in extra_profile_for_suite))
    failed = True

if unverified_elsewhere:
    banner("Suites in a sibling not checked out here (not verified)")
    print("\n".join(f"  - {r}" for r in sorted(set(unverified_elsewhere))))

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
            suites_s = ", ".join(suites + (row.get("elsewhere") or [])) or "-"
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

if status_only_tests:
    banner(f"Status only ({len(status_only_tests)} tests whose only check is a status code, for a reader to judge)")
    print("\n".join(status_only_tests))

if failed:
    sys.exit(1)
# The routes half of this audit in the standard form the meta runner
# `scripts/audit-surfaces.sh` collects: no `routes` line has a reason, and the
# lines naming an owner are the gaps.
print(
    f"\nebpfsentinel/routes: {len(disk_routes)} surfaces, {routes_by_scan} by scan, "
    f"{routes_by_suite} by suite, 0 by reason, {routes_gaps} gaps"
)
sys.exit(0)
PY
