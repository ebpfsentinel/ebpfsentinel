#!/usr/bin/env python3
"""Every alert component reaches an alert in a suite, every metric is asserted.

Two inventories, read off the code outside its test modules:

- `component`: the value an alert carries in its `component` field. Read from
  `const <NAME>_COMPONENT: &str = "<value>"`, from `component: "<value>"`
  literals, from the arms that turn a `PacketAlertComponent` into its string,
  and from the first argument of `Alert::operational(...)` and
  `Alert::from_ai_security(...)` when it is a literal, in `crates/domain/src`
  and `crates/application/src`.
- `metric`: every family registered on the agent's Prometheus registry in
  `crates/adapters/src/metrics.rs`, exposed as `ebpfsentinel_<name>`.

The evidence is a line of `tests/integration/suites/*.bats` or
`tests/integration/lib/*.bash` (comment lines aside):

- `component`: the suite selects alerts by that component, as a jq filter
  (`.component == "<value>"`) or as the alerts API query (`component=<value>`).
- `metric`: the suite names the exposed family (`ebpfsentinel_<name>`, a
  `_total`, `_bucket`, `_sum` or `_count` suffix allowed).

What no scan sees lives in `alerts-metrics.toml` beside the suites, one table
per kind (`component`, `metric`), one line per surface, carrying exactly one of
`suites` (suites that reach it another way, each of which must exist and still
name the surface), `reason` (no evidence can stand behind it) or `gap` (it
should have evidence and does not yet). The number of `gap` lines equals the
top-level `gap_ceiling`. A line for a surface the scan sees, or for one the
code no longer has, fails. The last line printed is the summary the meta
runner `scripts/audit-surfaces.sh` collects.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
INTEGRATION = REPO / "tests/integration"
MANIFEST = INTEGRATION / "alerts-metrics.toml"
GATE = "ebpfsentinel/alerts-metrics"
KINDS = ("component", "metric")
FLOORS = {"component": 20, "metric": 100}


def without_tests(text: str) -> str:
    cut = re.search(r"^#\[cfg\(test\)\]\s*\n\s*mod ", text, re.M)
    return text[: cut.start()] if cut else text


def sources(*dirs: str) -> list[str]:
    out = []
    for d in dirs:
        for path in sorted((REPO / d).rglob("*.rs")):
            if "tests" not in path.relative_to(REPO).parts:
                out.append(without_tests(path.read_text()))
    return out


def components() -> set[str]:
    found: set[str] = set()
    for text in sources("crates/domain/src", "crates/application/src"):
        found.update(re.findall(r'const [A-Z_]*COMPONENT: &str = "([a-z0-9_-]+)"', text))
        found.update(re.findall(r'\bcomponent: "([a-z0-9_-]+)"', text))
        found.update(re.findall(r'PacketAlertComponent::\w+ => "([a-z0-9_-]+)"', text))
        found.update(re.findall(r'(?:Alert|Self)::(?:operational|from_ai_security)\(\s*"([a-z0-9_-]+)"', text))
    return found


def metrics() -> set[str]:
    text = without_tests((REPO / "crates/adapters/src/metrics.rs").read_text())
    return set(re.findall(r'\.register\(\s*"([a-z0-9_]+)"', text))


def suite_texts() -> dict[str, str]:
    texts = {}
    for path in sorted((INTEGRATION / "suites").glob("*.bats")):
        texts[path.name.split("-")[0]] = uncommented(path.read_text())
    return texts


def helper_texts() -> list[str]:
    return [uncommented(p.read_text()) for p in sorted((INTEGRATION / "lib").glob("*.bash"))]


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def component_seen(name: str, text: str) -> bool:
    quoted = re.escape(name)
    return bool(
        re.search(r'\.component\s*==\s*\\?"' + quoted + r'\\?"', text)
        or re.search(r"[?&]component=" + quoted + r"\b", text)
    )


def metric_seen(name: str, text: str) -> bool:
    return bool(re.search(r"\bebpfsentinel_" + re.escape(name) + r"(_total|_bucket|_sum|_count)?\b", text))


def main() -> int:
    inventory = {"component": components(), "metric": metrics()}
    failures: list[str] = []
    for kind, floor in FLOORS.items():
        if len(inventory[kind]) < floor:
            failures.append(f"read {len(inventory[kind])} {kind}s, floor {floor}: the scanner no longer reads the code")
    suites = suite_texts()
    texts = list(suites.values()) + helper_texts()
    seen_by = {"component": component_seen, "metric": metric_seen}

    manifest = tomllib.loads(MANIFEST.read_text())
    ceiling = manifest.get("gap_ceiling")
    if not isinstance(ceiling, int):
        failures.append("alerts-metrics.toml has no integer gap_ceiling")
    for key in manifest:
        if key not in KINDS and key != "gap_ceiling":
            failures.append(f"alerts-metrics.toml: unknown table [{key}]")

    by_scan = by_suite = by_reason = 0
    gaps: list[str] = []
    for kind in KINDS:
        lines = manifest.get(kind, {})
        for name in sorted(set(lines) - inventory[kind]):
            failures.append(f'[{kind}."{name}"]: the code has no such {kind}, drop the line')
        for name in sorted(inventory[kind]):
            line = lines.get(name)
            if any(seen_by[kind](name, t) for t in texts):
                if line is not None:
                    failures.append(f'[{kind}."{name}"]: covered by the scan, drop the line')
                by_scan += 1
                continue
            if line is None:
                failures.append(f"{kind} {name}: no suite reaches it and alerts-metrics.toml does not list it")
                continue
            given = [k for k in ("suites", "reason", "gap") if k in line]
            if len(given) != 1 or set(line) != set(given):
                failures.append(f'[{kind}."{name}"]: carries {sorted(line)}, needs exactly one of suites, reason, gap')
                continue
            if given[0] == "suites":
                ok = True
                for number in line["suites"]:
                    text = suites.get(str(number))
                    if text is None:
                        failures.append(f'[{kind}."{name}"]: suite {number} does not exist')
                        ok = False
                    elif name not in text:
                        failures.append(f'[{kind}."{name}"]: suite {number} no longer names {name}')
                        ok = False
                by_suite += ok
            elif given[0] == "reason":
                by_reason += 1
            else:
                gaps.append(f"gap: {kind} {name}: {line['gap']}")

    if isinstance(ceiling, int) and len(gaps) != ceiling:
        failures.append(f"{len(gaps)} gaps but gap_ceiling is {ceiling}: set it to the count")
    for gap in gaps:
        print(gap)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{GATE}: {len(failures)} failures", file=sys.stderr)
        return 1
    total = sum(len(v) for v in inventory.values())
    print(
        f"{GATE}: {total} surfaces, {by_scan} by scan, {by_suite} by suite, "
        f"{by_reason} by reason, {len(gaps)} gaps (ceiling {ceiling})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
