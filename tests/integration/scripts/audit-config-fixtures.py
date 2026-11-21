#!/usr/bin/env python3
"""Every configuration key is set by a fixture a suite loads, or listed.

The inventory is every field serde reads off the configuration document: each
field of a struct deriving `Deserialize` under `crates/infrastructure/src/config/`,
under the name serde gives it (`rename` honoured, `skip` left out, a `flatten`
field standing for the fields of the struct it names), as `Struct.key`.

The evidence is a YAML document a suite loads: a file under
`tests/integration/fixtures/` whose name a suite, a helper or a script of the
integration tree names, or a here-document of a suite that parses as a
configuration. Each document is walked from `AgentConfig` along the types the
fields declare (`Option`, `Vec`, `Box`, `Arc` and the values of a map seen
through), so a key counts only where the loader would read it, not wherever a
key of the same name appears.

What no fixture sets lives in `config-fixtures.toml` beside the suites, one line
per `Struct.key` under `[keys]`, carrying exactly one of `reason` (no fixture can
stand behind it) or `gap` (one should and does not yet). The number of `gap`
lines equals the top-level `gap_ceiling`. A line for a key a fixture sets, or for
one the loader no longer has, fails. The last line printed is the summary the
meta runner `scripts/audit-surfaces.sh` collects.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
INTEGRATION = REPO / "tests/integration"
SOURCES = sorted((REPO / "crates/infrastructure/src/config").rglob("*.rs"))
MANIFEST = INTEGRATION / "config-fixtures.toml"
GATE = "ebpfsentinel/config-fixtures"
ROOT = "AgentConfig"
KEY_FLOOR = 700

STRUCT = re.compile(
    r"#\[derive\(([^)]*)\)\]((?:\s*#\[[^\]]*\]|\s*///[^\n]*)*)\s*pub struct (\w+)\s*\{(.*?)\n\}",
    re.S,
)
UNTAGGED = re.compile(
    r"#\[serde\([^)]*\buntagged\b[^)]*\)\]((?:\s*#\[[^\]]*\]|\s*///[^\n]*)*)\s*pub enum (\w+)\s*\{(.*?)\n\}",
    re.S,
)
VARIANT = re.compile(r"^\w+\s*\(\s*([A-Za-z_]\w*)\s*\)\s*,?$")
FIELD = re.compile(r"^pub(?:\([^)]*\))?\s+(?:r#)?(\w+)\s*:\s*(.+?),?$")
WRAPPERS = {"Option", "Vec", "Box", "Arc", "HashMap", "BTreeMap", "IndexMap", "HashSet", "BTreeSet"}


def structs(sources: list[Path]) -> dict[str, dict[str, tuple[str, list[str]]]]:
    """Struct name to {key: (field kind, type names)}; kind is `flatten` or `key`."""
    out: dict[str, dict[str, tuple[str, list[str]]]] = {}
    for path in sources:
        for derives, attrs, name, body in STRUCT.findall(path.read_text()):
            if "Deserialize" not in derives or re.search(r'rename_all\s*=\s*"(?!snake_case)', attrs):
                continue
            fields: dict[str, tuple[str, list[str]]] = {}
            pending = ""
            for raw in body.split("\n"):
                line = raw.strip()
                if line.startswith("#["):
                    pending += line
                    continue
                field = FIELD.match(line)
                if field:
                    serde, pending = pending, ""
                    if re.search(r"\bskip\b(?!_)", serde) or "skip_deserializing" in serde:
                        continue
                    types = [t for t in re.findall(r"[A-Za-z_]\w*", field[2]) if t not in WRAPPERS]
                    if re.search(r"\bflatten\b", serde):
                        fields[f"<flatten {field[1]}>"] = ("flatten", types)
                        continue
                    renamed = re.search(r'\brename\s*=\s*"([^"]+)"', serde)
                    fields[renamed[1] if renamed else field[1]] = ("key", types)
                elif line and not line.startswith("//"):
                    pending = ""
            out.setdefault(name, {}).update(fields)
    # An untagged enum is whichever of its newtype variants the value parses
    # as, so its keys are those of every variant struct, as a flatten would be.
    for path in sources:
        for _, name, body in UNTAGGED.findall(path.read_text()):
            for raw in body.split("\n"):
                variant = VARIANT.match(raw.strip())
                if variant:
                    out.setdefault(name, {})[f"<variant {variant[1]}>"] = ("flatten", [variant[1]])
    return out


def keys(graph, name: str) -> set[str]:
    """The keys a value of this type may carry, through flattens and variants."""
    out: set[str] = set()
    for key, (kind, types) in graph.get(name, {}).items():
        if kind == "key":
            out.add(key)
        else:
            for t in types:
                if t != name:
                    out |= keys(graph, t)
    return out


def walk(graph, name: str, value, seen: set[str]) -> None:
    fields = graph.get(name)
    if fields is None or not isinstance(value, dict):
        return
    for _, types in (f for f in fields.values() if f[0] == "flatten"):
        for t in types:
            walk(graph, t, value, seen)
    for key, child in value.items():
        field = fields.get(str(key))
        if field is None or field[0] != "key":
            continue
        seen.add(f"{name}.{key}")
        for t in field[1]:
            if t in graph:
                descend(graph, t, child, seen)


def descend(graph, name: str, value, seen: set[str]) -> None:
    """A field's value: the struct itself, a list of it, or a map whose values are it."""
    if isinstance(value, list):
        for item in value:
            descend(graph, name, item, seen)
    elif isinstance(value, dict):
        if any(str(k) in keys(graph, name) for k in value) or not value:
            walk(graph, name, value, seen)
        else:
            for item in value.values():
                descend(graph, name, item, seen)


def uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def documents() -> list[tuple[str, object]]:
    """Every configuration a suite loads, with where it came from."""
    readers = [
        uncommented(p.read_text())
        for d in ("suites", "lib", "scripts")
        for p in sorted((INTEGRATION / d).iterdir())
        if p.is_file() and p.suffix in (".bats", ".bash", ".sh", ".py")
    ]
    out: list[tuple[str, object]] = []
    for path in sorted((INTEGRATION / "fixtures").rglob("*.yaml")) + sorted(
        (INTEGRATION / "fixtures").rglob("*.yml")
    ):
        if not any(path.name in text for text in readers):
            continue
        try:
            for doc in yaml.safe_load_all(path.read_text()):
                out.append((str(path.relative_to(REPO)), doc))
        except yaml.YAMLError:
            continue
    heredoc = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\s*\1\s*$", re.S | re.M)
    for path in sorted((INTEGRATION / "suites").glob("*.bats")):
        for _, body in heredoc.findall(path.read_text()):
            try:
                doc = yaml.safe_load(body)
            except yaml.YAMLError:
                continue
            out.append((str(path.relative_to(REPO)), doc))
    return out


def main() -> int:
    graph = structs(SOURCES)
    inventory = {f"{s}.{k}" for s, fields in graph.items() for k, f in fields.items() if f[0] == "key"}
    failures: list[str] = []
    if len(inventory) < KEY_FLOOR:
        failures.append(f"read {len(inventory)} keys, floor {KEY_FLOOR}: the scanner no longer reads the loader")
    if ROOT not in graph:
        failures.append(f"no struct {ROOT}: the scanner no longer reads the loader")
    seen: set[str] = set()
    for _, doc in documents():
        walk(graph, ROOT, doc, seen)

    manifest = tomllib.loads(MANIFEST.read_text())
    ceiling = manifest.get("gap_ceiling")
    if not isinstance(ceiling, int):
        failures.append("config-fixtures.toml has no integer gap_ceiling")
    for key in manifest:
        if key not in ("keys", "gap_ceiling"):
            failures.append(f"config-fixtures.toml: unknown table [{key}]")
    lines = manifest.get("keys", {})
    for name in sorted(set(lines) - inventory):
        failures.append(f'[keys."{name}"]: the loader has no such key, drop the line')
    by_scan = by_reason = 0
    gaps: list[str] = []
    for name in sorted(inventory):
        line = lines.get(name)
        if name in seen:
            if line is not None:
                failures.append(f'[keys."{name}"]: a fixture sets it, drop the line')
            by_scan += 1
            continue
        if line is None:
            failures.append(f"key {name}: no fixture a suite loads sets it and config-fixtures.toml does not list it")
            continue
        given = [k for k in ("reason", "gap") if k in line]
        if len(given) != 1 or set(line) != set(given):
            failures.append(f'[keys."{name}"]: carries {sorted(line)}, needs exactly one of reason, gap')
        elif given[0] == "reason":
            by_reason += 1
        else:
            gaps.append(f"gap: {name}: {line['gap']}")

    if isinstance(ceiling, int) and len(gaps) != ceiling:
        failures.append(f"{len(gaps)} gaps but gap_ceiling is {ceiling}: set it to the count")
    for gap in gaps:
        print(gap)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{GATE}: {len(failures)} failures", file=sys.stderr)
        return 1
    print(
        f"{GATE}: {len(inventory)} surfaces, {by_scan} by scan, 0 by suite, "
        f"{by_reason} by reason, {len(gaps)} gaps (ceiling {ceiling})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
