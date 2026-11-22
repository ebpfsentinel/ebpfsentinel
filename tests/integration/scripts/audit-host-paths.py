#!/usr/bin/env python3
"""Every host path the agent or the warden names, against what each
containerised deployment mounts.

A path the code reads off the host works on a host install and silently
reads nothing in a container unless the deployment mounts it. This gate
reads every absolute host path written as a literal in the shipped sources
of the agent and the warden, and for each one asks two deployments:

- compose: is it under a volume target of the `agent` or `warden` service of
  `dist/compose.yaml`? A volume line commented out counts as offered (the
  operator uncomments it for a feature that is off by default) and is printed
  for a reader to judge;
- chart: is it under a literal `mountPath` of `charts/ebpfsentinel/templates`?

What neither deployment mounts carries a line in `tests/integration/host-paths.toml`, under
`[compose."<path>"]` or `[chart."<path>"]`, with exactly one of `reason`
(nothing to mount: the path is inside the image, the container's own,
validated rather than read, or the feature does not run there) or `gap`
(the deployment should mount it and does not). `suites` is not accepted:
the evidence is a mount, not a test.

The domain crate is not read: it does no input or output, and the paths it
names are joined by an adapter onto a root the adapter names. `/proc/self`,
`/dev` and `/tmp` are the container's own wherever it runs.

Prints one line per offered mount, then the summary line; problems go to
stderr and exit 1.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = Path(__file__).resolve().parents[1] / "host-paths.toml"
CRATES = ["adapters", "infrastructure", "warden", "warden-proto", "warden-client", "agent"]
COMPOSE = ROOT / "dist" / "compose.yaml"
CHART = ROOT / "charts" / "ebpfsentinel" / "templates"
COMPOSE_SERVICES = {"agent", "warden"}
FLOOR = 50

HOST_PATH = re.compile(
    r'"(/(?:var|run|etc|home|sys|proc|usr|lib|lib64|opt|srv|root|mnt|media)/[^"\s{}*]*)"'
)
OWN = ("/proc/self", "/dev/", "/tmp/")
TEST_MODULE = re.compile(r"^#\[cfg\(test\)\]\s*\n\s*(?:pub(?:\([^)]*\))?\s+)?mod\s", re.M)


def fail(problems: list[str]) -> None:
    for line in problems:
        print(line, file=sys.stderr)
    sys.exit(1)


def shipped_source(text: str) -> str:
    """The file without its test module and without comment lines."""
    cut = TEST_MODULE.search(text)
    if cut:
        text = text[: cut.start()]
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def inventory() -> dict[str, set[str]]:
    paths: dict[str, set[str]] = {}
    for crate in CRATES:
        for file in sorted((ROOT / "crates" / crate / "src").rglob("*.rs")):
            for match in HOST_PATH.finditer(shipped_source(file.read_text())):
                path = match.group(1).rstrip("/") or "/"
                if path.startswith(OWN) or path + "/" in OWN:
                    continue
                paths.setdefault(path, set()).add(crate)
    return paths


def compose_targets() -> tuple[set[str], set[str]]:
    """Volume targets of the agent and warden services: (mounted, offered)."""
    mounted: set[str] = set()
    offered: set[str] = set()
    service = None
    short = re.compile(r"^\s*(#\s*)?-\s*\"?([^\s:\"]+):(/[^\s:\"]*)")
    long_target = re.compile(r"^\s*(#\s*)?target:\s*\"?(/[^\s\"]+)")
    for line in COMPOSE.read_text().splitlines():
        top = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if top:
            service = top.group(1)
            continue
        if re.match(r"^\S", line):
            service = None
            continue
        if service not in COMPOSE_SERVICES:
            continue
        for pattern in (short, long_target):
            m = pattern.match(line)
            if m:
                target = m.group(3) if pattern is short else m.group(2)
                (offered if m.group(1) else mounted).add(target.rstrip("/") or "/")
    return mounted, offered


def chart_targets() -> set[str]:
    targets: set[str] = set()
    for file in sorted(CHART.glob("*.yaml")):
        for m in re.finditer(r"mountPath:\s*\"?(/[^\s\"{}]+)", file.read_text()):
            targets.add(m.group(1).rstrip("/") or "/")
    return targets


def under(path: str, targets: set[str]) -> bool:
    return any(path == t or path.startswith(t + "/") or t == "/" for t in targets)


def main() -> None:
    problems: list[str] = []
    paths = inventory()
    if len(paths) < FLOOR:
        fail([f"host-paths: {len(paths)} paths read, floor {FLOOR}: the scanner no longer matches the sources"])

    manifest = tomllib.loads(MANIFEST.read_text())
    ceiling = manifest.get("gap_ceiling")
    if not isinstance(ceiling, int):
        problems.append("host-paths.toml: top-level gap_ceiling missing")
        ceiling = 0

    mounted, offered = compose_targets()
    chart = chart_targets()
    if not mounted or not chart:
        problems.append("host-paths: no volume read from compose or chart; the scanner no longer matches them")

    scan = reasons = gaps = 0
    judged: list[str] = []
    for kind, covered in (("compose", lambda p: under(p, mounted)), ("chart", lambda p: under(p, chart))):
        lines = manifest.get(kind, {})
        for path in sorted(set(lines) - set(paths)):
            problems.append(f"host-paths.toml: [{kind}.\"{path}\"] names a path no source reads any more")
        for path in sorted(paths):
            line = lines.get(path)
            if covered(path):
                scan += 1
                if line is not None:
                    problems.append(f"host-paths.toml: [{kind}.\"{path}\"] is stale, the deployment mounts it")
                continue
            if kind == "compose" and under(path, offered):
                scan += 1
                judged.append(f"compose offers {path} commented out (read by {', '.join(sorted(paths[path]))})")
                if line is not None:
                    problems.append(f"host-paths.toml: [{kind}.\"{path}\"] is stale, the deployment offers it")
                continue
            if line is None:
                problems.append(
                    f"{kind} mounts nothing over {path}, read by {', '.join(sorted(paths[path]))}: "
                    f"mount it or add [{kind}.\"{path}\"] to host-paths.toml"
                )
                continue
            keys = {"reason", "gap"} & set(line)
            if len(keys) != 1 or set(line) - {"reason", "gap"}:
                problems.append(f"host-paths.toml: [{kind}.\"{path}\"] needs exactly one of reason or gap")
                continue
            if "gap" in line:
                gaps += 1
            else:
                reasons += 1

    if gaps != ceiling:
        problems.append(f"host-paths.toml: {gaps} gaps against gap_ceiling {ceiling}; the ceiling follows the count")
    if problems:
        fail(problems)
    for line in judged:
        print(line)
    total = scan + reasons + gaps
    print(f"ebpfsentinel/host-paths: {total} surfaces, {scan} by scan, 0 by suite, {reasons} by reason, {gaps} gaps (ceiling {ceiling})")


if __name__ == "__main__":
    main()
