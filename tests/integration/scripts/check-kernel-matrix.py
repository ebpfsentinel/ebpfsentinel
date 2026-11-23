#!/usr/bin/env python3
"""The kernels the agents are run on, held to the agent and to kernel.org.

`tests/integration/kernels.toml` lists every kernel release, as major.minor,
from the floor to the newest stable, plus at most one release under
development. The point release a run boots is resolved when it runs (--resolve),
never written in the list. This gate fails when:

- `floor` differs from MIN_KERNEL_MAJOR.MIN_KERNEL_MINOR in
  crates/adapters/src/ebpf/kernel_probe.rs, or the first entry is not it;
- a release between the floor and the newest entry is missing or listed twice,
  or the entries are out of order (6.19 is followed by 7.0, any other release
  by the next minor);
- the floor, the newest stable or a `longterm = true` entry is not `full`, a
  tier is unknown, or a `preview` entry is anything but the last one and above
  the newest stable;
- a capability's `since` in capabilities.json names no listed release.

With --online it also asks kernel.org and kernel.ubuntu.com, and fails when:

- the latest stable release, or a longterm release at or above the floor, is
  not listed, or a listed release kernel.org calls longterm lacks the flag;
- kernel.org's mainline release is a candidate of a release the list neither
  has as stable nor as preview;
- a listed release resolves to no build (printed with what each resolves to).

Other modes serve the runners:
  --list <tier>[,<tier>...]   releases of those tiers, one per line
  --tier <release>            the tier of one listed release
  --resolve <release>         the build a run boots: the newest point release
                              kernel.ubuntu.com/mainline built for amd64 (image
                              and modules), else, for a release still under
                              development, its newest candidate, as the
                              directory name without its `v` (6.18.5, 6.19,
                              7.4-rc4)

Prints the summary line; problems go to stderr and exit 1.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

INTEG = Path(__file__).resolve().parent.parent
ROOT = INTEG.parent.parent
MATRIX = INTEG / "kernels.toml"
PROBE = ROOT / "crates/adapters/src/ebpf/kernel_probe.rs"
CATALOGUE = ROOT / "capabilities.json"
TIERS = ("full", "load", "preview")
RELEASE = re.compile(r"^(\d+)\.(\d+)$")
UPSTREAM = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+)|-rc(\d+))?$")
UBUNTU = "https://kernel.ubuntu.com/mainline"
BANNER = "https://www.kernel.org/finger_banner"


def release(version: str) -> tuple[int, int]:
    m = RELEASE.match(version)
    if not m:
        raise ValueError(f"{version!r} is not major.minor")
    return int(m.group(1)), int(m.group(2))


def upstream_release(version: str) -> tuple[int, int]:
    m = UPSTREAM.match(version)
    if not m:
        raise ValueError(f"{version!r} is not a kernel version")
    return int(m.group(1)), int(m.group(2))


def follows(prev: tuple[int, int], nxt: tuple[int, int]) -> bool:
    return nxt == (prev[0], prev[1] + 1) or nxt == (prev[0] + 1, 0)


def load() -> tuple[str, list[dict]]:
    data = tomllib.loads(MATRIX.read_text())
    return data["floor"], data.get("kernel", [])


def probe_floor() -> str:
    text = PROBE.read_text()
    major = re.search(r"MIN_KERNEL_MAJOR:\s*u32\s*=\s*(\d+)", text)
    minor = re.search(r"MIN_KERNEL_MINOR:\s*u32\s*=\s*(\d+)", text)
    if not major or not minor:
        raise SystemExit(f"no MIN_KERNEL_MAJOR / MIN_KERNEL_MINOR in {PROBE}")
    return f"{major.group(1)}.{minor.group(1)}"


def offline(floor: str, kernels: list[dict]) -> list[str]:
    problems: list[str] = []
    agent_floor = probe_floor()
    if floor != agent_floor:
        problems.append(f"floor {floor} differs from the agent's {agent_floor} ({PROBE.name})")
    if not kernels:
        return problems + ["no [[kernel]] entry"]

    malformed: list[str] = []
    for k in kernels:
        if k.get("tier") not in TIERS:
            malformed.append(f"{k.get('version')}: tier {k.get('tier')!r} is not one of {TIERS}")
        try:
            release(k["version"])
        except (KeyError, ValueError) as err:
            malformed.append(f"entry {k}: {err}")
    if malformed:
        return problems + malformed

    stable = [k for k in kernels if k["tier"] != "preview"]
    previews = [k for k in kernels if k["tier"] == "preview"]
    if len(previews) > 1:
        problems.append("more than one preview entry")
    for k in previews:
        if k is not kernels[-1]:
            problems.append(f"{k['version']}: a preview entry is the last one")

    if not stable:
        return problems + ["no stable entry"]
    first = release(stable[0]["version"])
    if f"{first[0]}.{first[1]}" != floor:
        problems.append(f"first entry {stable[0]['version']} is not the floor {floor}")
    for prev, nxt in zip(stable, stable[1:]):
        a, b = release(prev["version"]), release(nxt["version"])
        if not follows(a, b):
            problems.append(f"{nxt['version']} follows {prev['version']}: a release is missing, doubled or out of order")
    if previews and stable and not release(previews[0]["version"]) > release(stable[-1]["version"]):
        problems.append(f"{previews[0]['version']} is not above the newest stable {stable[-1]['version']}")

    must_be_full = {stable[0]["version"]: "the floor", stable[-1]["version"]: "the newest stable"}
    for k in stable:
        if k.get("longterm"):
            must_be_full.setdefault(k["version"], "longterm")
    for version, what in must_be_full.items():
        tier = next(k["tier"] for k in kernels if k["version"] == version)
        if tier != "full":
            problems.append(f"{version} is {what} and is tier {tier}, not full")

    listed = {release(k["version"]) for k in stable}
    catalogue = json.loads(CATALOGUE.read_text())
    for cap in catalogue["capabilities"]:
        since = tuple(int(x) for x in cap["since"].split("."))
        if since not in listed:
            problems.append(f"capability {cap['id']} since {cap['since']} names no listed release")
    return problems


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "kernel-matrix-check"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def resolve(rel: str) -> str | None:
    """The newest build of a release with an amd64 image and modules."""
    major, minor = release(rel)
    index = fetch(f"{UBUNTU}/")
    dirs = set(re.findall(r'href="v(\d+\.\d+(?:\.\d+|-rc\d+)?)/"', index))
    points, candidates = [], []
    for d in dirs:
        m = UPSTREAM.match(d)
        if not m or (int(m.group(1)), int(m.group(2))) != (major, minor):
            continue
        if m.group(4):
            candidates.append((int(m.group(4)), d))
        else:
            points.append((int(m.group(3) or 0), d))
    for _, d in sorted(points, reverse=True) + sorted(candidates, reverse=True):
        try:
            listing = fetch(f"{UBUNTU}/v{d}/amd64/")
        except OSError:
            continue
        image = re.search(r"linux-image-unsigned-[^\"]*-generic_[^\"]*_amd64\.deb", listing)
        modules = re.search(r"linux-modules-[^\"]*-generic_[^\"]*_amd64\.deb", listing)
        if image and modules:
            return d
    return None


def online(kernels: list[dict]) -> list[str]:
    problems: list[str] = []
    banner = fetch(BANNER)
    latest = re.search(r"latest stable version of the Linux kernel is:\s+(\S+)", banner)
    mainline = re.search(r"latest mainline version of the Linux kernel is:\s+(\S+)", banner)
    longterms = re.findall(r"latest longterm \S+ version of the Linux kernel is:\s+(\S+)", banner)
    by_release = {release(k["version"]): k for k in kernels if k["tier"] != "preview"}
    previews = {release(k["version"]) for k in kernels if k["tier"] == "preview"}
    floor = min(by_release)

    targets: list[tuple[str, bool]] = []
    if latest:
        targets.append((latest.group(1), False))
    else:
        problems.append(f"{BANNER} names no latest stable release")
    targets += [(v, True) for v in longterms]
    for upstream, longterm in targets:
        rel = upstream_release(upstream)
        if rel < floor:
            continue
        entry = by_release.get(rel)
        if entry is None:
            problems.append(f"{upstream} ({'longterm' if longterm else 'latest stable'}) is published and {rel[0]}.{rel[1]} is not listed")
            continue
        if longterm and not entry.get("longterm"):
            problems.append(f"{entry['version']}: kernel.org lists {rel[0]}.{rel[1]} as longterm, the entry lacks longterm = true")
    if mainline and "-rc" in mainline.group(1):
        rel = upstream_release(mainline.group(1))
        if rel not in by_release and rel not in previews:
            problems.append(f"{mainline.group(1)} is the mainline candidate and {rel[0]}.{rel[1]} is listed neither as stable nor as preview")

    for k in kernels:
        try:
            build = resolve(k["version"])
        except OSError as err:
            problems.append(f"{k['version']}: {UBUNTU} unreadable ({err})")
            continue
        if build is None:
            problems.append(f"{k['version']}: kernel.ubuntu.com has no amd64 image and modules for any build of it")
        else:
            print(f"{k['version']} -> {build}")
    return problems


def main(argv: list[str]) -> int:
    floor, kernels = load()
    if len(argv) == 2 and argv[0] == "--list":
        wanted = set(argv[1].split(","))
        unknown = wanted - set(TIERS)
        if unknown:
            print(f"unknown tier {sorted(unknown)}", file=sys.stderr)
            return 2
        for k in kernels:
            if k["tier"] in wanted:
                print(k["version"])
        return 0
    if len(argv) == 2 and argv[0] == "--tier":
        for k in kernels:
            if k["version"] == argv[1]:
                print(k["tier"])
                return 0
        print(f"{argv[1]} is not in {MATRIX.name}", file=sys.stderr)
        return 1
    if len(argv) == 2 and argv[0] == "--resolve":
        if not any(k["version"] == argv[1] for k in kernels):
            print(f"{argv[1]} is not in {MATRIX.name}", file=sys.stderr)
            return 1
        build = resolve(argv[1])
        if build is None:
            print(f"{argv[1]}: kernel.ubuntu.com has no amd64 build of it", file=sys.stderr)
            return 1
        print(build)
        return 0
    if argv not in ([], ["--online"]):
        print(__doc__, file=sys.stderr)
        return 2

    problems = offline(floor, kernels)
    if not problems and argv == ["--online"]:
        problems = online(kernels)
    for p in problems:
        print(p, file=sys.stderr)
    tiers = {t: sum(1 for k in kernels if k["tier"] == t) for t in TIERS}
    print(
        f"kernel matrix: floor {floor}, {len(kernels)} kernels "
        f"({tiers['full']} full, {tiers['load']} load, {tiers['preview']} preview), "
        f"{len(problems)} problems{' (online)' if argv == ['--online'] else ''}"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
