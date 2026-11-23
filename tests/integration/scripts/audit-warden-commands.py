"""Every command the warden answers, against the policy that fences it and a
test that sends it.

The warden is the privileged half of the rootless split: what it answers is
what a compromised agent could ask of the host. This gate reads every variant
of `Command` in `crates/warden-proto/src/lib.rs` and asks two questions of
each:

- fence: does `Command::family` give it a family, and does
  `WardenPolicy::check` in `crates/warden/src/policy.rs` name it? A command in
  a family that `check` does not name falls through to its catch-all and is
  answered whatever the policy says. A command in no family carries a
  `reason` under `[unfenced]` in `tests/integration/warden-commands.toml`, so
  a new command is in a family or is argued to be in none;
- tested: does a test of the warden (the unit tests of its modules, its
  integration tests under `crates/warden/tests`) name `Command::<Variant>`?
  A command no test names carries a `gap` under `[untested]`.

Every line carries exactly one of `reason` or `gap`; a line for a command
the scan already settles, or that no longer exists, is stale. The number of
`gap` lines equals `gap_ceiling`.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROTO = ROOT / "crates/warden-proto/src/lib.rs"
POLICY = ROOT / "crates/warden/src/policy.rs"
WARDEN = ROOT / "crates/warden"
MANIFEST = ROOT / "tests/integration/warden-commands.toml"
GATE = "ebpfsentinel/warden-commands"
FLOOR = 40
RANK = ["scan", "reason", "gap"]


def fail(problems: list[str]) -> None:
    for p in problems:
        print(p, file=sys.stderr)
    sys.exit(1)


def block(text: str, start: str) -> str:
    """The text from `start` to the brace closing it."""
    i = text.index(start)
    depth = 0
    for j in range(text.index("{", i), len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    raise ValueError(f"unclosed {start}")


def without_comments(text: str) -> str:
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


def commands(proto: str) -> list[str]:
    body = block(proto, "pub enum Command {")
    return re.findall(r"^    ([A-Z]\w*)\s*[{,(]", without_comments(body), re.M)


def families(proto: str) -> set[str]:
    """Commands `Command::family` puts in a family."""
    body = without_comments(block(proto, "pub fn family(&self) -> Option<Family>"))
    fenced: set[str] = set()
    # Each arm is `Self::A { .. } | Self::B => Some(Family::X)` or `=> None`.
    for arm in re.finditer(r"((?:\|?\s*Self::\w+(?:\s*\{[^}]*\})?\s*)+)=>\s*(Some|None)", body):
        if arm.group(2) == "Some":
            fenced.update(re.findall(r"Self::(\w+)", arm.group(1)))
    return fenced


def checked(policy: str) -> set[str]:
    """Commands `WardenPolicy::check` names in an arm of its own."""
    body = without_comments(block(policy, "pub fn check(&self, cmd: &Command)"))
    return set(re.findall(r"Command::(\w+)", body))


def tested() -> set[str]:
    named: set[str] = set()
    for path in sorted((WARDEN / "src").rglob("*.rs")):
        text = path.read_text()
        cut = text.find("#[cfg(test)]")
        if cut >= 0:
            named.update(re.findall(r"Command::(\w+)", without_comments(text[cut:])))
    for path in sorted((WARDEN / "tests").rglob("*.rs")):
        named.update(re.findall(r"Command::(\w+)", without_comments(path.read_text())))
    return named


def main() -> None:
    proto = PROTO.read_text()
    inventory = commands(proto)
    problems: list[str] = []
    if len(inventory) < FLOOR:
        fail([f"{GATE}: read {len(inventory)} commands, under the floor of {FLOOR}: the scanner no longer matches the enum"])

    in_family = families(proto)
    in_check = checked(POLICY.read_text())
    sent = tested()
    manifest = tomllib.loads(MANIFEST.read_text())
    unfenced = manifest.get("unfenced", {})
    untested = manifest.get("untested", {})
    ceiling = manifest.get("gap_ceiling")
    if not isinstance(ceiling, int):
        problems.append(f"{MANIFEST.name}: gap_ceiling is missing")

    known = set(inventory)
    gaps = 0
    reasons: dict[str, str] = {}
    for table, lines in (("unfenced", unfenced), ("untested", untested)):
        for name, line in lines.items():
            keys = {"reason", "gap"} & set(line)
            if len(keys) != 1 or set(line) - {"reason", "gap"}:
                problems.append(f"[{table}.{name}] carries exactly one of reason or gap")
                continue
            if name not in known:
                problems.append(f"[{table}.{name}] names no command: stale line")
            if "gap" in line:
                gaps += 1
            else:
                reasons[f"{table}.{name}"] = line["reason"]

    by_scan = by_reason = by_gap = 0
    for name in inventory:
        worst = "scan"
        if name in in_family:
            if name not in in_check:
                problems.append(
                    f"{name} is in a family but WardenPolicy::check does not name it: the policy never refuses it"
                )
            if name in unfenced:
                problems.append(f"[unfenced.{name}] is in a family: stale line")
        elif name not in unfenced:
            problems.append(f"{name} is in no family and carries no [unfenced.{name}] reason")
        else:
            worst = "gap" if "gap" in unfenced[name] else "reason"
        if name in sent:
            if name in untested:
                problems.append(f"[untested.{name}] is sent by a warden test: stale line")
        elif name not in untested:
            problems.append(f"{name} is sent by no warden test and carries no [untested.{name}] line")
        else:
            found = "gap" if "gap" in untested[name] else "reason"
            worst = max(worst, found, key=RANK.index)
        if worst == "scan":
            by_scan += 1
        elif worst == "reason":
            by_reason += 1
        else:
            by_gap += 1

    if isinstance(ceiling, int) and gaps != ceiling:
        problems.append(f"{gaps} gap lines against a gap_ceiling of {ceiling}: the ceiling equals the count")
    if problems:
        fail(problems)
    for key, reason in sorted(reasons.items()):
        print(f"{key}: {reason}")
    print(
        f"{GATE}: {len(inventory)} surfaces, {by_scan} by scan, 0 by suite, "
        f"{by_reason} by reason, {by_gap} gaps (ceiling {ceiling})"
    )


if __name__ == "__main__":
    main()
