#!/usr/bin/env python3
"""Run dataset and datarep rules over DNS queries through a real Suricata.

The sets are named by Suricata's configuration (`datasets.NAME.type` and
`datasets.NAME.load`), as the agent's configuration names them, over the
files this script writes in datasets/ beside it: base64 strings, hex
digests and addresses, with lines Suricata skips, a reputation per value,
and a file mixing values with and without one. The rules look the query
name up, as it is or through `to_md5` and `to_sha256`, test, add and remove
values, compare reputations, and some are written to be refused.

Writes datasets/*.lst and dataset-verdicts.txt beside this script, in the
format of applayer-verdicts.txt, after a 'set NAME TYPE FILE' line per
configured set. The test needs neither this script nor docker. Needs docker.
"""

import base64
import hashlib
import os
import shutil
import tempfile
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 12000

spec = util.spec_from_file_location("dns", os.path.join(HERE, "make-dns-verdicts.py"))
dns = util.module_from_spec(spec)
spec.loader.exec_module(dns)
applayer = dns.applayer


def b64(text, pad=True):
    out = base64.b64encode(text.encode()).decode()
    return out if pad else out.rstrip("=")


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


FILES = {
    "names.lst": [
        "# a comment is not base64 and is skipped",
        b64("example.com"),
        "",
        b64("evil.test"),
        b64("Mixed.Case"),
        "not base64!",
        b64("unpadded.x", pad=False),
    ],
    "reputation.lst": [
        b64("example.com") + ",5",
        b64("evil.test") + ",20",
        b64("bad.score") + ",x",
    ],
    "late-mix.lst": [
        "not base64,3",
        b64("example.com"),
    ],
    "mixed.lst": [
        b64("example.com") + ",5",
        b64("evil.test"),
        b64("after.mix") + ",9",
    ],
    "md5.lst": [md5("example.com"), "", md5("EVIL.TEST"), "zz"],
    "sha256.lst": [sha256("example.com")],
}

# name, type, file
SETS = [
    ("names", "string", "names.lst"),
    ("unsets", "string", "names.lst"),
    ("reps", "string", "reputation.lst"),
    ("plain", "string", "names.lst"),
    ("mixed", "string", "mixed.lst"),
    ("latemix", "string", "late-mix.lst"),
    ("md5s", "md5", "md5.lst"),
    ("shas", "sha256", "sha256.lst"),
]

RULES = [
    'dns.query; dataset:isset,names;',
    'dns.query; dataset:isnotset,names;',
    'dns.query; dataset:isset,names, type string;',
    'dns.query; dataset:isset,names, type md5;',
    'dns.query; dataset:isset,nobody;',
    'dns.query; dataset:isset,later, type string;',
    'dns.query; content:"example"; dataset:set,later;',
    'dns.query; dataset:isset,later;',
    'dns.query; dataset:unset,unsets;',
    'dns.query; dataset:isset,unsets;',
    'dns.query; datarep:reps, >, 10;',
    'dns.query; datarep:reps, <, 10;',
    'dns.query; datarep:reps, ==, 5;',
    'dns.query; datarep:reps, =, 20;',
    'dns.query; datarep:reps, >=, 5;',
    'dns.query; datarep:reps, <=, 5;',
    'dns.query; datarep:reps, !=, 5;',
    'dns.query; datarep:plain, ==, 0;',
    'dns.query; dataset:isset,reps;',
    'dns.query; datarep:mixed, ==, 5;',
    'dns.query; dataset:isset,mixed;',
    'dns.query; to_md5; dataset:isset,md5s;',
    'dns.query; dataset:isset,md5s;',
    'dns.query; to_sha256; dataset:isset,shas;',
    'dns.query; dataset:isset,names, memcap 10mb, hashsize 1024;',
    'dns.query; content:"evil"; dataset:set,fresh, type sha256;',
    'dns.query; to_sha256; dataset:set,fresh2, type sha256;',
    'dns.query; to_sha256; dataset:isset,fresh2;',
    'dataset:isset,names;',
    'dns.query; dataset:isset,latemix;',
    'dns.query; dataset:isset,names, type string, load names.lst;',
]

NAMES = [
    "example.com", "evil.test", "Mixed.Case", "unpadded.x", "other.org",
    "example.com", "EVIL.TEST", "after.mix", "bad.score", "mixed.case",
]


def conversations():
    out = []
    for n, text in enumerate(NAMES, start=1):
        q = dns.name(*text.encode().split(b"."))
        applayer.udp_conversation(out, n, 53, [(0.0, ">", dns.query(q)), (0.01, "<", dns.answer(q))])
    return out


def main():
    data = os.path.join(HERE, "datasets")
    os.makedirs(data, exist_ok=True)
    for name, lines in FILES.items():
        with open(os.path.join(data, name), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    settings = []
    for name, kind, path in SETS:
        settings += ["--set", f"datasets.{name}.type={kind}", "--set", f"datasets.{name}.load=/w/{path}"]
    applayer.EXTRA_ARGS = settings
    original = tempfile.TemporaryDirectory

    class Work:
        """The capture's working directory, holding the set files."""

        def __init__(self):
            self.inner = original()

        def __enter__(self):
            work = self.inner.__enter__()
            for name in FILES:
                shutil.copy(os.path.join(data, name), work)
            return work

        def __exit__(self, *exc):
            return self.inner.__exit__(*exc)

    applayer.tempfile.TemporaryDirectory = Work
    rules = [f'alert dns any any -> any any (msg:"dataset {FIRST_SID + n}"; {options})' for n, options in enumerate(RULES)]
    applayer.HERE = HERE
    applayer.verdicts("dataset", "make-dataset-verdicts.py", FIRST_SID, rules, conversations())
    path = os.path.join(HERE, "dataset-verdicts.txt")
    lines = open(path, encoding="utf-8").read().splitlines()
    sets = [f"set {name} {kind} datasets/{file}" for name, kind, file in SETS]
    lines[1:1] = ["# 'set NAME TYPE FILE': a set the configuration names, its file beside."] + sets
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
