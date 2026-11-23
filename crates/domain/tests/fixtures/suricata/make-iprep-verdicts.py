#!/usr/bin/env python3
"""Run iprep rules over UDP exchanges through a real Suricata.

The reputation lists are named by Suricata's configuration
(`reputation-categories-file` and `reputation-files`), as the agent's
configuration names them, over the files this script writes in iprep/
beside it: categories by number and short name, then addresses and
networks with a category and a score, with lines Suricata skips. Each
exchange is a query from 10.9.0.N and its answer from 10.10.0.N, and the
rules compare the source, the destination, either or both with a score, or
ask whether an address is listed at all; some are written to be refused.

Writes iprep/* and iprep-verdicts.txt beside this script, in the format of
applayer-verdicts.txt, after a 'categories FILE' and a 'reputation FILE'
line. The test needs neither this script nor docker. Needs docker.
"""

import os
import shutil
import tempfile
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 13000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

FILES = {
    "categories.txt": [
        "1,BadHosts,Known bad hosts",
        "2,Google,Known google hosts",
        "3,Unused,Nothing listed in it",
    ],
    "reputation.list": [
        "10.9.0.1,1,50",
        "10.10.0.1,1,40",
        "10.9.0.2,1,10",
        "10.10.0.3,2,90",
        "10.9.0.5,2,0",
        "10.9.0.6,9,40",
        "10.9.0.7,1,200",
        "not an address,1,40",
        "10.9.0.8/30,1,70",
        "10.9.0.9,2,20",
    ],
}

RULES = [
    "iprep:src,BadHosts,>,30;",
    "iprep:dst,BadHosts,>,30;",
    "iprep:any,BadHosts,>,30;",
    "iprep:both,BadHosts,>,30;",
    "iprep:src,BadHosts,<,20;",
    "iprep:src,BadHosts,=,10;",
    "iprep:src,Google,isset;",
    "iprep:dst,Google,isset;",
    "iprep:src,BadHosts,isnotset;",
    "iprep:any,Unused,isset;",
    "iprep:src,Google,=,0;",
    "iprep:src,Nobody,>,1;",
    "iprep:src,BadHosts,>,128;",
    "iprep:src,BadHosts,>=,1;",
    "iprep:src,BadHosts,<,201;",
    "iprep:src,BadHosts,>,60; iprep:src,Google,>,10;",
    "iprep:src,BadHosts,<=,10;",
    "iprep:src,BadHosts,!=,50;",
    "iprep:src,BadHosts,40-60;",
    "iprep:src,BadHosts,>,255;",
    "iprep:src,BadHosts,>,256;",
    "iprep:src,BadHosts,=,70;",
    "iprep:src,badhosts,>,1;",
    "iprep:sideways,BadHosts,>,1;",
]


def conversations():
    out = []
    for n in range(1, 11):
        applayer.udp_conversation(out, n, 5353 + 0, [(0.0, ">", b"ping"), (0.01, "<", b"pong")])
    return out


def main():
    data = os.path.join(HERE, "iprep")
    os.makedirs(data, exist_ok=True)
    for name, lines in FILES.items():
        with open(os.path.join(data, name), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    applayer.EXTRA_ARGS = [
        "--set", "reputation-categories-file=/w/categories.txt",
        "--set", "default-reputation-path=/w",
        "--set", "reputation-files.0=reputation.list",
    ]
    original = tempfile.TemporaryDirectory

    class Work:
        """The capture's working directory, holding the lists."""

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
    rules = [f'alert udp any any -> any any (msg:"iprep {FIRST_SID + n}"; {options})' for n, options in enumerate(RULES)]
    applayer.HERE = HERE
    applayer.verdicts("iprep", "make-iprep-verdicts.py", FIRST_SID, rules, conversations())
    path = os.path.join(HERE, "iprep-verdicts.txt")
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[1:1] = [
        "# The lists the configuration names, beside.",
        "categories 0 iprep/categories.txt",
        "reputation 0 iprep/reputation.list",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
