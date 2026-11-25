#!/usr/bin/env python3
"""kfunc-externs.py <btf.json> <header>... -- <source>...

Print an extern declaration bound to `.ksyms` (what libbpf's `__ksym` spells)
for every kernel function a source names that none of the headers declares,
read off the kernel's BTF.

Why. bpftool writes kfunc prototypes into vmlinux.h only when the kernel's BTF
tags its kfuncs (pahole's `decl_tag_kfuncs`). A distribution kernel may carry
the functions without the tags: Ubuntu's 7.0 does. The selftest the bench
builds expects the prototypes in vmlinux.h, so build.sh appends these where
bpftool left them out.

<btf.json> is `bpftool -j btf dump file /sys/kernel/btf/vmlinux`.
"""
import json
import re
import sys


def main() -> int:
    args = sys.argv[1:]
    if "--" not in args or len(args) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    split = args.index("--")
    btf_path, headers, sources = args[0], args[1:split], args[split + 1 :]

    with open(btf_path, encoding="utf-8") as fh:
        types = {t["id"]: t for t in json.load(fh)["types"]}
    funcs = {t["name"]: t for t in types.values() if t["kind"] == "FUNC"}

    declared = set()
    for path in headers:
        with open(path, encoding="utf-8", errors="replace") as fh:
            # Any mention counts: bpf_helper_defs.h declares helpers as
            # function pointers, `(*bpf_map_lookup_elem)(...)`.
            declared.update(re.findall(r"\b(bpf_\w+)\b", fh.read()))

    named = set()
    for path in sources:
        with open(path, encoding="utf-8", errors="replace") as fh:
            named.update(re.findall(r"\b(bpf_\w+)\s*\(", fh.read()))

    def ctype(type_id: int, inner: str = "") -> str:
        if type_id == 0:
            return f"void{inner}"
        t = types[type_id]
        kind = t["kind"]
        if kind == "PTR":
            return ctype(t["type_id"], f" *{inner.lstrip()}")
        if kind in ("CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"):
            word = {"CONST": "const", "VOLATILE": "volatile", "RESTRICT": "restrict"}.get(kind)
            base = ctype(t["type_id"], "")
            return f"{word} {base}{inner}" if word else f"{base}{inner}"
        if kind in ("STRUCT", "UNION", "ENUM", "ENUM64", "FWD"):
            tag = {"STRUCT": "struct", "UNION": "union", "FWD": "struct"}.get(kind, "enum")
            if kind == "FWD" and t.get("fwd_kind") == "union":
                tag = "union"
            return f"{tag} {t['name']}{inner}"
        if kind in ("INT", "TYPEDEF", "FLOAT"):
            return f"{t['name']}{inner}"
        raise ValueError(f"type {type_id} of kind {kind} has no C spelling here")

    for name in sorted(named - declared):
        func = funcs.get(name)
        if func is None:
            continue
        proto = types[func["type_id"]]
        params = []
        for i, param in enumerate(proto.get("params", [])):
            if param["type_id"] == 0:
                params.append("...")
                continue
            params.append(ctype(param["type_id"], f" {param.get('name') or f'arg{i}'}"))
        ret = ctype(proto["ret_type_id"], f" {name}({', '.join(params) or 'void'})")
        print(f'extern {ret} __attribute__((section(".ksyms")));')
    return 0


if __name__ == "__main__":
    sys.exit(main())
