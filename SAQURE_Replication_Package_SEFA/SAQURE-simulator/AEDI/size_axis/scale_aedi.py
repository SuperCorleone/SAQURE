#!/usr/bin/env python3
"""Scale an AEDI attack-goal problem to a managed system of N stacked SEFA replicas.

Shared objects (attacker, user, comchannel, ...) stay single; every object whose name
mentions SEFA is replicated per replica, together with every init fact that mentions one.
The goal stays on replica 1, so the attack target is fixed while the environment grows.

Two modes, matching the two quantities reported for RQ4(2)(ii) and RQ4(3)(ii):

  joint  one problem describing all N replicas at once. This is NOT how SAQURE assesses
         risk; it is generated only to quantify the grounding blow-up such a model incurs.
  split  N problems, each describing a single replica in isolation. This mirrors how EADSA
         actually works (one Metric-FF run per service), so the risk assessment time of the
         whole managed system is the sum over the N problems.

Usage:
  python3 scale_aedi.py --src <AEDI.pddl> --out <dir> --n <N> --mode {joint,split}
"""
import re, sys

TOKEN = re.compile(r"[A-Za-z0-9_\-\.]+")
DECL = re.compile(r"^(.*?)\s-\s*([A-Za-z0-9_\-]+)\s*$")

def load(path):
    lines = open(path).read().split("\n")
    oi = next(i for i, l in enumerate(lines) if "(:objects" in l)
    ii = next(i for i, l in enumerate(lines) if "(:init" in l)
    gi = next(i for i, l in enumerate(lines) if "(:goal" in l)
    return lines[:oi + 1], lines[oi + 1:ii], lines[ii:ii + 1] + lines[ii + 1:gi], lines[gi:]

def obj_names(decl_lines):
    names, decls = set(), []
    for l in decl_lines:
        body = l.split(";")[0]
        # PDDL lexes '-' as its own token, so declarations appear both as "x - t" and "x -t".
        m = DECL.match(body)
        if not m:
            continue
        ns = TOKEN.findall(m.group(1))
        names.update(ns)
        decls.append((l, ns))
    return names, decls


def facts(lines):
    """Yield one balanced init fact per item, skipping blanks, comments and stray parens."""
    buf = ""
    for l in lines:
        s = l.split(";")[0].strip()
        if not s:
            continue
        buf = (buf + " " + s).strip() if buf else s
        if buf.count("(") == buf.count(")"):
            if TOKEN.findall(buf):
                yield buf
            buf = ""

def rename(text, mapping):
    return TOKEN.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)

def main(src, dst, n):
    head, objs, init, tail = load(src)
    names, decls = obj_names(objs)
    scoped = {x for x in names if "SEFA" in x}
    maps = [{x: f"{x}_r{k}" for x in scoped} for k in range(1, n + 1)]

    out = list(head)
    for l, ns in decls:
        if any(x in scoped for x in ns):
            for m in maps:
                out.append(rename(l, m))
        else:
            out.append(l)
    out.append("  )")
    out.append("  (:init")
    for s in facts(init[1:]):
        if any(x in scoped for x in TOKEN.findall(s)):
            for m in maps:
                out.append("    " + rename(s, m))
        else:
            out.append("    " + s)
    out.append("  )")
    out += [rename(l, maps[0]) for l in tail]
    open(dst, "w").write("\n".join(out) + "\n")
    print(f"{dst}: replicas={n} scoped_objects={len(scoped)} shared_objects={len(names)-len(scoped)} lines={len(out)}")

def cli():
    import argparse, os
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--src", required=True, help="source AEDI attack-goal problem")
    p.add_argument("--out", required=True, help="output directory")
    p.add_argument("--n", type=int, required=True, help="number of SEFA replicas")
    p.add_argument("--mode", choices=["joint", "split"], default="split")
    a = p.parse_args()
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.splitext(os.path.basename(a.src))[0]
    if a.mode == "joint":
        main(a.src, os.path.join(a.out, "%s_joint_N%d.pddl" % (stem, a.n)), a.n)
    else:
        for k in range(1, a.n + 1):
            main(a.src, os.path.join(a.out, "%s_r%d.pddl" % (stem, k)), 1)


if __name__ == "__main__":
    cli()
