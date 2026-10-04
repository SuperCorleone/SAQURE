#!/usr/bin/env python3
"""Summarise run_rq412_bench.sh logs.

    python3 server_rq412/summarize.py <run_dir>                # one machine
    python3 server_rq412/summarize.py <mac_run_dir> <server_run_dir>   # side by side

Medians over the repeats; decision = risk assessment + Planner (the paper's decision time).
"""
import os
import re
import statistics
import sys

DECISION = re.compile(r'Runtime decision time:\s*([\d.]+)ms')
SPLIT = re.compile(r'Risk assessment:\s*\d+ implementations,\s*([\d.]+)ms; Planner:\s*([\d.]+)ms')


def parse_log(path):
    with open(path, errors='replace') as f:
        text = f.read()
    d = DECISION.findall(text)
    s = SPLIT.findall(text)
    if not d:
        return None
    return {
        'decision': float(d[-1]),
        'risk': float(s[-1][0]) if s else None,
        'planner': float(s[-1][1]) if s else None,
    }


def collect(folder):
    rows = []
    if os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            if name.endswith('.log'):
                r = parse_log(os.path.join(folder, name))
                if r:
                    rows.append(r)
    return rows


def med(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    return statistics.median(vals) if vals else None


def fmt(v):
    return '-' if v is None else f'{v:,.0f}'


def scales(run_dir):
    a = os.path.join(run_dir, 'A')
    if not os.path.isdir(a):
        return []
    return sorted((d for d in os.listdir(a) if d.startswith('S')), key=lambda s: int(s[1:]))


def threads(run_dir):
    b = os.path.join(run_dir, 'B')
    if not os.path.isdir(b):
        return []
    return sorted((d for d in os.listdir(b) if d.startswith('T')), key=lambda s: int(s[1:]))


def part_a(run_dir):
    out = {}
    for s in scales(run_dir):
        for approach in ('SAQURE', 'AQUA'):
            rows = collect(os.path.join(run_dir, 'A', s, approach))
            out[(s, approach)] = {k: med(rows, k) for k in ('decision', 'risk', 'planner')} | {'n': len(rows)}
    return out


def part_b(run_dir):
    out = {}
    for t in threads(run_dir):
        rows = collect(os.path.join(run_dir, 'B', t))
        out[t] = {k: med(rows, k) for k in ('decision', 'risk', 'planner')} | {'n': len(rows)}
    return out


def header(run_dir):
    m = os.path.join(run_dir, 'machine.txt')
    if os.path.exists(m):
        with open(m) as f:
            lines = f.read().splitlines()
        keep = [l for l in lines if l.startswith(('host:', 'logical CPUs', 'Model name', 'cgroup')) or 'Apple' in l or 'Intel' in l]
        return ' | '.join(keep[:4])
    return run_dir


def single(run_dir):
    print(f'### {run_dir}\n{header(run_dir)}\n')
    a = part_a(run_dir)
    if a:
        print('Part A  RQ4.1.2 (median ms; default thread pool)')
        print(f'{"CVEs":>5} | {"SAQURE decision":>15} {"risk":>7} {"planner":>8} | {"AQUA decision":>13} {"planner":>8} | n')
        for s in scales(run_dir):
            sq, aq = a[(s, 'SAQURE')], a[(s, 'AQUA')]
            print(f'{s[1:]:>5} | {fmt(sq["decision"]):>15} {fmt(sq["risk"]):>7} {fmt(sq["planner"]):>8} | '
                  f'{fmt(aq["decision"]):>13} {fmt(aq["planner"]):>8} | {sq["n"]}/{aq["n"]}')
        ss = scales(run_dir)
        if len(ss) >= 2:
            lo, hi = a[(ss[0], 'SAQURE')]['decision'], a[(ss[-1], 'SAQURE')]['decision']
            if lo and hi:
                print(f'SAQURE growth {ss[0][1:]}->{ss[-1][1:]} CVEs: {fmt(lo)} -> {fmt(hi)} ms (+{(hi / lo - 1) * 100:.0f}%)')
        print()
    b = part_b(run_dir)
    if b:
        print('Part B  thread sweep (median ms)')
        base = b[threads(run_dir)[0]]['risk']
        print(f'{"threads":>7} | {"risk":>7} {"speedup":>7} | {"planner":>7} | {"decision":>8} | n')
        for t in threads(run_dir):
            r = b[t]
            sp = f'{base / r["risk"]:.2f}x' if base and r['risk'] else '-'
            print(f'{t[1:]:>7} | {fmt(r["risk"]):>7} {sp:>7} | {fmt(r["planner"]):>7} | {fmt(r["decision"]):>8} | {r["n"]}')
        print()


def compare(d1, d2):
    single(d1)
    single(d2)
    a1, a2 = part_a(d1), part_a(d2)
    common = [s for s in scales(d1) if s in scales(d2)]
    if common:
        print(f'### Comparison  (ratio = {os.path.basename(d1)} / {os.path.basename(d2)}; >1 means the second is faster)')
        print(f'{"CVEs":>5} | {"SAQURE dec":>10} {"ratio":>6} | {"risk":>6} {"ratio":>6} | {"planner":>7} {"ratio":>6} | {"AQUA dec":>8} {"ratio":>6}')
        for s in common:
            x, y = a1[(s, 'SAQURE')], a2[(s, 'SAQURE')]
            p, q = a1[(s, 'AQUA')], a2[(s, 'AQUA')]

            def r(u, v):
                return f'{u / v:.2f}' if u and v else '-'
            print(f'{s[1:]:>5} | {fmt(y["decision"]):>10} {r(x["decision"], y["decision"]):>6} | '
                  f'{fmt(y["risk"]):>6} {r(x["risk"], y["risk"]):>6} | {fmt(y["planner"]):>7} {r(x["planner"], y["planner"]):>6} | '
                  f'{fmt(q["decision"]):>8} {r(p["decision"], q["decision"]):>6}')
        print('(values shown are the second machine; ratios are first/second)')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        single(sys.argv[1])
    elif len(sys.argv) == 3:
        compare(sys.argv[1], sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
