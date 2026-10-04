#!/usr/bin/env python3
"""Measure runtime risk assessment time against the size of the managed system.

The managed system is a stack of N SEFA replicas. Two quantities are reported, matching the
two readings of RQ4(2)(ii):

  split  EADSA as implemented: one Metric-FF run per replica per STRIDE category. The
         per-replica time is invariant in N; the whole-system time is the sum over replicas.
  joint  one Metric-FF run over a single problem describing all N replicas. Reported only as
         a contrast: the grounding cross-product makes it intractable well before 500x.

Usage:
  python3 measure_size_axis.py --domain <AED.pddl> --aedi-dir <dir> \
      --scales 1,2,4,8 --mode split --out results.csv
Run from the SAQURE-simulator directory (the Metric-FF binary is resolved relative to it).
"""
import argparse, csv, os, re, subprocess, sys, tempfile, time

STRIDE = ["spoofing", "tampering", "repudiation",
          "information_disclosure", "denial_of_service", "elevation_of_privilege"]
FF = "./Metric-FF/ff"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from scale_aedi import main as scale_one  # noqa: E402


def run_ff(domain, problem):
    t = time.perf_counter()
    out = subprocess.run([FF, "-o", domain, "-f", problem, "-s", "4", "-w", "1"],
                         capture_output=True, text=True).stdout
    dt = time.perf_counter() - t
    acts = re.search(r"and (\d+) actions", out)
    cost = re.search(r"plan cost: ([\d.]+)", out)
    return dt, int(acts.group(1)) if acts else None, float(cost.group(1)) if cost else None


def measure_split(domain, aedi_dir, n, work):
    """One isolated single-replica problem per replica, six STRIDE runs each."""
    per_cat_max, total = 0.0, 0.0
    for k in range(1, n + 1):
        cat_times = []
        for cat in STRIDE:
            prob = os.path.join(work, "%s_r%d.pddl" % (cat, k))
            scale_one(os.path.join(aedi_dir, cat + ".pddl"), prob, 1)
            dt, _, _ = run_ff(domain, prob)
            cat_times.append(dt)
            total += dt
        per_cat_max += max(cat_times)  # EADSA runs the six categories in parallel
    return dict(scale=n, mode="split", total_s=round(total, 3),
                per_replica_s=round(total / n, 3), parallel_s=round(per_cat_max, 3),
                actions=None, plan_cost=None)


def measure_joint(domain, aedi_dir, n, work):
    """A single problem holding all N replicas: the contrast case."""
    prob = os.path.join(work, "spoofing_joint_N%d.pddl" % n)
    scale_one(os.path.join(aedi_dir, "spoofing.pddl"), prob, n)
    dt, acts, cost = run_ff(domain, prob)
    return dict(scale=n, mode="joint", total_s=round(dt, 3), per_replica_s=None,
                parallel_s=None, actions=acts, plan_cost=cost)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--domain", required=True, help="AED domain produced by AED_process")
    p.add_argument("--aedi-dir", default="AEDI", help="directory holding the six STRIDE problems")
    p.add_argument("--scales", required=True, help="comma separated replica counts")
    p.add_argument("--mode", choices=["split", "joint"], default="split")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    rows = []
    with tempfile.TemporaryDirectory() as work:
        for n in [int(x) for x in a.scales.split(",")]:
            fn = measure_split if a.mode == "split" else measure_joint
            row = fn(a.domain, a.aedi_dir, n, work)
            rows.append(row)
            print(row, flush=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
