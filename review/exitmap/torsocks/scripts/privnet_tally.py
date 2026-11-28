"""Tally connection outcomes by connection number over privnet.py runs.
A result other than FAIL counts as fetched (the 'ident' runs wrote a
WRONG-EXIT marker from a check that cannot work on loopback; those fetches
succeeded).  usage: privnet_tally.py <label> <run dir> [<run dir> ...]"""
import collections
import os
import sys

label, runs = sys.argv[1], sys.argv[2:]
per_n = collections.defaultdict(collections.Counter)
probes = 0
for run in runs:
    with open(os.path.join(run, "results.txt")) as f:
        rows = [line.split() for line in f]
    probes += len(set(r[0] for r in rows))
    for r in rows:
        n = int(r[1])
        if n == 1 and "dnsfail" in run:
            continue  # first URL deliberately unresolvable
        per_n[n]["FAIL" if r[2].startswith("FAIL") else "ok"] += 1
print("%s: %d runs, %d probes" % (label, len(runs), probes))
odd = sum(c["FAIL"] for n, c in per_n.items() if n % 2)
even4 = [c for n, c in per_n.items() if n % 2 == 0 and n >= 4]
print("  connection 2: %d of %d failed" % (per_n[2]["FAIL"], sum(per_n[2].values())))
print("  even connections 4..30: %d of %d failed" % (
    sum(c["FAIL"] for c in even4), sum(sum(c.values()) for c in even4)))
print("  odd connections (3..29; 1 except dnsfail): %d of %d failed" % (
    odd, sum(sum(c.values()) for n, c in per_n.items() if n % 2)))
