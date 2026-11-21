"""RQ2 (UPT-side part): grant computation cost vs. boundary size, and verification
cost vs. effective-table size. The enterprise DNOS recomputation is NOT included;
it is measured on the testbed (see testbed/README.md).

Usage: python experiments/rq2_cost.py
Writes results/rq2_atoms.json and results/rq2_table.json.
"""
import json
import random
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "experiments")]

from corpus import C_R, _atom, _widen, make_case  # noqa: E402
from upt import Deny, compute_grant  # noqa: E402
from upt.translate import Rule, Table, translate  # noqa: E402
from upt.verify import check_rule_set  # noqa: E402

REPS = 30


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def atoms_sweep():
    rng = random.Random(5)
    out = []
    for path in [("res", "ent"), ("mob", "ent", "res")]:
        for k in [1, 2, 5, 10, 20, 50]:
            rows = []
            while len(rows) < REPS:
                cs = make_case(len(rows), rng)
                if cs.kind != "ok":
                    continue
                base = rng.randrange(1, 200)
                src = [replace(_atom(rng, base), syscalls=None) for _ in range(k)]
                tgt = [_widen(a, rng) for a in src]
                path_pol = {}
                ref = list(cs.policies.values())
                for i, d in enumerate(path):
                    p = ref[min(i, len(ref) - 1)]
                    path_pol[d] = replace(p, atoms=tuple(src if i == 0 else tgt),
                                          suites=frozenset({"AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"}),
                                          qos=replace(p.qos, mtd_max=float("inf")) if d != "mob" else replace(p.qos, eta_hard=False),
                                          resp=0, iso=min(p.iso, 1), amin=1, theta=0.0)
                from upt.iils import TrustContext
                T = TrustContext({"res": 1, "ent": 2, "mob": 3}[path[0]], 47, 3, 0, path[0])
                for verify in (False, True):
                    g = compute_grant(cs.subject, T, path, path_pol, cs.bindings, 10.0, C_R, verify=verify)
                    if isinstance(g, Deny):
                        break
                    if verify:
                        rows.append({**g.timings, "rules": sum(len(t.rules) for t in g.tables.values())})
                    else:
                        nov = g.timings["total"]
                else:
                    rows[-1]["total_noverify"] = nov
            agg = {"path": "-".join(path), "atoms": k}
            for key in ["admission", "compose", "place", "translate", "verify", "total", "total_noverify", "rules"]:
                vals = [r[key] for r in rows]
                agg[key] = {"median": statistics.median(vals), "p95": pct(vals, 0.95), "mean": statistics.mean(vals)}
            out.append(agg)
            print(agg["path"], k, "total med %.2f ms p95 %.2f ms; no-verify %.2f ms; rules %d" % (
                1e3 * agg["total"]["median"], 1e3 * agg["total"]["p95"], 1e3 * agg["total_noverify"]["median"],
                agg["rules"]["median"]))
    return out


def table_sweep():
    """Existing rules either belong to other subjects (filtered out before the
    SMT query) or have wildcard sources (relevant to every subject)."""
    rng = random.Random(9)
    out = []
    cs_list = []
    while len(cs_list) < REPS:
        cs = make_case(1000 + len(cs_list), rng)
        if cs.kind == "ok" and "ent" in cs.path:
            cs_list.append(cs)
    for kind in ["other-subject", "wildcard-source"]:
        for n in [0, 100, 300, 1000, 3000, 10000]:
            if kind == "wildcard-source" and n > 3000:
                continue
            times = []
            for cs in cs_list:
                pol = cs.policies["ent"]
                b = cs.bindings["ent"]
                new = translate("ent", pol, b)
                other = []
                for j in range(n):
                    a = _atom(rng, rng.randrange(1, 250))
                    if kind == "other-subject":
                        other.append(Rule(1000, frozenset([(100 << 24) | (65 << 16) | j]), a.dst, a.protos,
                                          ("range", a.lo, a.hi), None, "acc"))
                    else:  # wildcard-source deny rules (e.g., infrastructure blocks) at lower priority
                        other.append(Rule(500, None, a.dst, a.protos, ("range", a.lo, a.hi), None, "drop"))
                eff = Table("ent", "prio", 32, other + list(new.rules))
                t0 = time.perf_counter()
                r = check_rule_set(new, eff, pol, b, 4)
                times.append(time.perf_counter() - t0)
                assert r.ok
            out.append({"kind": kind, "existing_rules": n, "median": statistics.median(times), "p95": pct(times, 0.95)})
            print(kind, n, "T_ver med %.1f ms p95 %.1f ms" % (1e3 * out[-1]["median"], 1e3 * out[-1]["p95"]))
    return out


if __name__ == "__main__":
    res = ROOT / "results"
    res.mkdir(exist_ok=True)
    if "--table-only" not in sys.argv:
        (res / "rq2_atoms.json").write_text(json.dumps(atoms_sweep(), indent=1))
    (res / "rq2_table.json").write_text(json.dumps(table_sweep(), indent=1))
