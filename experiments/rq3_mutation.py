"""RQ3: verifier effectiveness under injected translator faults, and T_ver scaling.

Usage: python experiments/rq3_mutation.py [n_cases] [seed]
Writes results/rq3_mutation.json and results/rq3_tver.json.
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

from corpus import C_R, make_corpus  # noqa: E402
from upt import Deny, compute_grant  # noqa: E402
from upt.grant import PROFILES  # noqa: E402
from upt.translate import Rule, Table, map_atom  # noqa: E402
from upt.verify import Flow, check_complete, check_rule_set, check_sound, eval_policy, eval_table  # noqa: E402

CLASSES = ["port", "prefix", "direction", "fail_open", "subject", "drop_atom", "shadowing"]
WIDENING = {"port", "prefix", "direction", "fail_open", "subject", "shadowing"}


def mutate(t: Table, cls: str, rng: random.Random, subj_addrs):
    rules = list(t.rules)
    if cls == "fail_open":
        return Table(t.domain, t.kind, t.width, rules, "acc")
    if cls == "shadowing":
        sh = Rule(5000, frozenset([rng.choice(subj_addrs)]), None, None, None, None, "acc")
        return Table(t.domain, t.kind, t.width, [sh] + rules, t.default)
    if cls == "drop_atom":
        if len(rules) < 2:
            return None
        rules.pop(rng.randrange(len(rules)))
        return Table(t.domain, t.kind, t.width, rules, t.default)
    i = rng.randrange(len(rules))
    r = rules[i]
    if cls == "port":
        if r.ports[0] == "range":
            if r.ports[2] == 65535:
                return None
            nr = replace(r, ports=("range", r.ports[1], r.ports[2] + 1))
        else:
            v, m = r.ports[1], r.ports[2]
            if m == 0:
                return None
            low = m & -m
            nr = replace(r, ports=("mask", v & (m ^ low), m ^ low))
    elif cls == "prefix":
        if r.dst.plen == 0:
            return None
        pl = r.dst.plen - 1
        mask = ((1 << r.dst.width) - 1) ^ ((1 << (r.dst.width - pl)) - 1)
        nr = replace(r, dst=replace(r.dst, net=r.dst.net & mask, plen=pl))
    elif cls == "direction":
        if r.dir is None:
            return None
        nr = replace(r, dir=None)
    elif cls == "subject":
        nr = replace(r, src=None)
    rules[i] = nr
    return Table(t.domain, t.kind, t.width, rules, t.default)


def sample_flows(policy, binding, version, width, rng, n=200):
    """Boundary-biased flows around every atom, plus random ones (ground truth sampler)."""
    subs = sorted({a for s in policy.subjects for a in binding.get(s, ())})
    others = [rng.getrandbits(width) for _ in range(2)]
    flows = []
    atoms = [map_atom(a, version) for a in policy.atoms]
    while len(flows) < n:
        a = rng.choice(atoms)
        size = 1 << (width - a.dst.plen)
        dst = rng.choice([a.dst.net, a.dst.net + size - 1, (a.dst.net - 1) % (1 << width),
                          (a.dst.net + size) % (1 << width), a.dst.net + rng.randrange(size)])
        port = rng.choice([a.lo, a.hi, max(0, a.lo - 1), min(65535, a.hi + 1), rng.randrange(65536)])
        proto = rng.choice([6, 17, 1])
        src = rng.choice(subs + others)
        flows.append(Flow(src, dst, proto, port, rng.random() < 0.5))
    return flows


def main(n_cases=400, seed=21):
    rng = random.Random(seed)
    cases = make_corpus(n_cases, 0.0, seed=seed)
    stats = {c: {"mutants": 0, "rejected": 0, "witness_confirmed": 0, "sampler_found": 0,
                 "flagged_incomplete": 0, "missed": 0} for c in CLASSES}
    tver = []
    for cs in cases:
        g = compute_grant(cs.subject, cs.T, cs.path, cs.policies, cs.bindings, t=10.0, c_r=C_R)
        if isinstance(g, Deny):
            continue
        for d, tab in g.tables.items():
            ver = PROFILES[d].version
            b = cs.bindings[d]
            from upt.core import local_veto
            pol = local_veto(g.policy, cs.policies[d])
            t0 = time.perf_counter()
            check_rule_set(tab, tab, pol, b, ver)
            tver.append((len(tab.rules), time.perf_counter() - t0))
            subj = sorted(b[cs.subject])
            flows = sample_flows(pol, b, ver, tab.width, rng)
            for cls in CLASSES:
                m = mutate(tab, cls, rng, subj)
                if m is None:
                    continue
                st = stats[cls]
                st["mutants"] += 1
                # shadowing models a pre-existing rule: the new rules are `tab`, the effective table is `m`
                r = check_rule_set(tab if cls == "shadowing" else m, m, pol, b, ver)
                if not r.ok:
                    st["rejected"] += 1
                    w = r.witness
                    if eval_table(m, w) and not eval_policy(pol, b, ver, w):
                        st["witness_confirmed"] += 1
                found = any(eval_table(m, f) and (cls != "shadowing" or f.src in subj)
                            and not eval_policy(pol, b, ver, f) for f in flows)
                if found:
                    st["sampler_found"] += 1
                    if r.ok:
                        st["missed"] += 1
                if cls == "drop_atom" and not check_complete(m, pol, b, ver).ok:
                    st["flagged_incomplete"] += 1
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "rq3_mutation.json").write_text(json.dumps({"n_cases": n_cases, "seed": seed, "classes": stats}, indent=1))
    (out / "rq3_tver_corpus.json").write_text(json.dumps(tver))
    for c, s in stats.items():
        print(c, s)
    ts = sorted(x[1] for x in tver)
    print("T_ver median %.2f ms p95 %.2f ms over %d checks" % (1e3 * statistics.median(ts),
                                                              1e3 * ts[int(0.95 * len(ts))], len(ts)))


if __name__ == "__main__":
    main(*(int(x) for x in sys.argv[1:]))
