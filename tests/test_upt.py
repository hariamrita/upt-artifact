"""Property tests for Lemma 1, Theorems 2-3, Propositions 1-2 and the verifier."""
import itertools
import random
import sys
from dataclasses import replace
from pathlib import Path

import z3

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "experiments")]

from corpus import C_R, make_corpus  # noqa: E402
from upt import Deny, GrantStore, TrustContext, compute_grant  # noqa: E402
from upt.core import boundary_meet, compose, local_veto, policy_meet  # noqa: E402
from upt.translate import range_to_masks, translate  # noqa: E402
from upt.verify import Vars, check_sound, eval_policy, policy_formula  # noqa: E402

CASES = make_corpus(120, 0.0, seed=11)


def _equiv(p, q, binding):
    V = Vars(32)
    s = z3.Solver()
    s.add(policy_formula(V, p, binding, 4) != policy_formula(V, q, binding, 4))
    return s.check() == z3.unsat


def _and(p, q, binding):
    V = Vars(32)
    return z3.And(policy_formula(V, p, binding, 4), policy_formula(V, q, binding, 4)), V


def test_range_to_masks_exact():
    rng = random.Random(3)
    for _ in range(300):
        lo = rng.randrange(65536)
        hi = rng.randrange(lo, 65536)
        cover = range_to_masks(lo, hi)
        for p in [lo, hi, max(0, lo - 1), min(65535, hi + 1), rng.randrange(65536)]:
            inside = any((p & m) == v for v, m in cover)
            assert inside == (lo <= p <= hi)


def test_lemma1_exact_meet():
    """A_{P meet Q} = A_P intersect A_Q, checked by SMT equivalence."""
    for cs in CASES[:60]:
        ps = list(cs.policies.values())
        p, q = ps[0], ps[-1]
        b = cs.bindings["ent"]
        m = policy_meet(p, q)
        V = Vars(32)
        s = z3.Solver()
        both = z3.And(policy_formula(V, p, b, 4), policy_formula(V, q, b, 4))
        s.add(policy_formula(V, m, b, 4) != both)
        assert s.check() == z3.unsat, cs.cid


def test_order_independence():
    for cs in CASES[:40]:
        ps = list(cs.policies.values()) + [list(cs.policies.values())[0]]
        b = cs.bindings["ent"]
        ref = compose(ps)
        for perm in itertools.permutations(ps):
            alt = compose(list(perm))
            assert _equiv(ref, alt, b)
            assert (alt.suites, alt.iso, alt.resp, alt.life, alt.amin, alt.theta) == \
                   (ref.suites, ref.iso, ref.resp, ref.life, ref.amin, ref.theta)


def test_monotonic_security_and_grants():
    for cs in CASES:
        g = compute_grant(cs.subject, cs.T, cs.path, cs.policies, cs.bindings, t=10.0, c_r=C_R)
        assert not isinstance(g, Deny), (cs.cid, g)
        for d in cs.path:
            P = cs.policies[d]
            assert g.policy.iso >= P.iso and g.policy.resp >= P.resp and g.policy.life <= P.life
            V = Vars(32)
            s = z3.Solver()
            s.add(policy_formula(V, g.policy, cs.bindings["ent"], 4),
                  z3.Not(policy_formula(V, P, cs.bindings["ent"], 4)))
            assert s.check() == z3.unsat


def test_local_veto_bounds_compromised_upt():
    """Proposition 2: whatever the UPT sends, installed rules stay within the local policy."""
    rng = random.Random(5)
    for cs in CASES[:40]:
        local = cs.policies["ent"] if "ent" in cs.policies else list(cs.policies.values())[-1]
        evil = replace(local, atoms=tuple(replace(a, dst=replace(a.dst, net=0, plen=0), lo=0, hi=65535,
                                                  protos=frozenset({6, 17}), dir="bi") for a in local.atoms),
                       subjects=frozenset({cs.subject, "attacker"}))
        inst = local_veto(evil, local)
        tab = translate("ent", inst, cs.bindings["ent"])
        assert check_sound(tab, local, cs.bindings["ent"], 4).ok


def test_revocation_target_first_and_lease():
    cs = CASES[0]
    g = compute_grant(cs.subject, cs.T, cs.path, cs.policies, cs.bindings, t=10.0, c_r=C_R)
    store = GrantStore()
    store.add(g)
    bad = TrustContext(cs.T.assurance, cs.T.alpha, cs.T.beta + 200, 20.0, cs.T.src)
    ops = store.on_trust_event(cs.subject, bad, 20.0, cs.policies)
    assert [d for _, d, _ in ops] == list(reversed(cs.path))
    assert store.by_subject[cs.subject] == []
    assert g.t_exp > 10.0


def test_shadowing_detected():
    from upt.translate import Rule, Table
    cs = CASES[1]
    b = cs.bindings["ent"]
    pol = cs.policies["ent"]
    tab = translate("ent", pol, b)
    addr = next(iter(b[cs.subject]))
    existing = Table("ent", "prio", 32, [Rule(2000, frozenset([addr]), None, None, None, None, "acc")])
    eff = Table("ent", "prio", 32, existing.rules + tab.rules)
    r = check_sound(eff, pol, b, 4, restrict=True)
    assert not r.ok and not eval_policy(pol, b, 4, r.witness)


def test_wildcard_subject_detected():
    from dataclasses import replace as rp
    from upt.translate import Table
    cs = CASES[2]
    b = cs.bindings["ent"]
    pol = cs.policies["ent"]
    tab = translate("ent", pol, b)
    bad = Table("ent", "prio", 32, [rp(r, src=None) for r in tab.rules])
    r = check_sound(bad, pol, b, 4)
    assert not r.ok and not eval_policy(pol, b, 4, r.witness)
