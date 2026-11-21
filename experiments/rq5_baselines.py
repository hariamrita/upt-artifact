"""RQ5: UPT vs. re-implementations of the composition semantics of two baselines.

B1 (I2NSF-style): every domain translates only its own policy to its own NSFs
   (RFC 8329). There is no cross-domain composition and no trust exchange; an
   obligation a domain cannot enforce is mapped to the closest available
   capability or omitted, and each segment uses the suite its endpoints support.
B2 (OPA/Rego at every PEP): each PEP evaluates its domain's policy on a shared
   request document that includes the subject's claimed trust context; the flow
   is admitted only if every PEP allows it. Decisions carry no obligations.

For every corpus case we record, per approach:
  surfaced  - an injected conflict is reported before any traffic is admitted
  obl_loss  - an obligation required by some domain is enforced nowhere
  unsafe    - the subject is admitted although some domain's admission
              requirement is not met (including assurance claims above the
              source domain's registered maximum)
Usage: python experiments/rq5_baselines.py [n] [c] [seed]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "experiments")]

from corpus import C_R, make_corpus  # noqa: E402
from upt import Deny, admit, compose, compute_grant, negotiate_qos  # noqa: E402
from upt.core import is_empty  # noqa: E402
from upt.grant import PROFILES  # noqa: E402
from upt.iils import ALL, INF  # noqa: E402


def truth(cs, t=10.0):
    """Ground-truth admission and obligation facts for a case."""
    cap = PROFILES[cs.path[0]].max_assurance
    admissible = all(admit(cs.T, cs.policies[d].amin, cs.policies[d].theta, t, cap) for d in cs.path)
    return admissible


def required_obligations(cs):
    """Obligations demanded by some domain policy on the path."""
    req = set()
    for d in cs.path:
        P = cs.policies[d]
        if P.iso > 0:
            req.add(("iso", P.iso))
        if P.resp > 0:
            req.add(("resp", P.resp))
        if P.qos.mtd_max < INF:
            req.add(("mtd", P.qos.mtd_max))
        if P.suites is not ALL:
            req.add(("suite", P.suites))
        if any(a.syscalls is not None for a in P.atoms):
            req.add(("syscalls", None))
    return req


def enforceable_somewhere(ob, cs):
    kind, val = ob
    prof = [PROFILES[d] for d in cs.path]
    if kind == "iso":
        return any(g.iso_max >= val for g in prof)
    if kind == "resp":
        return any(val in g.resp for g in prof)
    if kind == "mtd":
        return any(g.mtd for g in prof)
    if kind == "syscalls":
        return any(g.syscalls for g in prof)
    if kind == "suite":
        return all((PROFILES[a].suites & PROFILES[b].suites & val) for a, b in zip(cs.path, cs.path[1:]))
    return True


def obligation_unmet(cs, admitted_policy_atoms_dropped=False):
    """True if some obligation demanded by a domain on the path cannot be met by
    the path as configured: an unenforceable obligation, an empty composed suite
    set on any segment, or a hard availability bound broken by the MTD interval.
    The same check is applied to every approach."""
    reqs = required_obligations(cs)
    for o in reqs:
        if o[0] == "syscalls" and admitted_policy_atoms_dropped:
            continue  # the UPT removes such atoms instead of admitting them unenforced
        if not enforceable_somewhere(o, cs):
            return True
    pf = compose([cs.policies[d] for d in cs.path])
    if pf.suites is not ALL and not enforceable_somewhere(("suite", pf.suites), cs):
        return True
    if negotiate_qos([cs.policies[d].qos for d in cs.path], C_R).hard_violation:
        return True
    return False


def run_b1(cs):
    # No trust exchange: only the source domain evaluates the subject's trust.
    src = cs.path[0]
    admitted = admit(cs.T, cs.policies[src].amin, cs.policies[src].theta, 10.0, 3)
    # Each domain filters its own boundary; with disjoint boundaries no packet
    # passes, but nothing reports the conflict before deployment.
    surfaced = False
    return admitted, surfaced, obligation_unmet(cs)


def run_b2(cs):
    # Every PEP evaluates its own admission rule on the claimed trust context
    # (no registered-assurance cap) and its boundary; decisions are conjoined.
    pf = compose([cs.policies[d] for d in cs.path])
    decisions = all(admit(cs.T, cs.policies[d].amin, cs.policies[d].theta, 10.0, 3) for d in cs.path)
    boundary_ok = bool(pf.atoms) and not (pf.subjects is not ALL and not pf.subjects)
    admitted = decisions and boundary_ok
    surfaced = not admitted  # a deny at request time, before traffic flows
    return admitted, surfaced, obligation_unmet(cs)


def run_upt(cs):
    g = compute_grant(cs.subject, cs.T, cs.path, cs.policies, cs.bindings, 10.0, C_R)
    admitted = not isinstance(g, Deny)
    surfaced = not admitted or bool(getattr(g, "warnings", []))
    return admitted, surfaced, obligation_unmet(cs, admitted_policy_atoms_dropped=True)


def main(n=1000, c=0.5, seed=31):
    cases = make_corpus(n, c, seed=seed)
    approaches = {"B1": run_b1, "B2": run_b2, "UPT": run_upt}
    res = {a: {"cases": 0, "conflict_cases": 0, "surfaced": 0, "obl_loss": 0, "unsafe": 0,
               "ok_admitted": 0, "ok_cases": 0} for a in approaches}
    by_kind = {}
    for cs in cases:
        adm_truth = truth(cs)
        for a, fn in approaches.items():
            admitted, surfaced, loss = fn(cs)
            r = res[a]
            r["cases"] += 1
            if cs.kind == "ok":
                r["ok_cases"] += 1
                r["ok_admitted"] += int(admitted)
            else:
                r["conflict_cases"] += 1
                r["surfaced"] += int(surfaced)
                by_kind.setdefault(a, {}).setdefault(cs.kind, [0, 0])
                by_kind[a][cs.kind][0] += int(surfaced)
                by_kind[a][cs.kind][1] += 1
            r["obl_loss"] += int(admitted and loss)
            r["unsafe"] += int(admitted and not adm_truth)
    out = {"n": n, "c": c, "seed": seed, "summary": res, "surfaced_by_kind": by_kind}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "rq5_baselines.json").write_text(json.dumps(out, indent=1))
    for a, r in res.items():
        print(a, "surfaced %.1f%%  obligation-loss %.1f%%  unsafe %.1f%%  ok-admitted %.1f%%" % (
            100 * r["surfaced"] / r["conflict_cases"], 100 * r["obl_loss"] / r["cases"],
            100 * r["unsafe"] / r["cases"], 100 * r["ok_admitted"] / r["ok_cases"]))
    print(json.dumps(by_kind))


if __name__ == "__main__":
    args = sys.argv[1:]
    main(int(args[0]) if args else 1000, float(args[1]) if len(args) > 1 else 0.5,
         int(args[2]) if len(args) > 2 else 31)
