"""SMT verification of translated rule sets (Section VI) and an independent
concrete interpreter used as ground truth in the evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

import z3

from .iils import ALL, Atom, Policy, Prefix
from .translate import Rule, Table, map_atom


@dataclass
class Flow:
    src: int
    dst: int
    proto: int
    port: int
    out: bool


class Vars:
    def __init__(self, width: int):
        self.width = width
        self.src = z3.BitVec("src", width)
        self.dst = z3.BitVec("dst", width)
        self.proto = z3.BitVec("proto", 8)
        self.port = z3.BitVec("port", 16)
        self.out = z3.Bool("out")


def _pfx(v, p: Prefix, width: int):
    return (v & z3.BitVecVal(p.mask, width)) == z3.BitVecVal(p.net, width)


def _in(v, values, width):
    return z3.Or([v == z3.BitVecVal(x, width) for x in values]) if values else z3.BoolVal(False)


def atom_formula(V: Vars, a: Atom):
    c = [_pfx(V.dst, a.dst, V.width), _in(V.proto, sorted(a.protos), 8),
         z3.ULE(z3.BitVecVal(a.lo, 16), V.port), z3.ULE(V.port, z3.BitVecVal(a.hi, 16))]
    if a.dir == "out":
        c.append(V.out)
    elif a.dir == "in":
        c.append(z3.Not(V.out))
    return z3.And(c)


def subject_addrs(policy: Policy, binding: Dict[str, Sequence[int]]):
    if policy.subjects is ALL:
        return None
    return sorted({a for s in policy.subjects for a in binding.get(s, ())})


def policy_formula(V: Vars, policy: Policy, binding, version: int):
    """Phi_P (Eqs. 8-9) in the domain's address family."""
    atoms = [map_atom(a, version) for a in policy.atoms]
    body = z3.Or([atom_formula(V, a) for a in atoms]) if atoms else z3.BoolVal(False)
    addrs = subject_addrs(policy, binding)
    return body if addrs is None else z3.And(_in(V.src, addrs, V.width), body)


def rule_match(V: Vars, r: Rule):
    c = []
    if r.src is not None:
        c.append(_in(V.src, sorted(r.src), V.width))
    if r.dst is not None:
        c.append(_pfx(V.dst, r.dst, V.width))
    if r.protos is not None:
        c.append(_in(V.proto, sorted(r.protos), 8))
    if r.ports is not None:
        if r.ports[0] == "range":
            c.append(z3.ULE(z3.BitVecVal(r.ports[1], 16), V.port))
            c.append(z3.ULE(V.port, z3.BitVecVal(r.ports[2], 16)))
        else:
            c.append((V.port & z3.BitVecVal(r.ports[2], 16)) == z3.BitVecVal(r.ports[1], 16))
    if r.dir is not None:
        c.append(V.out if r.dir else z3.Not(V.out))
    return z3.And(c) if c else z3.BoolVal(True)


def acc_formula(V: Vars, t: Table):
    """Acc_R (Eq. 10) as a linear If-chain over the ordered rule list."""
    acc = z3.BoolVal(t.default == "acc")
    for r in reversed(t.ordered()):
        acc = z3.If(rule_match(V, r), z3.BoolVal(r.action == "acc"), acc)
    return acc


@dataclass
class Result:
    ok: bool
    witness: Optional[Flow] = None


def _model_flow(m, V: Vars) -> Flow:
    def g(x, d=0):
        v = m.eval(x, model_completion=True)
        return v.as_long() if hasattr(v, "as_long") else d
    return Flow(g(V.src), g(V.dst), g(V.proto), g(V.port), z3.is_true(m.eval(V.out, model_completion=True)))


def check_sound(t: Table, policy: Policy, binding, version: int, restrict: bool = False) -> Result:
    """Eq. (sound): Acc_R and not Phi_P must be unsatisfiable.

    Two queries are used (Section VI-B): the newly generated rules over *all*
    sources (restrict=False), which catches rules that admit other subjects, and
    the domain's effective table restricted to src in beta(S) (restrict=True),
    which catches shadowing by existing rules without flagging other subjects'
    legitimate rules."""
    V = Vars(t.width)
    s = z3.Solver()
    addrs = subject_addrs(policy, binding)
    if restrict and addrs is not None:
        s.add(_in(V.src, addrs, V.width))
    s.add(acc_formula(V, t), z3.Not(policy_formula(V, policy, binding, version)))
    if s.check() == z3.unsat:
        return Result(True)
    return Result(False, _model_flow(s.model(), V))


def check_rule_set(new: Table, effective: Table, policy: Policy, binding, version: int) -> Result:
    """Both soundness queries; returns the first failure."""
    r = check_sound(new, policy, binding, version)
    if not r.ok:
        return r
    return check_sound(relevant(effective, policy, binding), policy, binding, version, restrict=True)


def relevant(t: Table, policy: Policy, binding) -> Table:
    """Keep only rules that can match a source in beta(S); removing the others
    does not change acceptance of any flow from beta(S)."""
    addrs = subject_addrs(policy, binding)
    if addrs is None:
        return t
    A = set(addrs)
    keep = [r for r in t.rules if r.src is None or (r.src & A)]
    return Table(t.domain, t.kind, t.width, keep, t.default)


def check_complete(t: Table, policy: Policy, binding, version: int) -> Result:
    V = Vars(t.width)
    s = z3.Solver()
    s.add(policy_formula(V, policy, binding, version), z3.Not(acc_formula(V, t)))
    if s.check() == z3.unsat:
        return Result(True)
    return Result(False, _model_flow(s.model(), V))


def check_obligations(config: Dict, required: Dict) -> List[str]:
    """Lookup checks of Section VI-B. Returns the list of failed obligations."""
    bad = []
    if "suite" in required and config.get("suite") not in required["suite"]:
        bad.append("suite")
    if config.get("iso", 0) < required.get("iso", 0):
        bad.append("iso")
    if config.get("life", float("inf")) > required.get("life", float("inf")):
        bad.append("life")
    if config.get("resp", 0) < required.get("resp", 0):
        bad.append("resp")
    if "syscalls" in required and config.get("syscalls") != required["syscalls"]:
        bad.append("syscalls")
    return bad


# --------------------------------------------------------------------------- ground truth


def eval_rule(r: Rule, f: Flow, width: int) -> bool:
    if r.src is not None and f.src not in r.src:
        return False
    if r.dst is not None and (f.dst & r.dst.mask) != r.dst.net:
        return False
    if r.protos is not None and f.proto not in r.protos:
        return False
    if r.ports is not None:
        if r.ports[0] == "range" and not (r.ports[1] <= f.port <= r.ports[2]):
            return False
        if r.ports[0] == "mask" and (f.port & r.ports[2]) != r.ports[1]:
            return False
    if r.dir is not None and r.dir != f.out:
        return False
    return True


def eval_table(t: Table, f: Flow) -> bool:
    for r in t.ordered():
        if eval_rule(r, f, t.width):
            return r.action == "acc"
    return t.default == "acc"


def eval_policy(policy: Policy, binding, version: int, f: Flow) -> bool:
    addrs = subject_addrs(policy, binding)
    if addrs is not None and f.src not in addrs:
        return False
    for a in policy.atoms:
        a = map_atom(a, version)
        if (f.dst & a.dst.mask) != a.dst.net or f.proto not in a.protos or not (a.lo <= f.port <= a.hi):
            continue
        if a.dir == "bi" or (a.dir == "out") == f.out:
            return True
    return False
