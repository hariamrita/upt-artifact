"""Lattice meet, trust/admission/leases, QoS negotiation, placement, local veto
(Sections IV-C, IV-E, V-C, V-D, V-E, V-F)."""
from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from functools import reduce
from typing import Dict, List, Optional, Sequence, Tuple

from .iils import ALL, INF, Atom, Policy, QoS, TrustContext, meet_set

# --------------------------------------------------------------------------- meet


def boundary_meet(a: Sequence[Atom], b: Sequence[Atom]) -> Tuple[Atom, ...]:
    """B meet B' (Lemma 1), O(|B||B'|), with deduplication of identical atoms."""
    out = []
    seen = set()
    for x in a:
        for y in b:
            z = x.meet(y)
            if z is not None and z not in seen:
                seen.add(z)
                out.append(z)
    return tuple(out)


def policy_meet(p: Policy, q: Policy) -> Policy:
    """Componentwise meet of the security components (Theorem 1). QoS is left to
    negotiate_qos; the anchor of the left operand is kept."""
    return Policy(
        anchor=p.anchor,
        subjects=meet_set(p.subjects, q.subjects),
        atoms=boundary_meet(p.atoms, q.atoms),
        suites=meet_set(p.suites, q.suites),
        iso=max(p.iso, q.iso),
        resp=max(p.resp, q.resp),
        life=min(p.life, q.life),
        amin=max(p.amin, q.amin),
        theta=max(p.theta, q.theta),
        qos=p.qos,
    )


def is_empty(p: Policy) -> bool:
    subj_empty = p.subjects is not ALL and len(p.subjects) == 0
    suites_empty = p.suites is not ALL and len(p.suites) == 0
    return subj_empty or not p.atoms or suites_empty


# --------------------------------------------------------------------------- trust

MU = {1: 1 / 600.0, 2: 1 / 1800.0, 3: 1 / 3600.0}  # decay rates mu_a (1/s), Eq. (score)


def score(T: TrustContext, t: float) -> float:
    return T.mean() * math.exp(-MU[T.assurance] * max(0.0, t - T.t0))


def admit(T: TrustContext, amin: int, theta: float, t: float, cap: int = 3) -> bool:
    """Eq. (admit). `cap` is the highest assurance the source domain registered (A3)."""
    a = min(T.assurance, cap)
    return a >= amin and score(T, t) >= theta


def lease_expiry(T: TrustContext, theta: float, life: float, t: float) -> float:
    """Eq. (lease)."""
    s0 = T.mean()
    if theta <= 0:
        trust_t = INF
    elif s0 < theta:
        trust_t = T.t0
    else:
        trust_t = T.t0 + math.log(s0 / theta) / MU[T.assurance]
    return min(trust_t, t + life)


# --------------------------------------------------------------------------- QoS


@dataclass
class QoSResult:
    mtd_interval: float
    violated: bool
    hard_violation: bool


def negotiate_qos(qs: Sequence[QoS], c_r: float) -> QoSResult:
    """Eq. (qos): U = min U_i, L = max c_r/(1-eta_i), Delta t_f = U."""
    U = min(q.mtd_max for q in qs)
    bounds = [(c_r / (1 - q.eta_min) if q.eta_min < 1 else INF, q.eta_hard) for q in qs]
    L = max(b for b, _ in bounds)
    violated = L > U
    hard = any(h and b > U for b, h in bounds)
    return QoSResult(U, violated, hard)


# --------------------------------------------------------------------------- placement


@dataclass(frozen=True)
class Profile:
    """Capability profile Gamma_d (Section IV-D, Table III)."""

    name: str
    version: int  # address family of the domain's enforcement points
    anchors: frozenset
    suites: frozenset
    iso_max: int
    resp: frozenset
    lifetime: bool
    syscalls: bool
    mtd: bool
    max_assurance: int


@dataclass
class Placement:
    seg_suite: Dict[Tuple[str, str], str] = field(default_factory=dict)
    point: Dict[str, str] = field(default_factory=dict)  # obligation -> domain
    atoms: Tuple[Atom, ...] = ()
    dropped_atoms: int = 0


class PlacementError(Exception):
    pass


def place(pf: Policy, path: Sequence[str], prof: Dict[str, Profile], need_mtd: bool) -> Placement:
    pl = Placement()
    # Rule 2: encryption per segment.
    for a, b in zip(path, path[1:]):
        avail = prof[a].suites & prof[b].suites
        cand = avail if pf.suites is ALL else (avail & pf.suites)
        if not cand:
            raise PlacementError(f"no common suite on segment {a}-{b}")
        pl.seg_suite[(a, b)] = sorted(cand)[0]
    # Rule 3: point obligations nearest the target.
    rev = list(reversed(path))

    def nearest(pred):
        for d in rev:
            if pred(prof[d]):
                return d
        return None

    checks = {
        "iso": (pf.iso > 0, lambda g: g.iso_max >= pf.iso),
        "resp": (pf.resp > 0, lambda g: pf.resp in g.resp),
        "life": (pf.life < INF, lambda g: g.lifetime),
        "mtd": (need_mtd, lambda g: g.mtd),
    }
    for ob, (active, pred) in checks.items():
        if not active:
            continue
        d = nearest(pred)
        if d is None:
            raise PlacementError(f"obligation {ob} cannot be placed")
        pl.point[ob] = d
    # Atom-level system-call boundaries: drop atoms that no domain can enforce.
    sc_dom = nearest(lambda g: g.syscalls)
    kept = []
    for at in pf.atoms:
        if at.syscalls is not None and sc_dom is None:
            pl.dropped_atoms += 1
            continue
        kept.append(at)
    if sc_dom is not None and any(a.syscalls is not None for a in kept):
        pl.point["syscalls"] = sc_dom
    if not kept:
        raise PlacementError("all atoms carry unenforceable constraints")
    pl.atoms = tuple(kept)
    return pl


# --------------------------------------------------------------------------- local veto


def local_veto(received: Policy, local: Policy) -> Policy:
    """Section V-F: a controller installs phi_d(P_recv meet P_local)."""
    return policy_meet(received, local)


def compose(policies: Sequence[Policy]) -> Policy:
    """Eq. (compose)."""
    return reduce(policy_meet, policies)
