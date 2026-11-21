"""Algorithm 1 (cross-domain grant computation), leases and revocation (Sections V-C to V-F)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .core import (PlacementError, Profile, admit, compose, is_empty, lease_expiry, local_veto,
                   negotiate_qos, place)
from .iils import ALL, AL, INF, ISO, RESP, Policy, TrustContext, with_atoms
from .translate import Table, translate
from .verify import check_complete, check_obligations, check_rule_set

# Capability profiles of the evaluated domains (Table III). Suites for the
# enterprise and mobile tunnels must be confirmed against the implementations.
PROFILES = {
    "res": Profile("res", 4, frozenset({"MUD"}), frozenset({"CHACHA20-POLY1305"}), ISO["med"],
                   frozenset({RESP["log"], RESP["alert"], RESP["quarantine"]}), True, False, False, AL["AL1"]),
    "ent": Profile("ent", 4, frozenset({"WKLD"}), frozenset({"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}),
                   ISO["high"], frozenset(RESP.values()), True, True, False, AL["AL2"]),
    "mob": Profile("mob", 6, frozenset({"EUICC"}), frozenset({"AES-128-GCM", "AES-256-GCM"}), ISO["high"],
                   frozenset({RESP["log"], RESP["alert"], RESP["limit"]}), True, False, True, AL["AL3"]),
}

# Native construct level realised by each domain for isolation (Table III).
ISO_REALISED = {"res": ISO["med"], "ent": ISO["high"], "mob": ISO["high"]}
NATIVE_SUITE = {"res": "CHACHA20-POLY1305"}  # WireGuard can only use this suite


@dataclass
class Deny:
    reason: str


@dataclass
class Grant:
    subject: str
    path: List[str]
    policy: Policy
    tables: Dict[str, Table]
    configs: Dict[str, Dict]
    t_exp: float
    install_order: List[str]
    warnings: List[str] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)


def _configs(pf: Policy, path, pl) -> (Dict[str, Dict], Dict[str, Dict]):
    cfg, req = {d: {} for d in path}, {d: {} for d in path}
    for (a, b), suite in pl.seg_suite.items():
        for d in (a, b):
            cfg[d]["suite"] = NATIVE_SUITE.get(d, suite)
            req[d]["suite"] = (pf.suites if pf.suites is not ALL else {NATIVE_SUITE.get(d, suite)})
    for ob, d in pl.point.items():
        if ob == "iso":
            cfg[d]["iso"], req[d]["iso"] = ISO_REALISED[d], pf.iso
        elif ob == "resp":
            cfg[d]["resp"], req[d]["resp"] = pf.resp, pf.resp
        elif ob == "life":
            cfg[d]["life"], req[d]["life"] = pf.life, pf.life
        elif ob == "syscalls":
            sc = frozenset().union(*[a.syscalls for a in pl.atoms if a.syscalls is not None])
            cfg[d]["syscalls"], req[d]["syscalls"] = sc, sc
    return cfg, req


def compute_grant(subject: str, T: TrustContext, path: Sequence[str], policies: Dict[str, Policy],
                  bindings: Dict[str, Dict], t: float, c_r: float = 0.0,
                  profiles: Dict[str, Profile] = PROFILES,
                  existing: Optional[Dict[str, Table]] = None, verify: bool = True):
    tm = {}
    t0 = time.perf_counter()
    cap = profiles[path[0]].max_assurance
    for d in path:
        P = policies[d]
        if not admit(T, P.amin, P.theta, t, cap):
            return Deny(f"trust:{d}")
    tm["admission"] = time.perf_counter() - t0

    t1 = time.perf_counter()
    pf = compose([policies[d] for d in path])
    q = negotiate_qos([policies[d].qos for d in path], c_r)
    tm["compose"] = time.perf_counter() - t1
    if is_empty(pf):
        return Deny("conflict:empty")
    if q.hard_violation:
        return Deny("conflict:availability")

    t2 = time.perf_counter()
    try:
        pl = place(pf, path, profiles, need_mtd=q.mtd_interval < INF)
    except PlacementError as e:
        return Deny(f"unplaceable:{e}")
    pf = with_atoms(pf, pl.atoms)
    tm["place"] = time.perf_counter() - t2

    tables, warnings = {}, []
    if q.violated:
        warnings.append("availability bound violated (soft)")
    if pl.dropped_atoms:
        warnings.append(f"{pl.dropped_atoms} atom(s) dropped: system-call boundary unenforceable")
    cfg, req = _configs(pf, path, pl)
    tm["translate"] = 0.0
    tm["verify"] = 0.0
    for d in path:
        t3 = time.perf_counter()
        installed = local_veto(pf, policies[d])
        tab = translate(d, installed, bindings[d])
        tm["translate"] += time.perf_counter() - t3
        tables[d] = tab
        if verify:
            t4 = time.perf_counter()
            eff = tab
            if existing and d in existing:
                ex = existing[d]
                eff = Table(d, tab.kind, tab.width, list(ex.rules) + list(tab.rules), tab.default)
            ver = profiles[d].version
            if not check_rule_set(tab, eff, installed, bindings[d], ver).ok:
                return Deny(f"translation:{d}")
            if not check_complete(tab, installed, bindings[d], ver).ok:
                warnings.append(f"incomplete translation in {d}")
            if check_obligations(cfg[d], req[d]):
                return Deny(f"obligation:{d}")
            tm["verify"] += time.perf_counter() - t4

    pmax = compose([policies[d] for d in path])
    t_exp = lease_expiry(T, pmax.theta, pf.life, t)
    tm["total"] = time.perf_counter() - t0
    return Grant(subject, list(path), pf, tables, cfg, t_exp, list(reversed(path)), warnings, tm)


class GrantStore:
    """Active grants indexed by subject; event-driven revocation and lease expiry."""

    def __init__(self):
        self.by_subject: Dict[str, List[Grant]] = {}

    def add(self, g: Grant):
        self.by_subject.setdefault(g.subject, []).append(g)

    def on_trust_event(self, subject: str, T: TrustContext, t: float, policies: Dict[str, Policy],
                       profiles: Dict[str, Profile] = PROFILES) -> List[tuple]:
        """Re-evaluate Eq. (admit) for every grant of `subject`; return revocation
        operations ordered target-first."""
        ops, keep = [], []
        for g in self.by_subject.get(subject, []):
            cap = profiles[g.path[0]].max_assurance
            if all(admit(T, policies[d].amin, policies[d].theta, t, cap) for d in g.path):
                keep.append(g)
            else:
                ops += [("revoke", d, g) for d in reversed(g.path)]
        self.by_subject[subject] = keep
        return ops

    def expire(self, t: float) -> List[Grant]:
        gone = []
        for s, gs in self.by_subject.items():
            gone += [g for g in gs if g.t_exp <= t]
            self.by_subject[s] = [g for g in gs if g.t_exp > t]
        return gone
