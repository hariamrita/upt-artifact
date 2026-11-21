"""Synthetic policy corpus (Section VIII-A).

Each case is a subject with a trust context, a domain path, one IILS policy per
domain on the path, and per-domain address bindings. A fraction `c` of cases has
one injected conflict of a known type, so detection can be scored.
"""
from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, replace
from typing import Dict, List

from upt.iils import ALL, AL, INF, ISO, PROTO, RESP, Atom, Policy, Prefix, QoS, TrustContext

PATHS = [("res", "ent"), ("mob", "ent"), ("ent", "res"), ("mob", "ent", "res")]
CONFLICTS = ["boundary", "suite", "unplaceable", "availability", "trust"]
ANCHOR = {"res": "MUD", "ent": "WKLD", "mob": "EUICC"}
ASSURANCE = {"res": AL["AL1"], "ent": AL["AL2"], "mob": AL["AL3"]}
C_R = 0.24  # s; estimated from 99.92% session stability at a 300 s shuffle interval


@dataclass
class Case:
    cid: int
    subject: str
    T: TrustContext
    path: tuple
    policies: Dict[str, Policy]
    bindings: Dict[str, Dict[str, List[int]]]
    kind: str  # 'ok' or the injected conflict type


def _bindings(subject: str, k: int):
    v4 = lambda s: [int(ipaddress.IPv4Address(s))]
    return {
        "res": {subject: v4(f"192.168.{1 + k // 250}.{1 + k % 250}")},
        "ent": {subject: v4(f"100.64.{k // 250}.{1 + k % 250}")},
        # current and previous shuffled IPv6 address (2 s rule overlap)
        "mob": {subject: [int(ipaddress.IPv6Address(f"2001:db8::{k + 1:x}")),
                          int(ipaddress.IPv6Address(f"2001:db8:1::{k + 1:x}"))]},
    }


def _dst(rng: random.Random, base: int) -> Prefix:
    plen = rng.choice([16, 24, 24, 28, 32])
    host = (10 << 24) | (20 << 16) | (base << 8) | rng.randrange(256)
    return Prefix(4, host & (((1 << 32) - 1) ^ ((1 << (32 - plen)) - 1)), plen)


def _atom(rng: random.Random, base: int, out: bool = True) -> Atom:
    if rng.random() < 0.6:
        lo = hi = rng.choice([443, 8443, 5683, 1883, 8883, rng.randrange(1024, 65535)])
    else:
        lo = rng.randrange(1024, 60000)
        hi = min(65535, lo + rng.randrange(1, 4000))
    protos = frozenset(rng.sample([6, 17], rng.choice([1, 1, 2])))
    return Atom(_dst(rng, base), protos, lo, hi, rng.choice(["out", "bi"]) if out else "bi")


def _widen(a: Atom, rng: random.Random) -> Atom:
    """A target-side atom that covers `a` (so the meet is non-empty)."""
    plen = rng.choice([16, 24]) if a.dst.plen >= 24 else a.dst.plen
    mask = ((1 << 32) - 1) ^ ((1 << (32 - plen)) - 1)
    lo = max(0, a.lo - rng.randrange(0, 100))
    hi = min(65535, a.hi + rng.randrange(0, 100))
    return Atom(Prefix(4, a.dst.net & mask, plen), frozenset({6, 17}), lo, hi, "bi")


def make_case(cid: int, rng: random.Random, kind: str = "ok") -> Case:
    path = rng.choice(PATHS)
    subject = f"dev-{cid}"
    base = rng.randrange(1, 200)
    src_atoms = [_atom(rng, base) for _ in range(rng.randint(1, 10))]
    if "ent" in path and rng.random() < 0.2:
        src_atoms[0] = replace(src_atoms[0], syscalls=frozenset({"read", "write", "connect"}))
    tgt_atoms = [_widen(a, rng) for a in src_atoms if rng.random() < 0.8] or [_widen(src_atoms[0], rng)]

    # Suites consistent with every segment of the path.
    has_res, has_mob = "res" in path, "mob" in path
    suites = frozenset({"CHACHA20-POLY1305", "AES-256-GCM"}) if not has_mob else frozenset(
        {"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"})
    life = rng.choice([INF, 600.0, 3600.0])
    iso = rng.choice([ISO["low"], ISO["med"], ISO["high"]])
    resp = rng.choice([RESP["log"], RESP["alert"], RESP["quarantine"]] if not has_mob or "ent" in path else [RESP["alert"]])
    src_amin = 1
    pol = {}
    for i, d in enumerate(path):
        role_atoms = src_atoms if i == 0 else tgt_atoms
        qos = QoS()
        if d == "mob":
            qos = QoS(mtd_max=rng.choice([60.0, 300.0]))
        if d == "ent" and rng.random() < 0.3:
            qos = QoS(eta_min=0.99)
        pol[d] = Policy(ANCHOR[d], frozenset({subject}), tuple(role_atoms), suites,
                        iso if i == len(path) - 1 else 0, resp if i == len(path) - 1 else 0,
                        life, src_amin if i == 0 else 1, 0.6 if i == len(path) - 1 else 0.0, qos)
    src = path[0]
    T = TrustContext(ASSURANCE[src], 47.0, 3.0, 0.0, src)
    tgt = path[-1]

    if kind == "boundary":
        far = (base + 100) % 250 + 1
        pol[tgt] = replace(pol[tgt], atoms=tuple(_widen(_atom(rng, far), rng) for _ in range(len(tgt_atoms))))
        # guarantee disjointness: move every target atom outside the source /16 block
        pol[tgt] = replace(pol[tgt], atoms=tuple(
            Atom(Prefix(4, (10 << 24) | (21 << 16) | (far << 8), 24), a.protos, a.lo, a.hi, a.dir)
            for a in pol[tgt].atoms))
    elif kind == "suite":
        if has_res:
            pol[tgt] = replace(pol[tgt], suites=frozenset({"AES-256-GCM"}))
        else:
            pol[src] = replace(pol[src], suites=frozenset({"CHACHA20-POLY1305"}))
            pol[tgt] = replace(pol[tgt], suites=frozenset({"AES-256-GCM"}))
    elif kind == "unplaceable":
        if has_mob:  # mobile cannot quarantine and is the only point domain on (mob,ent)? use MTD on a path without mob instead
            path = ("res", "ent")
            pol = {d: pol.get(d, pol[list(pol)[-1]]) for d in path}
            pol["res"] = replace(pol["res"], anchor="MUD", atoms=tuple(src_atoms))
            T = TrustContext(ASSURANCE["res"], 47.0, 3.0, 0.0, "res")
        pol[path[-1]] = replace(pol[path[-1]], qos=QoS(mtd_max=30.0))
    elif kind == "availability":
        if not has_mob:
            path = ("mob", "ent")
            pol = {"mob": replace(pol[path[0]] if path[0] in pol else pol[src], anchor="EUICC",
                                  atoms=tuple(src_atoms), qos=QoS(mtd_max=60.0)),
                   "ent": pol.get("ent", pol[tgt])}
            T = TrustContext(ASSURANCE["mob"], 47.0, 3.0, 0.0, "mob")
            pol["mob"] = replace(pol["mob"], suites=frozenset({"AES-256-GCM"}))
            pol["ent"] = replace(pol["ent"], suites=frozenset({"AES-256-GCM"}))
        pol["ent"] = replace(pol["ent"], qos=QoS(eta_min=0.9999, eta_hard=True))
        pol["mob"] = replace(pol["mob"], qos=QoS(mtd_max=60.0))
    elif kind == "trust":
        if rng.random() < 0.5:
            T = TrustContext(T.assurance, 6.0, 4.0, 0.0, src)  # score 0.6 < 0.9
            pol[path[-1]] = replace(pol[path[-1]], theta=0.9)
        else:
            pol[path[-1]] = replace(pol[path[-1]], amin=AL["AL3"])
            if src == "mob":
                T = TrustContext(AL["AL3"], 47.0, 3.0, 0.0, src)
                # a compromised residential controller claiming AL3 is capped at AL1
                path = ("res", "ent")
                pol = {"res": replace(pol["mob"], anchor="MUD", atoms=tuple(src_atoms),
                                      suites=frozenset({"CHACHA20-POLY1305", "AES-256-GCM"}), qos=QoS()),
                       "ent": replace(pol["ent"], amin=AL["AL3"])}
                T = TrustContext(AL["AL3"], 47.0, 3.0, 0.0, "res")
    return Case(cid, subject, T, tuple(path), pol, _bindings(subject, cid), kind)


def make_corpus(n: int, c: float, seed: int = 7) -> List[Case]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        kind = rng.choice(CONFLICTS) if rng.random() < c else "ok"
        out.append(make_case(i, rng, kind))
    return out
