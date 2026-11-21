"""IILS data model (Section IV): addresses, boundary atoms, policies, trust context.

Resource names are assumed to be resolved to IP prefixes before a policy reaches
this layer (Section V-B); the resolution snapshot is part of the binding used by
the verifier.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field, replace
from typing import FrozenSet, Optional, Tuple

INF = math.inf

# Chains of Table II (higher value = more restrictive).
ISO = {"low": 0, "med": 1, "high": 2}
RESP = {"log": 0, "alert": 1, "limit": 2, "quarantine": 3}
AL = {"AL1": 1, "AL2": 2, "AL3": 3}
PROTO = {"tcp": 6, "udp": 17}
SUITES = frozenset({"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"})


class _All:
    """Top element of a powerset component (no restriction)."""

    def __repr__(self) -> str:
        return "ALL"

    def __and__(self, other):
        return other

    def __rand__(self, other):
        return other


ALL = _All()


def meet_set(a, b):
    if a is ALL:
        return b
    if b is ALL:
        return a
    return frozenset(a) & frozenset(b)


@dataclass(frozen=True)
class Prefix:
    version: int  # 4 or 6
    net: int
    plen: int

    @staticmethod
    def parse(text: str) -> "Prefix":
        n = ipaddress.ip_network(text, strict=False)
        return Prefix(n.version, int(n.network_address), n.prefixlen)

    @property
    def width(self) -> int:
        return 32 if self.version == 4 else 128

    @property
    def mask(self) -> int:
        w = self.width
        return ((1 << w) - 1) ^ ((1 << (w - self.plen)) - 1)

    def contains(self, other: "Prefix") -> bool:
        return (
            self.version == other.version
            and self.plen <= other.plen
            and (other.net & self.mask) == self.net
        )

    def meet(self, other: "Prefix") -> Optional["Prefix"]:
        if self.contains(other):
            return other
        if other.contains(self):
            return self
        return None

    def __str__(self) -> str:
        cls = ipaddress.IPv4Network if self.version == 4 else ipaddress.IPv6Network
        return str(cls((self.net, self.plen)))


@dataclass(frozen=True)
class Atom:
    """Boundary atom b = <R_b, Pi_b, [l_b, u_b], delta_b> (Eq. atom)."""

    dst: Prefix
    protos: FrozenSet[int]
    lo: int
    hi: int
    dir: str  # 'in' | 'out' | 'bi'
    syscalls: Optional[FrozenSet[str]] = None  # atom-level extension; None = no constraint

    def meet(self, o: "Atom") -> Optional["Atom"]:
        d = self.dst.meet(o.dst)
        if d is None:
            return None
        protos = self.protos & o.protos
        lo, hi = max(self.lo, o.lo), min(self.hi, o.hi)
        if self.dir == "bi":
            dr = o.dir
        elif o.dir == "bi" or o.dir == self.dir:
            dr = self.dir
        else:
            return None
        if not protos or lo > hi:
            return None
        if self.syscalls is None:
            sc = o.syscalls
        elif o.syscalls is None:
            sc = self.syscalls
        else:
            sc = self.syscalls & o.syscalls
        return Atom(d, frozenset(protos), lo, hi, dr, sc)


@dataclass(frozen=True)
class QoS:
    mtd_max: float = INF  # U_i: largest shuffle interval security tolerates (s)
    eta_min: float = 0.0  # minimum availability
    eta_hard: bool = False


@dataclass(frozen=True)
class Policy:
    """IILS policy P = <I_attr, C_bound, E_act, T_ctx> (Definition 1), without T_ctx."""

    anchor: str
    subjects: object  # frozenset of subject ids, or ALL
    atoms: Tuple[Atom, ...]
    suites: object = ALL  # frozenset or ALL
    iso: int = 0
    resp: int = 0
    life: float = INF
    amin: int = 1
    theta: float = 0.0
    qos: QoS = field(default_factory=QoS)


@dataclass(frozen=True)
class TrustContext:
    """T_ctx (Definition 5)."""

    assurance: int
    alpha: float
    beta: float
    t0: float
    src: str
    sig: bytes = b""

    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @staticmethod
    def from_enterprise_score(te: float, n_obs: float, t0: float, src: str = "enterprise",
                              assurance: int = 2) -> "TrustContext":
        """Map the enterprise trust score T_e of [own_phase2, Eq. 4.1] to a Beta
        posterior by moment matching with pseudo-count n_obs (Section IV-E)."""
        te = min(max(te, 1e-6), 1 - 1e-6)
        return TrustContext(assurance, 1 + n_obs * te, 1 + n_obs * (1 - te), t0, src)


def with_atoms(p: Policy, atoms) -> Policy:
    return replace(p, atoms=tuple(atoms))
