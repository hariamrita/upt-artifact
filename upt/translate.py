"""Domain translators phi_res, phi_ent, phi_mob (Section V-B, Table III).

Each translator emits an ordered match-action list (Section VI-A): iptables
chains (first match), OpenFlow tables (highest priority, port ranges expanded to
value/mask pairs) and P4 tables (highest priority, range match on IPv6, with
IPv4 destinations mapped through NAT64 64:ff9b::/96). Renderers produce the
native text that a controller adapter would push.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .iils import ALL, Atom, Policy, Prefix

NAT64 = int(ipaddress.IPv6Address("64:ff9b::"))


@dataclass(frozen=True)
class Rule:
    prio: int
    src: Optional[FrozenSet[int]]  # None = any source
    dst: Optional[Prefix]
    protos: Optional[FrozenSet[int]]
    ports: Optional[Tuple]  # ('range', lo, hi) | ('mask', value, mask) | None
    dir: Optional[bool]  # True = out, False = in, None = any
    action: str  # 'acc' | 'drop'


@dataclass
class Table:
    domain: str
    kind: str  # 'first' (iptables) | 'prio' (OpenFlow, P4)
    width: int
    rules: List[Rule] = field(default_factory=list)
    default: str = "drop"

    def ordered(self) -> List[Rule]:
        if self.kind == "first":
            return list(self.rules)
        return sorted(self.rules, key=lambda r: -r.prio)  # stable for equal priorities


def to_domain_prefix(p: Prefix, version: int) -> Prefix:
    if p.version == version:
        return p
    if p.version == 4 and version == 6:
        return Prefix(6, NAT64 | p.net, 96 + p.plen)
    raise ValueError("cannot map IPv6 destination into an IPv4 domain")


def map_atom(a: Atom, version: int) -> Atom:
    return Atom(to_domain_prefix(a.dst, version), a.protos, a.lo, a.hi, a.dir, a.syscalls)


def range_to_masks(lo: int, hi: int, width: int = 16) -> List[Tuple[int, int]]:
    """Minimal value/mask cover of [lo, hi] (OpenFlow tp_dst matching)."""
    out = []
    full = (1 << width) - 1
    while lo <= hi:
        size = lo & -lo if lo else 1 << width
        while size > hi - lo + 1:
            size >>= 1
        out.append((lo, full ^ (size - 1)))
        lo += size
    return out


def _dir(d: str) -> Optional[bool]:
    return None if d == "bi" else d == "out"


def _srcs(policy: Policy, binding: Dict[str, Sequence[int]]) -> List[Optional[FrozenSet[int]]]:
    if policy.subjects is ALL:
        return [None]
    return [frozenset([a]) for s in sorted(policy.subjects) for a in binding.get(s, ())]


def phi_res(policy: Policy, binding, version: int = 4) -> Table:
    t = Table("res", "first", 32)
    for at in policy.atoms:
        at = map_atom(at, version)
        for src in _srcs(policy, binding):
            for pr in sorted(at.protos):
                t.rules.append(Rule(0, src, at.dst, frozenset([pr]), ("range", at.lo, at.hi), _dir(at.dir), "acc"))
    return t


def phi_ent(policy: Policy, binding, version: int = 4) -> Table:
    t = Table("ent", "prio", 32)
    for at in policy.atoms:
        at = map_atom(at, version)
        for src in _srcs(policy, binding):
            for pr in sorted(at.protos):
                for v, m in range_to_masks(at.lo, at.hi):
                    t.rules.append(Rule(1000, src, at.dst, frozenset([pr]), ("mask", v, m), _dir(at.dir), "acc"))
    return t


def phi_mob(policy: Policy, binding, version: int = 6) -> Table:
    t = Table("mob", "prio", 128)
    for at in policy.atoms:
        at = map_atom(at, version)
        for src in _srcs(policy, binding):
            t.rules.append(Rule(1000, src, at.dst, at.protos, ("range", at.lo, at.hi), _dir(at.dir), "acc"))
    return t


TRANSLATORS = {"res": (phi_res, 4), "ent": (phi_ent, 4), "mob": (phi_mob, 6)}


def translate(domain: str, policy: Policy, binding) -> Table:
    fn, ver = TRANSLATORS[domain]
    return fn(policy, binding, ver)


# --------------------------------------------------------------------------- renderers

PNAME = {6: "tcp", 17: "udp"}


def _ip(a: int, width: int) -> str:
    return str(ipaddress.IPv4Address(a) if width == 32 else ipaddress.IPv6Address(a))


def render(t: Table, chain: str = "IILS-DEV") -> List[str]:
    lines = []
    for r in t.ordered():
        src = "" if r.src is None else _ip(next(iter(r.src)), t.width)
        pr = PNAME.get(next(iter(r.protos)), "ip") if r.protos else "ip"
        if t.domain == "res":
            d = "" if r.dir is None else (" -m conntrack --ctdir ORIGINAL" if r.dir else " -m conntrack --ctdir REPLY")
            lines.append(f"-A {chain} -s {src} -d {r.dst} -p {pr} --dport {r.ports[1]}:{r.ports[2]}{d} -j ACCEPT")
        elif t.domain == "ent":
            lines.append(f"priority={r.prio},{pr},nw_src={src},nw_dst={r.dst},tp_dst={r.ports[1]:#06x}/{r.ports[2]:#06x},actions=resubmit(,1)")
        else:
            lines.append(f'{{"table":"iils_acl","priority":{r.prio},"match":{{"src":"{src}","dst":"{r.dst}","dport":[{r.ports[1]},{r.ports[2]}]}},"action":"permit"}}')
    if t.domain == "res":
        lines.append(f"-A {chain} -j DROP")
    elif t.domain == "ent":
        lines.append("priority=0,actions=drop")
    else:
        lines.append('{"table":"iils_acl","default_action":"deny"}')
    return lines
