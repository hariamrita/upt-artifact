"""Summarise testbed JSON-lines logs (see testbed/README.md) and emit LaTeX rows.

Usage: python testbed/analyze.py logs/*.jsonl > results/testbed_summary.json
"""
import json
import random
import statistics
import sys
from collections import defaultdict

PAIRS = {
    "rq1": [("ES-SPA handshake + MTD tunnel (mobile)", "spa_mtd"), ("IILS parsing and admission", "parse"),
            ("Composition + placement", "compose"), ("Verification (Z3)", "verify"),
            ("DNOS recomputation (enterprise)", "dnos"), ("OpenFlow + eBPF installation", "of_ebpf"),
            ("WireGuard peer push (residential)", "wg")],
}


def ci95(xs, b=2000, seed=1):
    rng = random.Random(seed)
    means = sorted(statistics.mean(rng.choices(xs, k=len(xs))) for _ in range(b))
    return means[int(0.025 * b)], means[int(0.975 * b)]


def stats(xs):
    xs = sorted(xs)
    lo, hi = ci95(xs)
    return {"n": len(xs), "mean": statistics.mean(xs), "median": statistics.median(xs),
            "p95": xs[min(len(xs) - 1, int(0.95 * len(xs)))], "ci95": [lo, hi]}


def main(paths):
    ev = defaultdict(dict)  # (exp, run, n) -> stage -> t
    flows = defaultdict(list)
    for p in paths:
        for line in open(p):
            if not line.strip():
                continue
            e = json.loads(line)
            key = (e["exp"], e["run"], e.get("n"), e.get("scenario"), e.get("mode"))
            if e["stage"] == "malicious_flow":
                flows[key].append(bool(e.get("reached_target")))
            else:
                ev[key][e["stage"]] = e["t"]
    out = {}
    # RQ1 and RQ2: per-stage durations in ms
    for exp in ("rq1", "rq2"):
        groups = defaultdict(lambda: defaultdict(list))
        for (x, run, n, _, _), st in ev.items():
            if x != exp:
                continue
            for _, s in PAIRS["rq1"]:
                if f"{s}_start" in st and f"{s}_end" in st:
                    groups[n][s].append(1e3 * (st[f"{s}_end"] - st[f"{s}_start"]))
            ends = [v for k, v in st.items() if k.endswith("_end")]
            if "spa_mtd_start" in st and ends:
                groups[n]["T_converge"].append(1e3 * (max(ends) - st["spa_mtd_start"]))
        out[exp] = {str(n): {s: stats(v) for s, v in g.items() if v} for n, g in groups.items()}
    # RQ4: revocation latency and flows reaching the target
    rq4 = defaultdict(lambda: {"T_rev": [], "reached": 0, "flows": 0})
    for (x, run, _, sc, mode), st in ev.items():
        if x != "rq4":
            continue
        if "detect" in st and "target_install_end" in st:
            rq4[(sc, mode)]["T_rev"].append(1e3 * (st["target_install_end"] - st["detect"]))
        f = flows.get((x, run, None, sc, mode), [])
        rq4[(sc, mode)]["reached"] += sum(f)
        rq4[(sc, mode)]["flows"] += len(f)
    out["rq4"] = {f"{sc}/{mode}": {"T_rev": stats(v["T_rev"]) if v["T_rev"] else None,
                                   "reached": v["reached"], "flows": v["flows"]} for (sc, mode), v in rq4.items()}
    print(json.dumps(out, indent=1))
    # LaTeX rows for Table IV (RQ1)
    r1 = out.get("rq1", {}).get("None", {})
    for label, s in PAIRS["rq1"] + [("$T_{\\mathrm{converge}}$", "T_converge")]:
        if s in r1:
            v = r1[s]
            print(f"% {label} & {v['mean']:.1f} & {v['p95']:.1f} & [{v['ci95'][0]:.1f}, {v['ci95'][1]:.1f}] \\\\",
                  file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
