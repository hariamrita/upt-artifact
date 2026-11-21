"""Figure 3 of the paper from results/*.json (print figure, two panels, one column)."""
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BLUE, ORANGE = "#2a78d6", "#eb6834"  # validated categorical slots 1-2
INK, MUTED = "#0b0b0b", "#52514e"

plt.rcParams.update({"font.family": "serif", "font.size": 7, "axes.edgecolor": MUTED,
                     "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
                     "axes.linewidth": 0.6, "lines.linewidth": 1.2, "legend.frameon": False})

atoms = json.loads((ROOT / "results/rq2_atoms.json").read_text())
table = json.loads((ROOT / "results/rq2_table.json").read_text())

fig, (a, b) = plt.subplots(1, 2, figsize=(3.5, 1.85))
for path, col, mk in [("res-ent", BLUE, "o"), ("mob-ent-res", ORANGE, "s")]:
    rows = [r for r in atoms if r["path"] == path]
    k = [r["atoms"] for r in rows]
    a.plot(k, [1e3 * r["total"]["median"] for r in rows], color=col, marker=mk, ms=3,
           label=f"{path}, verified")
    a.plot(k, [1e3 * r["total_noverify"]["median"] for r in rows], color=col, marker=mk, ms=3,
           ls="--", mfc="white", label=f"{path}, no verif.")
a.set_xscale("log")
a.set_yscale("log")
a.set_xlabel("atoms per policy")
a.set_ylabel("grant time, median (ms)")
a.set_title("(a)", fontsize=7, color=INK)
a.grid(True, which="major", lw=0.3, color="#d9d8d4")


for kind, col, mk, lab in [("other-subject", BLUE, "o", "other subjects' rules"),
                            ("wildcard-source", ORANGE, "s", "wildcard-source rules")]:
    rows = [r for r in table if r["kind"] == kind and r["existing_rules"] > 0]
    b.plot([r["existing_rules"] for r in rows], [1e3 * r["median"] for r in rows], color=col,
           marker=mk, ms=3, label=lab)
b.set_xscale("log")
b.set_yscale("log")
b.set_xlabel("existing rules in table")
b.set_ylabel(r"$T_{\mathrm{ver}}$, median (ms)")
b.set_title("(b)", fontsize=7, color=INK)
b.grid(True, which="major", lw=0.3, color="#d9d8d4")
b.legend(fontsize=4.6, loc="upper left", labelspacing=0.25)
from matplotlib.ticker import FixedLocator, NullLocator, ScalarFormatter
b.yaxis.set_major_locator(FixedLocator([30, 50, 100, 200, 500]))
b.yaxis.set_minor_locator(NullLocator())
b.yaxis.set_major_formatter(ScalarFormatter())
for ax in (a, b):
    ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout(pad=0.3, w_pad=0.8, rect=(0, 0.13, 1, 1))
h, l = a.get_legend_handles_labels()
fig.legend(h, l, loc="lower left", bbox_to_anchor=(0.04, 0.0), ncol=2, fontsize=4.8, handlelength=2.4, columnspacing=1.2, labelspacing=0.2)
out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "fig_scale.pdf"
fig.savefig(out)
fig.savefig(out.with_suffix(".png"), dpi=200)
print(out)
