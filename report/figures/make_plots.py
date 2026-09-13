"""Reproducible generators for the paper's results plots. Print-friendly (light bg,
grayscale-safe). Data is computed live where possible; detection-quality aggregates
are regenerated with `python -m validation.evaluate_detection`.
    python report/figures/make_plots.py
"""
import io, contextlib, json, pathlib, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "report" / "figures"
LABS = [("fixed_lab", "Hardened"), ("broken_lab", "July-2026\nmisconfig"),
        ("exploit_lab", "Attacker\nconfigs r1"), ("adversarial_lab", "Attacker\nconfigs r2")]
RULES = ["1 registry", "2 egress", "3 sandbox", "4 hdf5", "5 jinja",
         "6 imds", "7 ctrl-plane", "8 tailscale", "9 creds"]

PASS_C, FAIL_C = "#2f3b52", "#e9ecf1"   # dark slate vs light; distinguishable in grayscale

def _scorecard():
    from validation.run_checks import run
    grid = {}
    for lab, _ in LABS:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            res = run(str(ROOT / f"environments/{lab}/configs"))
        grid[lab] = {r.rule_id: r.status for r in res}

    fig, ax = plt.subplots(figsize=(8.5, 6))
    for j, (lab, _) in enumerate(LABS):
        for i in range(9):
            st = grid[lab].get(i + 1, "SKIP")
            passed = st == "PASS"
            ax.add_patch(plt.Rectangle((j, 8 - i), 1, 1, facecolor=PASS_C if passed else FAIL_C,
                                       edgecolor="white", linewidth=2))
            ax.text(j + 0.5, 8 - i + 0.5, "PASS" if passed else "FAIL",
                    ha="center", va="center", fontsize=8,
                    color="white" if passed else "#8a94a6", fontweight="bold")
    ax.set_xlim(0, 4); ax.set_ylim(0, 9)
    ax.set_xticks([j + 0.5 for j in range(4)]); ax.set_xticklabels([n for _, n in LABS], fontsize=9)
    ax.set_yticks([8 - i + 0.5 for i in range(9)]); ax.set_yticklabels(RULES, fontsize=9)
    ax.tick_params(length=0); [ax.spines[s].set_visible(False) for s in ax.spines]
    ax.set_title("Containment scorecard: 9 controls x 4 targets\n"
                 "hardened 9/9, every attacker config 0/9 (offline, no lab access)", fontsize=11, pad=12)
    ax.legend(handles=[Patch(facecolor=PASS_C, label="control holds (PASS)"),
                       Patch(facecolor=FAIL_C, edgecolor="#c9d0da", label="boundary open (FAIL)")],
              loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=2, frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(OUT / "scorecard.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote scorecard.png")

def _quarantine():
    rec = json.loads((ROOT / "analysis/data/incident_public_record.json").read_text())
    days = rec["days"]; labels = [d["date"][5:] for d in days]; counts = [d["actions"] for d in days]
    day1 = counts[0]
    band = {t: 48 - (t / day1 * 24) for t in (500, 1000, 2000)}

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4.6), gridspec_kw={"width_ratios": [1.5, 1]})
    bars = a1.bar(labels, counts, color=["#c9d0da"] * len(counts), edgecolor="#2f3b52")
    bars[2].set_color("#2f3b52")  # Day-3 spike
    a1.annotate("Day-3 spike\n7,677 actions", (2, counts[2]), (2.1, counts[2] - 1800),
                fontsize=9, ha="left", color="#2f3b52",
                arrowprops=dict(arrowstyle="->", color="#2f3b52"))
    a1.axvline(0.0 + 6.35/24 - 0.4, color="#b23", linestyle="--", linewidth=1.4)
    a1.text(0.02, max(counts) * 0.96, "quarantine fires\n~6.4h into Day 1\n(1,000/identity/day)",
            fontsize=8, color="#b23", va="top")
    a1.set_ylabel("attacker actions (public record)"); a1.set_title("Action volume per day", fontsize=11)
    a1.spines["top"].set_visible(False); a1.spines["right"].set_visible(False)

    ts = list(band.keys()); hs = [band[t] for t in ts]
    b = a2.bar([str(t) for t in ts], hs, color=["#c9d0da", "#2f3b52", "#c9d0da"], edgecolor="#2f3b52")
    for rect, h in zip(b, hs):
        a2.text(rect.get_x() + rect.get_width()/2, h + 0.6, f"{h:.1f}h", ha="center", fontsize=9)
    a2.set_ylabel("hours before Day-3 spike"); a2.set_xlabel("threshold (actions / identity / day)")
    a2.set_title("Earlier-quarantine sensitivity band", fontsize=11); a2.set_ylim(0, 52)
    a2.spines["top"].set_visible(False); a2.spines["right"].set_visible(False)
    fig.suptitle("Headline: a per-identity action-rate threshold would have triggered quarantine "
                 "41.6 h before the main-campaign spike", fontsize=11, y=1.02)
    fig.tight_layout(); fig.savefig(OUT / "quarantine_timing.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote quarantine_timing.png")

def _detection():
    # aggregate over 36 cases (18 attack + 18 benign) from `python -m validation.evaluate_detection`
    TP, FP, FN, TN = 18, 0, 0, 18
    cm = [[TP, FN], [FP, TN]]
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.imshow([[0.85, 0.15], [0.15, 0.85]], cmap="Greys", vmin=0, vmax=1, alpha=0.9)
    labs = [["TP", "FN"], ["FP", "TN"]]
    for i in range(2):
        for j in range(2):
            v = cm[i][j]
            ax.text(j, i, f"{labs[i][j]}\n{v}", ha="center", va="center", fontsize=13,
                    color="white" if (i == j) else "#2f3b52", fontweight="bold")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["flagged", "cleared"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["attack\ncase", "benign\ncase"])
    ax.set_title("Detection quality: 36 cases across 9 rules\n"
                 "0 false positives, 0 false negatives (independent observer)", fontsize=10, pad=10)
    ax.tick_params(length=0)
    fig.tight_layout(); fig.savefig(OUT / "detection_quality.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote detection_quality.png")

if __name__ == "__main__":
    _scorecard(); _quarantine(); _detection()
