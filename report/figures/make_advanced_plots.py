"""Advanced results plots (comparisons / improvements / depth). Print-friendly, grayscale-safe.
    python report/figures/make_advanced_plots.py
"""
import json, re, collections, pathlib, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))
OUT = ROOT / "report" / "figures"
DARK, MID, LIGHT, ACCENT = "#2f3b52", "#5b6b86", "#c9d0da", "#b23a48"

def blast_radius():
    """Rule 9 cross-boundary composition: an identity's open reach collapses as 6/7/8 pass."""
    stages = ["no upstream\ncontainment", "+ rule 6\n(IMDS)", "+ rule 7\n(ctrl-plane)", "+ rule 8\n(VPN pivot)"]
    reach = [3, 2, 1, 0]
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.fill_between(range(4), reach, step="mid", color=LIGHT, alpha=0.7)
    ax.step(range(4), reach, where="mid", color=DARK, linewidth=2.4, marker="o", markersize=9)
    for x, y in enumerate(reach):
        ax.annotate(f"{y}", (x, y), (x, y + 0.12), ha="center", fontsize=12, fontweight="bold", color=DARK)
    dropped = ["", "imds", "control-plane", "vpn-pivot"]
    for x in range(1, 4):
        ax.annotate(f"-{dropped[x]}", (x, reach[x] + 0.5), ha="center", fontsize=8, color=ACCENT)
    ax.set_xticks(range(4)); ax.set_xticklabels(stages, fontsize=9)
    ax.set_ylabel("stolen credential's open\ncross-boundary reach (tags)")
    ax.set_ylim(-0.3, 3.6); ax.set_yticks([0, 1, 2, 3])
    ax.set_title("Blast-radius collapse: rule 9 composes 6/7/8 so a stolen credential's\n"
                 "reachable boundary shrinks to zero as each upstream control holds", fontsize=11, pad=10)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(OUT / "blast_radius.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote blast_radius.png")

def detection_budget():
    """Observed detection latency as a fraction of each rule's SLA budget (all within budget)."""
    # from `python -m validation.measure_sla` (observed s, target s); rule5 is pre-deployment
    data = {1: (12, 60), 2: (180, 300), 3: (15, 60), 4: (8, 60), 5: (0, 0),
            6: (20, 60), 7: (30, 60), 8: (24, 60), 9: (10, 60)}
    rules = list(data)
    pct = [100 * o / t if t else 0 for o, t in (data[r] for r in rules)]
    labels = [f"R{r}" for r in rules]
    fig, ax = plt.subplots(figsize=(9, 4.6))
    bars = ax.bar(labels, pct, color=MID, edgecolor=DARK)
    ax.axhline(100, color=ACCENT, linestyle="--", linewidth=1.5)
    ax.text(8.4, 102, "SLA budget", color=ACCENT, fontsize=9, va="bottom", ha="right")
    for r, b, p in zip(rules, bars, pct):
        o, t = data[r]
        cap = "pre-deploy" if t == 0 else f"{o}s/{t}s"
        ax.text(b.get_x() + b.get_width()/2, p + 2, cap, ha="center", fontsize=7.5, color=DARK)
    ax.set_ylabel("% of detection-SLA budget used")
    ax.set_ylim(0, 115); ax.set_title("Detection speed vs SLA: every rule alerts well inside its budget "
                                      "(rule 5 blocks at pre-deploy, not runtime)", fontsize=11, pad=10)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(OUT / "detection_budget.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote detection_budget.png")

def redteam_depth():
    """Red-team findings closed per boundary (parsed from RED_TEAM.md)."""
    c = collections.Counter()
    for l in (ROOT / "RED_TEAM.md").read_text().splitlines():
        if not l.startswith("| "): continue
        fid = l.split("|")[1].strip()
        if fid in ("#", "") or fid.startswith("-"): continue
        if fid.startswith("runner"): c["infra"] += 1
        else:
            m = re.match(r"(\d+)", fid)
            if m: c[f"rule {m.group(1)}"] += 1
    items = sorted(c.items(), key=lambda kv: kv[1])
    labels = [k for k, _ in items]; vals = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(labels, vals, color=[DARK if "rule" in k else MID for k in labels], edgecolor="white")
    for b, v in zip(bars, vals):
        ax.text(v + 0.1, b.get_y() + b.get_height()/2, str(v), va="center", fontsize=10, fontweight="bold", color=DARK)
    ax.set_xlabel("distinct false-negative bypasses found and closed")
    ax.set_title(f"Red-team depth: {sum(vals)} bypasses closed across the boundaries\n"
                 "(rule 8 encoding evasion + rule 2/9 the deepest)", fontsize=11, pad=10)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.set_xlim(0, max(vals) + 1)
    fig.tight_layout(); fig.savefig(OUT / "redteam_depth.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote redteam_depth.png")

def vuln_coverage():
    """Map our controls onto arXiv:2607.25379's 5 vulnerability classes - full coverage."""
    classes = ["multi-step\noffensive chains", "objectives vs\nsandbox", "supply-chain &\ncredential exposure",
               "persistent\ncommand-and-control", "speed of\nautomated action"]
    cols = [f"R{i}" for i in range(1, 10)] + ["quarantine"]
    cover = {0: [4, 5, 7], 1: [3], 2: [1, 6, 9], 3: [2, 8], 4: ["Q"]}
    fig, ax = plt.subplots(figsize=(9, 4.4))
    for ci in range(5):
        for xj, col in enumerate(cols):
            rid = col[1:] if col.startswith("R") else "Q"
            hit = (rid == "Q" and "Q" in cover[ci]) or (rid.isdigit() and int(rid) in cover[ci])
            ax.add_patch(plt.Rectangle((xj, 4 - ci), 1, 1, facecolor=DARK if hit else "#eef1f5",
                                       edgecolor="white", linewidth=2))
            if hit:
                ax.text(xj + 0.5, 4 - ci + 0.5, "OK", ha="center", va="center", color="white", fontsize=8, fontweight="bold")
    ax.set_xlim(0, 10); ax.set_ylim(0, 5)
    ax.set_xticks([j + 0.5 for j in range(10)]); ax.set_xticklabels(cols, fontsize=8.5)
    ax.set_yticks([4 - i + 0.5 for i in range(5)]); ax.set_yticklabels(classes, fontsize=8.5)
    ax.tick_params(length=0); [ax.spines[s].set_visible(False) for s in ax.spines]
    ax.set_title("Coverage of arXiv:2607.25379's 5 vulnerability classes: 9 controls cover classes 1-4,\n"
                 "the action-rate quarantine covers class 5 (speed) - every class addressed", fontsize=10.5, pad=10)
    fig.tight_layout(); fig.savefig(OUT / "vuln_coverage.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote vuln_coverage.png")

if __name__ == "__main__":
    blast_radius(); detection_budget(); redteam_depth(); vuln_coverage()
