"""
Generates the workshop paper's results figures as SEPARATE files - one PNG
per plot, each usable standalone. Replaces the old make_plots.py /
make_advanced_plots.py / make_wow_plots.py / make_paper_figure.py.

Every figure here is a plain bar, horizontal bar, line, or step chart -
nothing that needs a legend to know which color is "good". Reference/marker
lines are kept clear of the data they annotate (no dashed lines cutting
through bars or fills).

Run with:
    python report/figures/make_paper_figures.py

Requires: matplotlib, numpy. Reads:
    RED_TEAM.md
    analysis/data/incident_public_record.json
Writes, into report/figures/:
    fig_detection_budget.png
    fig_attack_volume.png
    fig_quarantine_sensitivity.png
    fig_blast_radius.png
    fig_redteam_depth.png
    fig_cumulative_prevented.png
"""
import json, re, collections, pathlib, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "report" / "figures"

DARK, MID, LIGHT, ACCENT = "#2f3b52", "#5b6b86", "#c9d0da", "#b23a48"
plt.rcParams.update({
    "font.size": 11.5,
    "axes.titlesize": 12.5,
    "axes.titleweight": "bold",
    "figure.facecolor": "white",
    "axes.edgecolor": "#3a3a3a",
})


def _clean(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def _save(fig, name):
    fig.tight_layout()
    path = OUT / name
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {path}")


# ---------------------------------------------------------------- 1
def fig_detection_budget():
    """Detection latency vs SLA, per rule."""
    data = {1: (12, 60), 2: (180, 300), 3: (15, 60), 4: (8, 60), 5: (0, 0),
            6: (20, 60), 7: (30, 60), 8: (24, 60), 9: (10, 60)}
    rules = list(data)
    pct = [100 * o / t if t else 0 for o, t in (data[r] for r in rules)]
    labels = [f"R{r}" for r in rules]

    fig, ax = plt.subplots(figsize=(7.5, 5))
    bars = ax.bar(labels, pct, color=MID, edgecolor=DARK)
    # SLA reference line sits above every bar - never crosses through one.
    ax.axhline(100, color=ACCENT, linestyle="--", linewidth=1.4, zorder=1)
    ax.text(8.35, 103, "SLA budget", color=ACCENT, fontsize=9.5, ha="right", va="bottom")
    for b, p, r in zip(bars, pct, rules):
        o, t = data[r]
        cap = "pre-deploy" if t == 0 else f"{o}s / {t}s"
        ax.text(b.get_x() + b.get_width() / 2, p + 3, cap, ha="center", fontsize=8.5, color=DARK)
    ax.set_ylabel("% of detection-SLA budget used")
    ax.set_ylim(0, 122)
    ax.set_title("Detection latency vs. SLA budget\nevery rule alerts well inside its budget")
    _clean(ax)
    _save(fig, "fig_detection_budget.png")


# ---------------------------------------------------------------- 2
def fig_attack_volume(rec):
    """Attacker actions per day, with the quarantine-trigger moment called
    out by an arrow that points AT the bar rather than a line drawn
    THROUGH it, so the bar's own shape and value stay fully readable."""
    days = rec["days"]
    labels = [d["date"][5:] for d in days]
    counts = [d["actions"] for d in days]
    colors = [MID] * len(counts)
    colors[2] = DARK  # spike day

    fig, ax = plt.subplots(figsize=(7.5, 5))
    bars = ax.bar(labels, counts, color=colors, edgecolor=DARK, zorder=2)
    ax.annotate("quarantine fires\n~6.4h into Day 1\n(1,000 actions/\nidentity)",
                xy=(0, counts[0]), xytext=(-0.42, max(counts) * 1.02),
                fontsize=9.5, color=ACCENT, ha="left", va="top",
                arrowprops=dict(arrowstyle="->", color=ACCENT, lw=1.4),
                zorder=3)
    ax.annotate("Day-3 spike\n7,677 actions", xy=(2, counts[2]),
                xytext=(2.55, counts[2] * 0.92), fontsize=9.5, color=DARK, ha="left",
                arrowprops=dict(arrowstyle="->", color=DARK, lw=1.2))
    ax.set_ylabel("attacker actions / day (public record)")
    ax.set_ylim(0, max(counts) * 1.28)
    ax.set_title("Attack volume by day")
    _clean(ax)
    _save(fig, "fig_attack_volume.png")


# ---------------------------------------------------------------- 3
def fig_quarantine_sensitivity(rec):
    """How much earlier a stricter per-identity rate threshold fires."""
    day1 = rec["days"][0]["actions"]
    thresholds = [500, 1000, 2000]
    hours_before = [48 - (t / day1 * 24) for t in thresholds]

    fig, ax = plt.subplots(figsize=(7.5, 5))
    colors = [LIGHT, DARK, LIGHT]
    bars = ax.bar([str(t) for t in thresholds], hours_before, color=colors, edgecolor=DARK)
    for b, h in zip(bars, hours_before):
        ax.text(b.get_x() + b.get_width() / 2, h + 1, f"{h:.1f}h", ha="center", fontsize=10.5)
    ax.set_ylabel("hours before Day-3 spike")
    ax.set_xlabel("threshold (actions / identity / day)")
    ax.set_ylim(0, 52)
    ax.set_title("Earlier quarantine, by threshold\n1,000/identity/day fires 41.6h before the spike")
    _clean(ax)
    _save(fig, "fig_quarantine_sensitivity.png")


# ---------------------------------------------------------------- 4
def fig_blast_radius():
    """Step chart: stolen credential's reachable boundary shrinks to zero."""
    stages = ["no upstream\ncontainment", "+ rule 6\n(IMDS)", "+ rule 7\n(ctrl-plane)", "+ rule 8\n(VPN pivot)"]
    reach = [3, 2, 1, 0]

    fig, ax = plt.subplots(figsize=(7.5, 5))
    ax.fill_between(range(4), reach, step="mid", color=LIGHT, alpha=0.7)
    ax.step(range(4), reach, where="mid", color=DARK, linewidth=2.4, marker="o", markersize=9)
    for x, y in enumerate(reach):
        ax.annotate(f"{y}", (x, y), (x, y + 0.15), ha="center", fontsize=12, fontweight="bold", color=DARK)
    ax.set_xticks(range(4))
    ax.set_xticklabels(stages, fontsize=9.5)
    ax.set_ylabel("stolen credential's open\ncross-boundary reach (tags)")
    ax.set_ylim(-0.3, 3.6)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_title("Blast-radius collapse\nreach shrinks to zero as each upstream control holds")
    _clean(ax)
    _save(fig, "fig_blast_radius.png")


# ---------------------------------------------------------------- 5
def fig_redteam_depth():
    """Horizontal bar: red-team bypasses closed per boundary."""
    c = collections.Counter()
    for line in (ROOT / "RED_TEAM.md").read_text().splitlines():
        if not line.startswith("| "):
            continue
        fid = line.split("|")[1].strip()
        if fid in ("#", "") or fid.startswith("-"):
            continue
        if fid.startswith("runner"):
            c["infra"] += 1
        else:
            m = re.match(r"(\d+)", fid)
            if m:
                c[f"rule {m.group(1)}"] += 1
    items = sorted(c.items(), key=lambda kv: kv[1])
    labels = [k for k, _ in items]
    vals = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    bars = ax.barh(labels, vals, color=[DARK if "rule" in k else MID for k in labels], edgecolor="white")
    for b, v in zip(bars, vals):
        ax.text(v + 0.1, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=10.5, fontweight="bold", color=DARK)
    ax.set_xlabel("distinct false-negative bypasses found and closed")
    ax.set_xlim(0, max(vals) + 1.2)
    ax.set_title(f"Red-team depth: {sum(vals)} bypasses closed\nrule 8 encoding evasion + rule 2/9 the deepest")
    _clean(ax)
    _save(fig, "fig_redteam_depth.png")


# ---------------------------------------------------------------- 6
def fig_cumulative_prevented(rec):
    """Cumulative attacker actions over time; line + shaded 'prevented' area.
    The trigger line sits at the natural boundary between the two fills, so
    it marks a transition rather than cutting across a single color block."""
    counts = [d["actions"] for d in rec["days"]]
    hours = np.arange(0, 120 + 1)
    rate = np.concatenate([[counts[d] / 24] * 24 for d in range(5)] + [[0]])
    cum = np.cumsum(rate)
    day1 = counts[0]
    trig_h = 1000 / day1 * 24
    total = cum[-1]
    prevented = total - 1000

    ymax = total * 1.08
    trig_y = float(np.interp(trig_h, hours, cum))

    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.fill_between(hours, cum, where=hours <= trig_h + 1, color=MID, alpha=0.9, zorder=2,
                     label="actions before quarantine")
    ax.fill_between(hours, cum, where=hours >= trig_h, color=ACCENT, alpha=0.25, zorder=1,
                     label="actions prevented")
    ax.plot(hours, cum, color=DARK, linewidth=2.4, zorder=3)
    # Marker line only reaches up to the curve itself, not the full axis height,
    # so it doesn't cut across the annotation text sitting above it.
    ax.axvline(trig_h, ymin=0, ymax=trig_y / ymax, color=ACCENT, linestyle="--", linewidth=1.3, zorder=1)
    ax.annotate(f"quarantine fires ~{trig_h:.1f}h\n(1,000 actions/identity)",
                xy=(trig_h, trig_y), xytext=(14, total * 0.40),
                fontsize=9.5, color=ACCENT, ha="left",
                arrowprops=dict(arrowstyle="->", color=ACCENT, lw=1.2))
    ax.annotate(f"~{prevented:,.0f} of {total:,.0f} actions\n(~{100*prevented/total:.0f}%) never happen",
                xy=(48, total * 0.92), fontsize=12, color=DARK, fontweight="bold", ha="center")
    ax.set_xticks([0, 24, 48, 72, 96, 120])
    ax.set_xlim(0, 120)
    ax.set_ylim(0, ymax)
    ax.set_xlabel("hours since first foothold")
    ax.set_ylabel("cumulative attacker actions")
    ax.set_title("What early quarantine buys")
    ax.legend(loc="lower right", fontsize=9.5, frameon=False)
    _clean(ax)
    _save(fig, "fig_cumulative_prevented.png")


def main():
    rec = json.loads((ROOT / "analysis/data/incident_public_record.json").read_text())
    fig_detection_budget()
    fig_attack_volume(rec)
    fig_quarantine_sensitivity(rec)
    fig_blast_radius()
    fig_redteam_depth()
    fig_cumulative_prevented(rec)


if __name__ == "__main__":
    main()
