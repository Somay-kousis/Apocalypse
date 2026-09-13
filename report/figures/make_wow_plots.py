"""Hero figures with striking shapes (area / flow / radial). Still honest data,
print-friendly. Exotic form; pair with the clear plots for the actual results section.
    python report/figures/make_wow_plots.py
"""
import json, re, collections, pathlib, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))
OUT = ROOT / "report" / "figures"
DARK, MID, LIGHT, ACCENT, GOLD = "#1f2a3c", "#5b6b86", "#c9d0da", "#b23a48", "#c98a2b"

def cumulative_prevented():
    """Flowing area: cumulative attacker actions over 4.5 days; the region after the
    ~6.4h quarantine trigger is the volume that would have been prevented."""
    rec = json.loads((ROOT / "analysis/data/incident_public_record.json").read_text())
    counts = [d["actions"] for d in rec["days"]]
    hours = np.arange(0, 120 + 1)                       # 5 days hourly
    rate = np.concatenate([[counts[d] / 24] * 24 for d in range(5)] + [[0]])
    cum = np.cumsum(rate)
    trig_h = 1000 / counts[0] * 24                      # quarantine at threshold 1000/identity/day
    total = cum[-1]; prevented = total - 1000
    fig, ax = plt.subplots(figsize=(11, 5.2))
    # allowed sliver (before trigger) vs prevented region (after)
    mask = hours <= trig_h
    ax.fill_between(hours, cum, where=hours <= trig_h + 1, color=MID, alpha=0.9)
    ax.fill_between(hours, cum, where=hours >= trig_h, color=ACCENT, alpha=0.28)
    ax.plot(hours, cum, color=DARK, linewidth=2.6)
    ax.axvline(trig_h, color=ACCENT, linestyle="--", linewidth=1.6)
    ax.annotate(f"quarantine fires ~{trig_h:.1f}h\n(1,000 actions / identity)",
                (trig_h, total * 0.5), (trig_h + 6, total * 0.42), fontsize=9, color=ACCENT,
                arrowprops=dict(arrowstyle="->", color=ACCENT))
    ax.annotate(f"~{prevented:,.0f} of {total:,.0f} actions\n(~{100*prevented/total:.0f}%) never happen\nunder early quarantine",
                (75, total * 0.62), fontsize=12, color=DARK, fontweight="bold", ha="center")
    for d in range(5):
        ax.text(d * 24 + 12, -total * 0.05, rec["days"][d]["date"][5:], ha="center", fontsize=8, color=MID)
    ax.set_xlim(0, 120); ax.set_ylim(0, total * 1.05)
    ax.set_xlabel("hours since first foothold"); ax.set_ylabel("cumulative attacker actions")
    ax.set_title("What early quarantine buys: the shaded region is the attack that never runs\n"
                 "once a per-identity action-rate threshold trips on Day 1", fontsize=11, pad=10)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(OUT / "cumulative_prevented.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote cumulative_prevented.png")

def killchain_flow():
    """Ribbon flow on one shared axis: the same 9 boundaries, two postures. Broken flows
    full-width to the crown jewels; hardened tapers to nothing at the first boundary."""
    stages = ["registry", "egress", "sandbox", "hdf5", "jinja", "imds", "ctrl-plane",
              "tailscale", "creds", "crown\njewels"]
    x = np.linspace(0, 9, 400)
    fig, ax = plt.subplots(figsize=(12, 5.2))
    # BROKEN: constant full-width band, top lane
    ax.fill_between(x, 2.15, 2.95, color=ACCENT, alpha=0.35)
    ax.plot(x, np.full_like(x, 2.95), color=ACCENT, lw=2); ax.plot(x, np.full_like(x, 2.15), color=ACCENT, lw=2)
    ax.annotate("", (9.35, 2.55), (9.0, 2.55), arrowprops=dict(arrowstyle="-|>", color=ACCENT, lw=3))
    ax.text(4.5, 3.15, "BROKEN - flows through every boundary to the crown jewels",
            color=ACCENT, fontsize=11, ha="center", fontweight="bold")
    # HARDENED: bottom lane tapering to ~0 by the first boundary, same x-scale
    h = np.where(x < 1.0, 0.8 * (1.0 - x) + 0.02, 0.02)
    ax.fill_between(x, 0.0, h, color=DARK, alpha=0.55)
    ax.plot(x, h, color=DARK, lw=2)
    ax.annotate("severed here", (1.0, 0.05), (1.8, 0.7), color=DARK, fontsize=9,
                arrowprops=dict(arrowstyle="->", color=DARK))
    ax.text(4.5, 0.95, "HARDENED - each control severs its own step; contained at boundary 1",
            color=DARK, fontsize=11, ha="center", fontweight="bold")
    for xi, stg in enumerate(stages):
        ax.axvline(xi, color="#e6e9ee", lw=1, zorder=0)
        ax.text(xi, 3.55, stg, ha="center", va="bottom", fontsize=8, color=MID)
    ax.set_xlim(-0.3, 9.8); ax.set_ylim(-0.2, 3.9); ax.axis("off")
    ax.set_title("Kill-chain flow: same 9 boundaries, two postures", fontsize=12, pad=30)
    fig.tight_layout(); fig.savefig(OUT / "killchain_flow.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote killchain_flow.png")


def redteam_radial():
    """Polar bars: red-team bypasses closed per boundary."""
    c = collections.Counter()
    for l in (ROOT / "RED_TEAM.md").read_text().splitlines():
        if not l.startswith("| "): continue
        fid = l.split("|")[1].strip()
        if fid in ("#", "") or fid.startswith("-"): continue
        key = "infra" if fid.startswith("runner") else (re.match(r"(\d+)", fid) and f"R{re.match(r'(\d+)', fid).group(1)}")
        if key: c[key] += 1
    order = [f"R{i}" for i in range(1, 10)] + ["infra"]
    vals = [c.get(k, 0) for k in order]
    ang = np.linspace(0, 2 * np.pi, len(order), endpoint=False)
    fig = plt.figure(figsize=(7.5, 7.5)); ax = fig.add_subplot(111, polar=True)
    bars = ax.bar(ang, vals, width=2 * np.pi / len(order) * 0.9,
                  color=[DARK if k != "infra" else MID for k in order], edgecolor="white")
    ax.set_xticks(ang); ax.set_xticklabels(order, fontsize=10)
    ax.set_yticks(range(0, max(vals) + 1, 2)); ax.set_yticklabels([str(v) for v in range(0, max(vals)+1, 2)], fontsize=7)
    for a, v in zip(ang, vals):
        if v: ax.text(a, v + 0.3, str(v), ha="center", va="center", fontsize=10, fontweight="bold", color=DARK)
    ax.set_title(f"Red-team depth (radial): {sum(vals)} bypasses closed across boundaries", fontsize=12, pad=24)
    fig.tight_layout(); fig.savefig(OUT / "redteam_radial.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote redteam_radial.png")

if __name__ == "__main__":
    cumulative_prevented(); killchain_flow(); redteam_radial()
