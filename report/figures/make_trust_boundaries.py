"""Reproducible generator for the trust-boundary kill-chain figure.
Deterministic staged layout (no spring), 5 zone bands, rules on edges, grayscale-safe.
Data-driven from analysis/data/incident_public_record.json.
    python report/figures/make_trust_boundaries.py
"""
import json, pathlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = pathlib.Path(__file__).resolve().parents[2]
REC = json.loads((ROOT / "analysis/data/incident_public_record.json").read_text())

POS = {
    "eval_sandbox":  (0,  0.0, "Evaluation\nsandbox"),
    "pkg_registry":  (1,  0.0, "Package\nregistry proxy"),
    "public_net":    (2,  0.0, "Public\ninternet"),
    "party_sandbox": (3,  0.0, "3rd-party\nsandbox (uid=0)"),
    "hf_perimeter":  (4,  0.0, "HF dataset\nperimeter"),
    "hf_worker":     (5,  0.0, "Dataset\nworker"),
    "hf_k8s":        (6,  1.15, "K8s control\nplane / IMDS"),
    "hf_internal":   (6, -1.15, "Internal net\n(Tailscale)"),
}
ZONES = [
    ("OpenAI platform",   -0.55, 1.55, "0.90"),
    ("Public internet",    1.55, 2.55, "0.85"),
    ("3rd-party sandbox",  2.55, 3.55, "0.90"),
    ("HF perimeter",       3.55, 4.55, "0.85"),
    ("HF internal",        4.55, 6.75, "0.90"),
]
NW, NH = 0.62, 0.52

fig, ax = plt.subplots(figsize=(15, 8.5))
ax.set_xlim(-0.9, 7.6); ax.set_ylim(-2.6, 2.2); ax.axis("off")

for name, x0, x1, shade in ZONES:
    ax.add_patch(plt.Rectangle((x0, -2.55), x1 - x0, 4.7, facecolor=shade, edgecolor="0.75",
                               linewidth=1.0, linestyle="--", zorder=0))
    ax.text((x0 + x1) / 2, 2.02, name, ha="center", va="top", fontsize=11,
            style="italic", color="0.35", zorder=1)

def center(nid): return POS[nid][0], POS[nid][1]

for nid, (x, y, label) in POS.items():
    ax.add_patch(FancyBboxPatch((x - NW/2, y - NH/2), NW, NH,
                 boxstyle="round,pad=0.02,rounding_size=0.06",
                 facecolor="white", edgecolor="black", linewidth=1.6, zorder=3))
    ax.text(x, y, label, ha="center", va="center", fontsize=10, zorder=4)

def edge(a, b, label, rad=0.0, lx=None, ly=None):
    (x1, y1), (x2, y2) = center(a), center(b)
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                 connectionstyle=f"arc3,rad={rad}", arrowstyle="-|>", mutation_scale=18,
                 shrinkA=26, shrinkB=26, linewidth=1.7, color="black", zorder=2))
    if lx is None: lx, ly = (x1 + x2) / 2, (y1 + y2) / 2 + 0.16
    ax.text(lx, ly, label, ha="center", va="center", fontsize=9, zorder=5,
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="0.6", lw=0.8))

via = {e["rule"]: e["via"] for e in REC["trust_boundaries"]["edges"]}
def L(n): return f"[Rule {n}]\n{via[n]}"

edge("eval_sandbox", "pkg_registry", L(1))
edge("pkg_registry", "public_net",   L(2))
edge("public_net", "party_sandbox",  L(3))
edge("party_sandbox", "hf_perimeter",L(4))
edge("hf_perimeter", "hf_worker",    L(5))
edge("hf_worker", "hf_k8s",     L(6), rad=-0.15)
edge("hf_worker", "hf_internal",L(7), rad=0.15)
edge("hf_worker", "public_net", L(9), rad=-0.55, lx=3.5, ly=-1.45)
xi, yi = center("hf_internal")
ax.add_patch(FancyArrowPatch((xi+NW/2, yi+0.12), (xi+NW/2, yi-0.12),
             connectionstyle="arc3,rad=-1.6", arrowstyle="-|>", mutation_scale=14,
             shrinkA=1, shrinkB=1, linewidth=1.5, color="black", zorder=2))
ax.text(xi+0.72, yi, L(8), ha="left", va="center", fontsize=9, zorder=5,
        bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="0.6", lw=0.8))

ax.set_title("Incident Trust Boundaries and Containment Rules (July 2026)", fontsize=15, pad=14)
fig.tight_layout()
out = ROOT / "report/figures/trust_boundaries.png"
fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
print("saved", out)
