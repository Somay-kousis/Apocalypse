# Figures

Reproducible generators (deterministic, print-friendly, grayscale-safe, no keys).

| File | Generator | What it shows |
|------|-----------|---------------|
| `trust_boundaries.png` | `make_trust_boundaries.py` | The July-2026 kill chain across 5 trust zones, each of the 9 rules pinned to the edge it closes |
| `scorecard.png` | `make_plots.py` | 9 controls x 4 targets: hardened 9/9, every attacker config 0/9 (the core "it works" proof) |
| `quarantine_timing.png` | `make_plots.py` | Headline number: action-rate quarantine fires ~41.6h before the Day-3 spike, with the 500/1000/2000 sensitivity band |
| `detection_quality.png` | `make_plots.py` | Detection confusion matrix over 36 cases: 18 TP / 0 FP / 0 FN / 18 TN |

Regenerate all: `python report/figures/make_trust_boundaries.py && python report/figures/make_plots.py`
Data is computed live from the labs and `analysis/data/incident_public_record.json`; the
detection-quality aggregate comes from `python -m validation.evaluate_detection`.

## Advanced (comparison / depth) - `make_advanced_plots.py`
| File | What it shows |
|------|---------------|
| `blast_radius.png` | Cross-boundary composition: a stolen credential's open reach collapses 3->2->1->0 as rules 6/7/8 hold (rule 9's depth) |
| `detection_budget.png` | Detection speed vs each rule's SLA budget - every rule alerts well inside budget |
| `redteam_depth.png` | 28 distinct false-negative bypasses found and closed, per boundary (where the hard bugs were) |
| `vuln_coverage.png` | Our controls mapped onto arXiv:2607.25379's 5 vulnerability classes - full coverage (class 5 by the quarantine) |

Regenerate advanced: `python report/figures/make_advanced_plots.py`
