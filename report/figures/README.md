# Figures

Reproducible generators (deterministic, print-friendly, grayscale-safe, no keys).
Every results figure is its own standalone PNG - plain bar, horizontal bar,
line, or step charts only. Reference/marker lines never cut across the data
they annotate (SLA line sits above every bar; the quarantine-trigger line
only reaches up to the curve; annotation text sits in open space, not on
top of bars or lines).

| File | Generator | What it shows |
|------|-----------|---------------|
| `trust_boundaries.png` | `make_trust_boundaries.py` | The July-2026 kill chain across 5 trust zones, each of the 9 rules pinned to the edge it closes |
| `fig_detection_budget.png` | `make_paper_figures.py` | Detection latency vs. each rule's SLA budget (bar) |
| `fig_attack_volume.png` | `make_paper_figures.py` | Public-record attacker actions per day, quarantine-trigger and spike called out with arrows (bar) |
| `fig_quarantine_sensitivity.png` | `make_paper_figures.py` | How much earlier a stricter per-identity rate threshold fires: 500/1000/2000 (bar) |
| `fig_blast_radius.png` | `make_paper_figures.py` | Stolen credential's open cross-boundary reach: 3 -> 2 -> 1 -> 0 as rules 6/7/8 hold (step) |
| `fig_redteam_depth.png` | `make_paper_figures.py` | 28 distinct false-negative bypasses found and closed, per boundary (horizontal bar) |
| `fig_cumulative_prevented.png` | `make_paper_figures.py` | Cumulative attacker actions over 5 days; shaded region is what quarantine prevents (line + area) |

Regenerate everything:
```
python report/figures/make_trust_boundaries.py
python report/figures/make_paper_figures.py
```
Data is read live from `RED_TEAM.md` and `analysis/data/incident_public_record.json`.

## Removed

`make_plots.py`, `make_advanced_plots.py`, and `make_wow_plots.py` are gone,
replaced by `make_paper_figures.py`. They produced a PASS/FAIL grid
(`scorecard.png`), a TP/FN/FP/TN grid (`detection_quality.png`), a coverage
grid (`vuln_coverage.png`), and two "hero" shapes - radial bars
(`redteam_radial.png`) and a ribbon-flow diagram (`killchain_flow.png`) -
that looked distinctive but took real effort to decode. The load-bearing
data from those (detection budget, red-team depth, blast radius, quarantine
timing/volume) now lives in the plain charts above; the pure pass/fail and
coverage grids weren't ported, since a 9x4 or 5x10 grid of identical cells
is a table, not a plot, and reads better as `control_table.md`.

An earlier pass combined all six charts into one `paper_results.png` grid;
that's been split back into individual files, one per chart, so each can be
dropped into the paper on its own.
