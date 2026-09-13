# Methodology -> where each step lives

Pipeline from the sprint brief, mapped to files so teammates know where their work goes.

| # | Step | Lives in |
|---|------|----------|
| 0 | **Headline number FIRST** (before building): backtest per-identity action-rate threshold vs published phase/day counts (Day 3 = 7,677); hours-earlier quarantine | `analysis/threshold_model.ipynb` + `analysis/data/incident_public_record.json` |
| 1 | Reconstruct incident into 9 boundaries | `analysis/data/incident_public_record.json` (nodes/edges/commands) |
| 2 | Define containment standard per boundary | `controls/control_spec.yaml` (requirement) |
| 3 | Translate each -> testable control (pass condition / verification w/o lab access / detection SLA / adoption cost) | `controls/control_spec.yaml` (all 5 fields) |
| 4 | Build test environment: one abstraction per boundary, composable | `environments/` (see `environments/boundaries/README.md`) |
| 5 | Validate: replay known path; adaptive agent (N trials, survival rate/control) | `validation/replay_attack.py` (known); `validation/adaptive_agent.py` is optional and currently unimplemented (N=0) |
| 6 | Measure: block rate, survival rate (N), alt paths, SLA hits/misses, detector TP/FP/FN/TN, blast-radius breach | `validation/run_checks.py` + `validation/measure_sla.py`; `validation/simulate_integration.py` performs contained actions observed by a separate process; `validation/evaluate_detection.py` scores attack/benign variants -> `report/results.md` |
| 7 | Produce Containment Standard mapped to submission format | `report/control_table.md`, `report/draft.md` |

**Owners:** Junyi 1,3,8 · Vikas 2,6,7 · Somay 4,5,9. Update `HANDOFF.md` at every sign-off.
