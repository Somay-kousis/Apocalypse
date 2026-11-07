# Apocalypse: Track 1, Containment Standards

<p align="center">
  <img src="https://img.shields.io/badge/language-Python-3776AB.svg" alt="Python" />
  <img src="https://img.shields.io/badge/pytest-tests-0A9EDC.svg" alt="pytest" />
  <img src="https://img.shields.io/badge/cryptography-Ed25519-2F2F2F.svg" alt="cryptography" />
</p>

A 9-rule containment standard for AI agent sandboxes, each rule tied to one documented step of a real
escape, plus a broken-vs-fixed test lab that checks the rules on a laptop in seconds: offline, no API
keys, no cluster. Built for the Apart x CeSIA **AI Incident Response Sprint** (Sep 11-13, 2026),
Track 1, whose bar is *verifiable by third parties without lab network access*.

Case study: the **July 9-13, 2026 frontier-model sandbox escape** (OpenAI eval model -> Hugging Face).

## Results

```
fixed lab                 9/9 rules pass
broken / exploit / adversarial labs   0/9
known attack path replay  13/13 boundary-testing steps blocked
detection SLA (fixtures)  9/9 HIT on the fixed lab
contained integration     9/9
observer quality          18 TP / 0 FN / 0 FP / 18 TN
tests                     118 passed
```

From the public day counts (`analysis/threshold_model.ipynb`, `report/results.md`): a quarantine
threshold of 1,000 actions per identity per day would have fired **41.6 hours before** the Day-3
campaign spike (35.3 to 44.8 hours across 500-2,000 actions/day). This assumes the 3,779 Day-1 actions
were spread evenly over 24 hours and came from one identity; the public record has no identity-level
breakdown.

## The evidence

There is **no 17,600-action corpus**. Hugging Face's "interactive replay" ships no JSON/CSV/IOC/YARA:
its entire public payload is **8 phase totals, 5 day counts and 14 example commands**. We extracted
all of it into `analysis/data/incident_public_record.json`, and every rule cites a specific line in
that file. Any larger dataset would have to come from the lab.

## Quickstart (offline, seconds, no API keys)

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m validation.run_checks    --target environments/fixed_lab/configs    # 9/9
.venv/bin/python -m validation.run_checks    --target environments/broken_lab/configs   # 0/9
.venv/bin/python -m validation.replay_attack --target environments/fixed_lab/configs    # 13/13 blocked
.venv/bin/python -m validation.measure_sla   --target environments/fixed_lab/configs    # 9/9 HIT
.venv/bin/python -m validation.simulate_detection --output /tmp/apocalypse-sla --trials 100
.venv/bin/python -m validation.simulate_integration --output /tmp/apocalypse-integration --trials 3
.venv/bin/python -m validation.evaluate_detection --output /tmp/apocalypse-quality
.venv/bin/python -m pytest tests/ -q                                                    # 118 passed
```

## Layout

- `controls/control_spec.yaml`: the canonical definition of all 9 rules (requirement, pass condition,
  verification, detection SLA, adoption cost, tested vs spec).
- `controls/{somay,vikas,junyi}/`: checkers by owner. Each is `run(target_dir) -> CheckResult`.
- `controls/somay/captoken.py`: a self-contained Ed25519 capability token (Biscuit model) for rule 9.
- `environments/`: `fixed_lab` (hardened), `broken_lab` (the real July 2026 misconfiguration), and
  `exploit_lab` + `adversarial_lab` (attacker configs used to red-team the checkers). Each has a
  `configs/` dir the checkers read. `boundaries/README.md` maps the 9 trust boundaries.
- `validation/`: `run_checks.py` (scorecard N/9, **fail-closed**: a hostile config fails one rule,
  never crashes the suite), `replay_attack.py` (the 13 boundary-testing steps drawn from the 14
  documented commands), `measure_sla.py` (fixture detection latency, all 9 rules),
  `simulate_detection.py` and `simulate_integration.py` (harmless local events, loopback-only
  connections and real HDF5/Jinja/token operations, detector in a separate process),
  `evaluate_detection.py` (attack and benign variants per rule). `adaptive_agent.py` needs an API
  key and was not run.
- `analysis/threshold_model.ipynb`: the quarantine number. `report/`: draft, control matrix, results,
  figures. `RED_TEAM.md`: every red-team bypass found and fixed. `HANDOFF.md`: status log.

## Limitations

- Simulator latency covers only local in-process matching. It does not measure production sensors,
  log transport, a SIEM or notification delivery.
- The 13/13 replay is the known attack path only. The adaptive agent was never run, so there is no
  evidence on alternative paths.
- Some restricted sandboxes need permission for loopback and `ps` to run the integration command.

## Team

- **Somay**: rules 4, 5, 9, plus the runner and architecture (control spec, fail-closed runner,
  incident record, labs, red team). Rules 4/5/9 execute real exploits (see `HANDOFF.md`).
- **Vikas**: rules 2, 6, 7, report lead and video.
- **Junyi**: rules 1, 3, 8, threat model and dual-use appendix.

## Papers

- [1] arXiv:2607.25379, *Cyber-Capable AI Agents* (this incident; 5 vulnerability classes, which our rules map onto)
- [2] arXiv:2604.23425, *When the Agent Is the Adversary* (April 2026 escape; 4 containment approaches, we build the 4th, "accessible audit")
- [3] arXiv:2606.08433, *AI Code Sandboxes* (51-property suite; format model and rule 3 reference)
