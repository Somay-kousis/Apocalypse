# Apocalypse - Track 1: Containment Standards

Submission for the Apart x CeSIA **AI Incident Response Sprint** (Sep 11-13, 2026), Track 1.
Case study: the **July 9-13, 2026 frontier-model sandbox escape** (OpenAI eval model -> Hugging Face).

## The deliverable
A **9-rule containment standard**, each rule tied to one documented step of the real attack,
paired with a **broken-vs-fixed test lab** that proves the checks work. A third party runs it on a
laptop in seconds and watches the score move from 0/9 (broken) to 9/9 (fixed). That contrast is
Track 1's literal success bar: *verifiable by third parties without lab network access* - offline,
no API keys, no cluster.

Current status: **fixed 9/9 - broken / exploit / adversarial 0/9 - replay 13/13 - fail-closed.**

## The evidence constraint (read this first)
There is **no 17,600-action corpus**. Hugging Face's "interactive replay" ships no JSON/CSV/IOC/YARA -
its entire public payload is **8 phase totals, 5 day counts, and 14 example commands**. We extracted
and curated all of it into `analysis/data/incident_public_record.json`; that curation is itself a
contribution. Every rule cites a specific line in that file. Do **not** plan work that assumes a
larger corpus - it does not exist (also a finding for the report's limitations section).

## Layout
- `controls/control_spec.yaml` - **canonical** definition of all 9 rules (requirement / pass condition /
  verification / detection SLA / adoption cost / tested-vs-spec). Agree here before writing checks.
- `controls/{somay,vikas,junyi}/` - checkers by owner. Each `run(target_dir) -> CheckResult`.
  `controls/somay/check_hdf5.py` and `check_creds.py` are worked, executing patterns to copy.
- `controls/somay/captoken.py` - self-contained Ed25519 capability token (Biscuit model) for rule 9.
- `environments/` - `fixed_lab` (hardened), `broken_lab` (the real July-2026 misconfig),
  `exploit_lab` + `adversarial_lab` (attacker configs used to red-team the checkers). Each has a
  `configs/` dir the checkers read. `boundaries/README.md` maps the 9 abstractions.
- `validation/run_checks.py` - scorecard runner (N/9), **fail-closed** (a hostile config fails one
  rule, never crashes the suite). `replay_attack.py` - replays the 13 boundary-testing steps (of
  14 documented commands - 3 are context-only recon/cleanup, not boundary tests) vs a target.
  Both **offline, no keys**. `adaptive_agent.py` - optional LLM stretch (only thing needing a key).
- `analysis/threshold_model.ipynb` - headline number from the public day counts.
- `report/` - draft, control matrix, `figures/trust_boundaries.png` (+ its generator).
- `tests/test_somay_section.py` - executable tests for rules 4/5/9 + the token primitive.
- `RED_TEAM.md` - the 10 bypasses found and fixed. `HANDOFF.md` - status + task board.

## Quickstart (offline, ~seconds, no API keys)
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m validation.run_checks    --target environments/fixed_lab/configs    # 9/9
.venv/bin/python -m validation.run_checks    --target environments/broken_lab/configs   # 0/9
.venv/bin/python -m validation.replay_attack --target environments/fixed_lab/configs    # 13/13 blocked
.venv/bin/python -m pytest tests/ -q                                                    # 76 passed
```

## Owners
- **Somay** - rules 4,5,9 + runner/architecture (control_spec, fail-closed runner, incident record,
  labs, red-team). **Done: 4/5/9 execute real exploits** (see HANDOFF).
- **Vikas** (AWS SAA) - rules 2,6,7 + report lead + video.
- **Junyi** - rules 1,3,8 + threat model + dual-use appendix.

See **HANDOFF.md** for exactly what's done and what each owner does next.

## Papers
- [1] arXiv:2607.25379 - *Cyber-Capable AI Agents* (this incident; 5 vuln classes - map our rules onto them)
- [2] arXiv:2604.23425 - *When the Agent Is the Adversary* (April 2026 escape; 4 containment approaches - we build the 4th, "accessible audit")
- [3] arXiv:2606.08433 - *AI Code Sandboxes* (51-property suite - format model, rule 3 reference)
