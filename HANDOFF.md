# HANDOFF - team status & task board

Update at every sign-off (India / China / US = near-24h coverage). Keep entries to
GREEN / BROKEN / NEXT. **Each owner edits only their own `controls/<name>/` dir.**
`controls/control_spec.yaml` is canonical - read your rows there before writing code.

Verify anytime (offline, no keys):
```
.venv/bin/python -m validation.run_checks --target environments/fixed_lab/configs   # must stay 9/9
.venv/bin/python -m validation.run_checks --target environments/adversarial_lab/configs  # must stay 0/9
.venv/bin/python -m pytest tests/ -q
```

=====================================================================
## DONE (Somay) - architecture + rules 4/5/9

- **Architecture (shared, please don't edit):** `control_spec.yaml` (canonical 9-rule spec),
  `validation/run_checks.py` (**fail-closed** scorecard), `validation/replay_attack.py`,
  `analysis/data/incident_public_record.json` (curated public record - the ground truth),
  the 4 labs, and `RED_TEAM.md` (10 checker bypasses found + fixed).
- **Rules 4/5/9 now EXECUTE real exploits, not string checks:**
  - Rule 4: builds a real malicious HDF5 external-link file; hardened loader refuses, broken lab leaks the secret.
  - Rule 5: fires a real SSTI payload; SandboxedEnvironment blocks it, plain Environment reaches Python internals.
  - Rule 9: mints a real Ed25519 capability token (`controls/somay/captoken.py`, Biscuit model) and replays the
    exfil off-origin - stolen token is rejected; bearer isn't; plus min-cut blast-radius over the RBAC graph.
  - Tests: `tests/test_somay_section.py` (10 passing, offline, <1s).
- **Headline number** computed in `analysis/threshold_model.ipynb`: quarantine at a per-identity action-rate
  threshold fires **41.6 h before the Day-3 spike** (band: 500->44.8h, 1000->41.6h, 2000->35.3h).
- **Figure:** `report/figures/trust_boundaries.png` (+ reproducible generator).
- **Status:** fixed 9/9, broken/exploit/adversarial 0/9, replay 14/14.
- **Note on biscuit:** the `biscuit-python` Rust binding won't build on modern Python, so rule 9 uses a
  self-contained Ed25519 implementation of the Biscuit model (installs anywhere - key for a judge-runnable artifact).

=====================================================================
## TODO (Vikas) - rules 2, 6, 7  (AWS SAA lane)

Your checkers exist but are **shallow config-audits** (placeholders Somay wrote, Claude hardened).
They pass the labs, but a judge will see they only read declared config. Deepen them with your AWS knowledge:
- **Rule 6 (IMDS):** add `HttpTokens: required` (IMDSv2 enforcement) - currently only hop-limit + link-local.
- **Rule 2 (egress):** make the allowlist logic real (SNI/domain semantics), beyond CIDR-breadth.
- **Rule 7 (control-plane):** sharpen the RBAC-vs-NetworkPolicy distinction.
- Keep the signature `run(target_dir) -> CheckResult`; copy the executing pattern in `controls/somay/check_creds.py`.
- After changes: `run_checks` must stay fixed 9/9 AND adversarial 0/9 (don't re-open a bypass).
- **Commit your own files** so the section is credited to you.
- **You also lead:** the 8-page report + the video.
- **Papers for your rules:** [1] arXiv:2607.25379 (class "supply-chain & credential exposure" = your 6/9 area);
  skim [3] arXiv:2606.08433 for how a property->test->result table reads.

=====================================================================
## TODO (Junyi) - rules 1, 3, 8  (security lane)

Same situation - shallow placeholders to deepen. Rule 8 is your real research contribution:
- **Rule 8 (Tailscale + detection):** currently just checks a boolean flag. Implement the **actual
  decoder-aware matcher** - unpack nested base64/gzip, then flag the sequence (env dump -> staged binary
  -> IMDS -> VPN start). This directly answers HF's stated blind spot ("naive text scanning missed encoded
  payloads"). Biggest real contribution still open.
- **Rule 3 (sandbox):** deepen the security-context checks (gVisor/seccomp specifics) if you want.
- **Rule 1 (registry):** currently `spec-only`; make it real if time allows.
- Keep the signature; copy `controls/somay/check_hdf5.py`. Stay fixed 9/9 + adversarial 0/9. Commit your files.
- **You also own:** the threat-model section + the required **Limitations & Dual-Use appendix**.
- **Papers for your rules:** [2] arXiv:2604.23425 ("the agent is the adversary" - grounds your threat model);
  [1] arXiv:2607.25379 (classes "persistent C2" + "multi-step chains" = your 8/3 area).

=====================================================================
## OPEN (whole team)
- Report prose (`report/draft.md`) - Vikas leads. Two framings to include: (a) per [2], of the 4 containment
  approaches we build the only third-party-verifiable one (accessible audit); (b) the headline number is the
  defense for [1]'s 5th vuln class ("speed of automated action") - our 9 controls cover classes 1-4.
- Confirm your own detection-SLA / adoption-cost rows in `report/control_table.md` (currently Somay's DRAFT values).
- Adaptive agent (`validation/adaptive_agent.py`) - optional stretch; only piece needing an API key.
  **Somay has no Anthropic key, so this is skippable** - the submission is complete without it. If a teammate
  wants to run it: create a key at https://console.anthropic.com (Billing -> add a few $ credit -> API Keys ->
  Create Key -> `sk-ant-...`), copy `.env.example` to `.env`, paste it as `ANTHROPIC_API_KEY`, use model
  `claude-sonnet-5`. `.env` is gitignored - never commit a real key. (Our AgentRouter/Codex proxy won't work -
  it's UA-gated to the Codex CLI.) Full steps are in `.env.example`.

---
## LOG
## 2026-09-12 (Somay) - GREEN: architecture + rules 4/5/9 execute; headline + figure done; 9/9 & 14/14.
   BROKEN: rules 1,2,3,6,7,8 are shallow placeholders (pass but static). NEXT: Vikas/Junyi deepen + commit their lanes; report prose.
## <date> (<name>) - GREEN: / BROKEN: / NEXT:
