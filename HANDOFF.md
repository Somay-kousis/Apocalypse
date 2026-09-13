# HANDOFF - team status & task board

Update at every sign-off (India / China / US = near-24h coverage). Keep entries to
GREEN / BROKEN / NEXT. **Each owner edits only their own `controls/<name>/` dir.**
`controls/control_spec.yaml` is canonical - read your rows there before writing code.

Verify anytime (offline, no keys):
```
.venv/bin/python -m validation.run_checks --target environments/fixed_lab/configs   # must stay 9/9
.venv/bin/python -m validation.run_checks --target environments/adversarial_lab/configs  # must stay 0/9
.venv/bin/python -m validation.measure_sla --target environments/fixed_lab/configs  # must stay 9 HIT
.venv/bin/python -m validation.simulate_detection --output /tmp/apocalypse-sla --trials 100 --overwrite
.venv/bin/python -m validation.simulate_integration --output /tmp/apocalypse-integration --trials 3 --overwrite
.venv/bin/python -m validation.evaluate_detection --output /tmp/apocalypse-quality --overwrite
.venv/bin/python -m pytest tests/ -q
```

=====================================================================
## DONE (Somay) - architecture + rules 1/3/4/5/8/9

- **Architecture (shared, please don't edit):** `control_spec.yaml` (canonical 9-rule spec),
  `validation/run_checks.py` (**fail-closed** scorecard), `validation/replay_attack.py`,
  `analysis/data/incident_public_record.json` (curated public record - the ground truth),
  the 4 labs, and `RED_TEAM.md` (checker bypasses found + fixed).
- **Rules 4/5/9 EXECUTE real exploits, not string checks:**
  - Rule 4: builds a real malicious HDF5 external-link file; hardened loader refuses, broken lab leaks the secret.
    Also rejects the config if a forbidden construct (e.g. `H5Pset_external`) is present anywhere in the text,
    even when the `allow_external_links` flag itself reads as safe (regression: flag-says-safe-but-isn't).
  - Rule 5: fires a real SSTI payload; SandboxedEnvironment blocks it, plain Environment reaches Python internals.
  - Rule 9: cross-boundary. Reads `b9_credentials/credential_scope.yaml` + `iam_graph.json`; composes rules 6/7/8's
    PASS/FAIL via the `context` kwarg `run_checks.py` wires up automatically (topological order from `depends_on`)
    to decide which of an identity's declared `reach` tags are actually closed off before comparing to the
    declared blast-radius bound.
- **Rules 1/3/8 were quietly reading the WRONG files and have been fixed** (see RED_TEAM.md "runner" /
  path-mismatch entries): `check_registry.py`, `check_sandbox.py`, and `check_tailscale.py` were reading
  legacy root-level `registry.json` / `pod_spec.json` / `vpn_config.json` instead of their declared
  `boundary_dir`/`config_file` (`b1_registry/mirror_manifest.yaml`, `b3_sandbox/security_context.yaml`,
  `b8_tailscale/worker_env.txt` + `alert_log.jsonl`). This meant `exploit_lab`/`adversarial_lab`'s per-boundary
  fixtures for these three rules were never actually exercised - the scorecard happened to read 0/9 there only
  because the (unused) legacy files were also insecure, not because the checkers were doing their job.
  All three now read the correct location, with `tests/test_check_registry.py` / `test_check_sandbox.py` /
  `test_check_tailscale.py` pinning the contract. Rule 8 also now implements the decoder-aware matcher HANDOFF
  had flagged as the biggest open contribution: it recursively decodes bounded standard/URL-safe base64,
  base32, hex, percent-URL, and gzip candidates in the worker env before matching the authkey pattern.
  `exploit_lab`/`adversarial_lab` now carry real per-boundary bypass fixtures for rules 1/3/8/9 too.
- **Headline number** computed in `analysis/threshold_model.ipynb`: quarantine at a per-identity action-rate
  threshold fires **41.6 h before the Day-3 spike** (band: 500->44.8h, 1000->41.6h, 2000->35.3h).
- **Figure:** `report/figures/trust_boundaries.png` (+ reproducible generator).
- **Status:** fixed 9/9, broken/exploit/adversarial 0/9, replay 13/13, `pytest tests/` 116/116 passing.
- **Note on biscuit:** the `biscuit-python` Rust binding won't build on modern Python, so rule 9's off-origin
  replay result is modeled declaratively via `credential_scope.yaml` rather than a live mint/verify - key for a
  judge-runnable artifact with no extra native deps.

=====================================================================
## TODO (Vikas) - rules 2, 6, 7  (AWS SAA lane)

These are already real, structured checkers (not placeholders) - `check_egress.py` does domain/SNI-agreement +
wildcard + IP-literal checks, `check_imds.py` does the hop-limit/http-tokens combination, `check_controlplane.py`
does two-layer (NetworkPolicy + RBAC) graph reachability. Still worth your AWS depth pass:
- **Rule 6 (IMDS):** double check the `HttpTokens: required` (IMDSv2 enforcement) path against a real AWS
  pod-spec shape you've seen in practice - the current logic is spec-driven, not battle-tested against a live cluster.
- **Rule 2 (egress):** the allowlist logic is real (domain==SNI, no wildcards, no IP literals) - stress it against
  real-world CDN/edge configs where legitimate domain-fronting-like patterns show up, and tune false positives.
- **Rule 7 (control-plane):** the RBAC-vs-NetworkPolicy two-layer model is in; the "single-layer-open" hardening
  note is informational only right now - decide if it should ever flip a PASS to a warning-level status.
- Keep the signature `run(target_dir) -> CheckResult`.
- After changes: `run_checks` must stay fixed 9/9 AND adversarial 0/9 (don't re-open a bypass).
- **Commit your own files** so the section is credited to you.
- **You also lead:** the 8-page report + the video.
- **Papers for your rules:** [1] arXiv:2607.25379 (class "supply-chain & credential exposure" = your 6/9 area);
  skim [3] arXiv:2606.08433 for how a property->test->result table reads.

=====================================================================
## DONE (Junyi) - rules 1, 3, 8  (security lane)

- **Rule 1 (registry):** validates 64-hex pins, confines artifact paths to the sealed mirror, requires each local
  artifact, and hashes its bytes. The fixed lab carries two deterministic offline artifact fixtures.
- **Rule 3 (sandbox):** strictly rejects privileged mode, privilege escalation, writable root filesystems,
  missing `drop: ALL`, root UID variants, added capabilities, unconfined seccomp, and egress.
- **Rule 8 (Tailscale + detection):** bounded recursive standard/URL-safe base64, base32, hex, percent-URL,
  and gzip decoding catches nested keys; policy requires ephemeral expiry <=24h. JSONL evidence is independently
  correlated across env dump -> staged binary -> IMDS -> VPN start for every workload containing an attack event,
  and every event must be detected within the <1 minute SLA.
- **Rule 1 trust boundary:** local SHA-256 checking proves artifact integrity relative to the supplied manifest,
  not publisher authenticity. A production implementation still needs an independent verified signature,
  transparency log, or separately trusted digest.
- **Threat model + Limitations & Dual-Use:** the report now states attacker capabilities, defender-controlled
  evidence, the bounded security claim, compositional containment, and the remaining mock/runtime limitations.
- Verified: fixed 9/9; broken/exploit/adversarial 0/9; replay 13/13; focused security tests 33/33;
  full suite 116/116.
- **Papers for these rules:** [2] arXiv:2604.23425 ("the agent is the adversary" - threat model);
  [1] arXiv:2607.25379 (classes "persistent C2" + "multi-step chains" = rules 8/3).

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
- **Reporting guardrail:** adaptive trials are N=0 and must remain labeled unmeasured until the
  runner is implemented and executed. The offline SLA harness measures committed synthetic evidence
  for all nine rules (fixed 9 HIT; other labs 9 MISS). The executable simulator additionally measures
  local matcher time; the contained integration tier performs safe local actions and sends raw
  telemetry to a separate observer process. The adversarial observer matrix currently reports
  18 TP / 0 FN / 0 FP / 18 TN. None may be presented as production sensor or SIEM latency.

---
## LOG
## 2026-09-12 (Somay) - GREEN: architecture + rules 4/5/9 execute; headline + figure done; 9/9 & 14/14.
   BROKEN: rules 1,2,3,6,7,8 are shallow placeholders (pass but static). NEXT: Vikas/Junyi deepen + commit their lanes; report prose.
## 2026-09-12 (Somay, follow-up) - GREEN: fixed the path-mismatch bug in rules 1/3/8 (check_registry.py,
   check_sandbox.py, check_tailscale.py were reading stale root-level json instead of their b1/b3/b8 boundary
   dirs - same class of bug RED_TEAM.md already documented and fixed for rules 4/5); wired context into
   check_creds.py (rule 9) so the cross-boundary composition described above actually runs; added the rule-8
   decoder-aware matcher; added real per-boundary bypass fixtures to exploit_lab/adversarial_lab for
   rules 1/3/8/9 (previously empty, so those rules were never actually red-teamed). `pytest tests/` was 16
   failing / 48 passing before this fix (mismatched paths + a `context` kwarg TypeError in rule 9); now 64/64
   passing. Scorecards unchanged in outcome (fixed 9/9, others 0/9) but now for the right reasons.
   NEXT: Vikas/Junyi review + commit their lanes; report prose.
## 2026-09-12 (Junyi, security hardening) - GREEN: rules 1/3/8 now verify artifact bytes, complete sandbox
   privilege fields, nested decoder evasion, correlated event order, key expiry, and detection SLA. Added an
   explicit threat model and limitations. Verified fixed 9/9, three attack labs 0/9, replay 13/13, tests 76/76.
   NEXT: review and commit this local security-lane diff; no pull request created.
## 2026-09-13 (Junyi, Rule 8 red-team follow-up) - GREEN: expanded bounded decoding to standard/URL-safe
   base64, base32, hex, percent-URL, and gzip; replaced first-clean-workload semantics with an ALL-workload
   requirement; added unit and adversarial fixtures for both bypasses. Documented Rule 1 integrity-vs-authenticity.
   Verified fixed 9/9, three attack labs 0/9, replay 13/13, focused tests 33/33, full suite 116/116.
   NEXT: commit the Junyi follow-up after review; Vikas still owns the separately reported Rule 7 node-identity fix.
## <date> (<name>) - GREEN: / BROKEN: / NEXT:
