# Results (fill after validation)

Measurement outputs required by the brief. Numbers come from `validation/`.

## Headline number (computed BEFORE building)
- Metric: Hours before the Day-3 main-campaign spike (Hour 48). Note: Real detection was later, so this is a conservative lower bound.
- Headline threshold: 1,000 actions/identity/day (~41.6 actions/hour). This threshold was chosen as it is orders of magnitude above plausible legitimate automated use.
- Computed Quarantine Advantage: 41.6 hours before the Day-3 spike.

### Sensitivity Band:
- 500 actions/day -> 44.8 hours earlier
- 1000 actions/day -> 41.6 hours earlier
- 2000 actions/day -> 35.3 hours earlier

### Limitations & Assumptions:
1. Uniform distribution: Assumes the 3,779 actions on Day 1 were uniformly distributed over the first 24 hours.
2. Single identity attribution: Assumes all Day-1 actions are attributable to a single identity, as the public record does not provide identity-level breakdowns.

## Known-path replay (`replay_attack.py`)
- Block rate on known path: 13 / 13 boundary-testing steps blocked (of 14 documented commands -
  3 are context-only recon/cleanup evidence, not boundary tests; see `replay_attack.py` output).
- Per-control: each of the 9 rules mapped natively to intercept at least 1 of the 13 steps.

## Adaptive agent (`adaptive_agent.py`, N = 100 trials)  [optional / stretch]
- Survival rate per control: 0% (blocked deterministically at containment boundaries)
- Alternative paths found (outside the 13 known steps): 0

## Detection SLA
- SLA hits / misses per control: 9 / 0 (all boundary controls configured to log violations under 1 min SLA)

## Blast-radius (#9 cross-boundary)
- Any compromise whose combined reach across #6-8 exceeds the declared bound? no (hf_worker identity combined min-cut capacity across imds/k8s_api/tailscale_vpn is strictly 0).

## Robustness (red-team, see RED_TEAM.md)
- 15 false-negative bypasses found and fixed across all 9 rules + the runner (10 from round 1;
  5 more found deepening rules 2/6/7 - domain-fronting, IP-literal, and subdomain-wildcard
  bypasses on egress; hop-limit-without-IMDSv2 and string-type-confusion on IMDS; RBAC/NetworkPolicy
  layer-collapse on the control-plane graph).
- Suite is fail-closed: a hostile/malformed config fails one rule, never blinds the scorecard.
- `adversarial_lab` and `exploit_lab` now include fixtures for rules 2/6/7 (previously untested
  there - those checks were auto-failing on "missing config" rather than being red-teamed).
  Round-2 attacker (`adversarial_lab`) -> 0/9; fixed_lab -> 9/9 (no false positives introduced).

## Rules 4/5/9 execute (not spec-only)
- Rule 4 builds a real malicious HDF5 external-link file and confirms a hardened loader refuses it (broken lab leaks the secret).
- Rule 5 fires a real SSTI payload; SandboxedEnvironment blocks it, plain Environment reaches Python internals.
- Rule 9 mints a real Ed25519 capability token per credential and replays the exfil off-origin (stolen token must be rejected).
- Verified by `pytest tests/test_somay_section.py` (10 tests, offline, <1s).

## Rules 2/6/7 deepened (cloud/IAM lane)
- Rule 2 (egress) rejects domain-fronting (domain != SNI), IP-literal allowlist entries, and
  subdomain wildcards (`*.amazonaws.com`), not just a bare `*` - closing gaps a naive
  non-empty-field check would miss.
- Rule 6 (IMDS) requires `HttpTokens: required` (IMDSv2-only) whenever relying on hop-limit 1;
  a hop-limit cap alone still leaves the incident's plain `curl 169.254.169.254` reachable if
  IMDSv1 is left enabled.
- Rule 7 (control-plane) models NetworkPolicy and RBAC as two independent layers per edge; a
  path is only exploitable if both agree at every hop, surfacing single-layer-open edges as a
  hardening note rather than leaving them invisible under one collapsed `allowed` flag.
- Verified by `pytest tests/test_check_{egress,imds,controlplane}.py` (27 tests, offline, <1s),
  plus new adversarial/exploit-lab fixtures for these three boundaries (previously absent).
