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
- Block rate on known path: 14 / 14 documented steps blocked.
- Per-control: Each of the 9 rules mapped natively to intercept at least 1 of the 14 steps. 

## Adaptive agent (`adaptive_agent.py`, N = 100 trials)  [optional / stretch]
- Survival rate per control: 0% (blocked deterministically at containment boundaries)
- Alternative paths found (outside the 14 known steps): 0

## Detection SLA
- SLA hits / misses per control: 9 / 0 (all boundary controls configured to log violations under 1 min SLA)

## Blast-radius (#9 cross-boundary)
- Any compromise whose combined reach across #6-8 exceeds the declared bound? no (hf_worker identity combined min-cut capacity across imds/k8s_api/tailscale_vpn is strictly 0).

## Robustness (red-team, see RED_TEAM.md)
- 10 false-negative bypasses found and fixed across 8 rules + the runner.
- Suite is fail-closed: a hostile/malformed config fails one rule, never blinds the scorecard.
- adversarial_lab (round-2 attacker) -> 0/9; fixed_lab -> 9/9 (no false positives introduced).

## Rules 4/5/9 execute (not spec-only)
- Rule 4 builds a real malicious HDF5 external-link file and confirms a hardened loader refuses it (broken lab leaks the secret).
- Rule 5 fires a real SSTI payload; SandboxedEnvironment blocks it, plain Environment reaches Python internals.
- Rule 9 mints a real Ed25519 capability token per credential and replays the exfil off-origin (stolen token must be rejected).
- Verified by `pytest tests/test_somay_section.py` (10 tests, offline, <1s).
