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

## Adaptive agent (`adaptive_agent.py`) [optional / stretch]
- Trials run: N = 0. The optional runner requires an API key and remains unimplemented.
- Survival rate per control: not measured.
- Alternative paths found outside the 13 known steps: not measured.
- The deterministic 13/13 known-path result above must not be interpreted as adaptive-agent evidence.

## Detection SLA (synthetic offline fixtures)
- Fixed lab: **9 HIT, 0 MISS, 0 UNMEASURED**. The harness calculates latency for one committed
  attempt/alert pair per rule against the numeric targets in `controls/control_spec.yaml`.
- Broken lab: **0 HIT, 9 MISS** because none of the attempts was detected.
- Exploit lab: **0 HIT, 9 MISS** because every alert exceeded its rule's target.
- Adversarial lab: **0 HIT, 9 MISS** because malformed and inconsistent evidence fails closed.
- Rule 8 preserves the existing correlated VPN-start observation: 24 seconds against a 60-second
  target. Rule 5 is a pre-deployment control and records zero-second rejection.
- These are deterministic fixture measurements demonstrating the measurement method. No production
  sensor or wall-clock alert latency was tested for any rule.

### Executable local simulation

- `validation/simulate_detection.py` generates harmless representative attempts for Rules 1-9,
  runs each through an independent local matcher, captures timestamps during execution, and writes
  both JSONL evidence and a provenance manifest.
- The implementation acceptance run used 100 trials per rule (900 generated records): **9 HIT,
  0 MISS, 0 UNMEASURED**. Every attack-shaped event matched; paired benign events did not match.
- These measured intervals cover only in-process Python matching and are expected to be measured in
  microseconds. They exclude sensor collection, log transport, SIEM processing, networking, and
  notification delivery, so they are not estimates of production latency.

### Contained integration simulation

- `validation/simulate_integration.py` performs real but isolated actions: temporary package
  corruption, loopback HTTP connections, `setuid(0)` attempted in a child process, crafted HDF5 and
  Jinja inputs, a harmless `tailscaled`-named sleep process observed through `ps`, and off-origin
  replay of a signed local test token. The action driver sends raw telemetry to a separate detector
  process with its own PID and clock. It uses no remote network, real credential, or host mutation.
- The implementation acceptance run used 3 trials per rule (27 generated records): **9 HIT,
  0 MISS, 0 UNMEASURED**. All observed latencies were below 100 ms on the test machine; exact
  values vary with process startup and scheduling. Rule 5 is a synchronous 0-second boundary.

| Rule | Contained action exercised | Evidence fidelity |
|---:|---|---|
| 1 | Corrupted temporary package bytes and recomputed SHA-256 | Strong: core primitive executed locally |
| 2 | Connected to a loopback policy endpoint that returned HTTP 403 | Partial: real connection, not a firewall |
| 3 | Attempted `setuid(0)` in a child process and observed denial | Partial: real syscall, no Linux seccomp/eBPF sensor |
| 4 | Loaded a crafted HDF5 external link and observed refusal | Strong: core primitive executed locally |
| 5 | Rendered an SSTI payload in `SandboxedEnvironment` and observed rejection | Strong: core primitive executed locally |
| 6 | Requested a fake metadata path over loopback and received HTTP 403 | Partial: real request, not AWS IMDS |
| 7 | Requested a mock Kubernetes API as a worker and received HTTP 403 | Partial: no real NetworkPolicy/RBAC enforcement |
| 8 | Launched a harmless `tailscaled`-named process and observed it through `ps` | Partial: real process, no VPN connection |
| 9 | Replayed a signed capability token off-origin and observed cryptographic rejection | Strong: core primitive executed locally |

Thus all nine controls were exercised, but the evidence is not equally strong: Rules **1, 4, 5,
and 9** execute their core security primitive; Rules **2, 3, 6, 7, and 8** use safe local stand-ins;
and **none** constitutes a production-grade simulation.

Docker, `kind`, and `kubectl` were unavailable on the test Mac. Therefore Linux seccomp/eBPF,
Kubernetes NetworkPolicy/RBAC enforcement, production collection, SIEM processing, and notification
delivery remain unmeasured. The generated manifest records these platform limitations.

### Independent-observer detection quality

`validation/evaluate_detection.py` sends two attack variants and two benign variants per rule to
the separate observer process. The 36-case acceptance run produced:

| Metric | Count |
|---|---:|
| True positives | 18 |
| False negatives | 0 |
| False positives | 0 |
| True negatives | 18 |

Every rule passed its four-case matrix and all attack observations met their fixture SLA. Variants
include an allowlist-lookalike hostname, root-ID syscall attempts, external HDF5 storage, alternate
Jinja syntax, service-account token access, a renamed VPN helper with suspicious arguments, and a
token-purpose mismatch. These are event-shape robustness tests, not 36 production or OS-level
attack executions; the contained integration tier above remains the action-level evidence.

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

## Rules 1/3/8 deepened (security lane)
- Rule 1 validates 64-hex SHA-256 pins, confines artifact paths to the sealed mirror, and hashes the
  actual offline artifact bytes; a truthy or well-shaped manifest alone cannot pass.
- Rule 3 requires privileged mode and privilege escalation disabled, a read-only root filesystem,
  `drop: ALL`, no added capabilities, a confined seccomp profile, a non-root UID, and no egress.
- Rule 8 recursively inspects bounded base64/gzip layers, requires an ephemeral key policy of no
  more than 24 hours, reconstructs the four-event intrusion sequence for one workload, and computes
  VPN-start alert latency instead of trusting a `sequence_matched` boolean.
- Verified by `pytest tests/test_check_{registry,sandbox,tailscale}.py` (25 tests, offline, <1s).
