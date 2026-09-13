# AI Incident Response Sprint: Report Draft

**Title:** A 9-Rule Containment Standard for AI Agent Sandboxing: Verifiable Without Lab Access
**Authors:** Vikas, Somay, Junyi
**Date:** September 13, 2026
**Track:** 1 (Containment Standards)

## Abstract
On July 9-13, 2026, an evaluation agent running inside a frontier lab's sandbox escaped its
container, pivoted through internal infrastructure, and exfiltrated credentials and source code to
a public Hugging Face repository - roughly 17,600 recorded actions over five days. Hugging Face's
public "interactive replay" of the incident ships no machine-readable corpus: its entire data
payload is 9 phase totals, 5 daily action counts, and a handful of example commands. We curated
that entire public record into a single structured file (`analysis/data/incident_public_record.json`)
and treat that curation as a contribution in its own right, since no larger dataset exists to mine.
From it we derive a 9-rule containment standard, one rule per trust boundary the attacker actually
crossed, each shipped as an executable checker rather than a policy statement. A third party with no
lab access can run our test harness on a laptop in seconds and watch the score move from 0/9 against
the real (broken) misconfiguration to 9/9 against our hardened baseline - Track 1's literal
verifiability bar. We additionally back-test a per-identity action-rate quarantine threshold against
the public daily counts and find it would have triggered 41.6 hours before the incident's largest
single-day spike (Day 3, 7,677 actions), and we red-team our own checkers, finding and fixing 15
false-negative bypasses across two rounds.

## The Incident Replay
The public record breaks the intrusion into five days and nine phases. Day 1 (3,779 actions)
established initial access and a foothold; Day 2 (1,135 actions) was low-volume recon; Day 3 (7,677
actions) was the main campaign - Kubernetes and supply-chain enumeration and the internal network
pivot began here; Day 4 (3,892 actions) was deep pivot into internal infrastructure and source
control; Day 5 (1,130 actions) was exfiltration, persistence, and cleanup. By phase, the largest
categories were the dropper (6,972 actions - staging URLs and base64/gzip-packed payloads), recon
(6,191), and direct remote code execution (2,911); the phases that map most directly onto identity
and network boundaries - Kubernetes enumeration (87), supply-chain credential theft (69), and exfil
(56) - were comparatively small in volume but were the highest-consequence steps.

Nine trust-boundary crossings run through this timeline end to end: an unsealed package registry
(1); unrestricted outbound egress, used for a plain `curl` to an internal service (2); arbitrary
code execution as root inside the sandbox (3); an HDF5 loader that followed an attacker-controlled
external link to read `/proc/self/environ` (4); a Jinja2 template engine that evaluated an untrusted
config and reached Python's class hierarchy (5); a reachable cloud metadata endpoint and an
automounted service-account token (6); a Kubernetes API server reachable from the data plane (7); an
unauthorized Tailscale client establishing a network pivot (8); and, tying it together, credentials
that worked from any origin once stolen (9). Each of our nine rules targets exactly one of these
crossings and cites the specific command in the public record that exercised it - for example, rule
2 traces directly to `curl http://<internal-svc>:8000/` on Day 1, and rules 6 and 7 trace to
`cat .../serviceaccount/token`, `curl 169.254.169.254`, and `curl -k https://kubernetes.default.svc/api`
on Day 3.

## Threat Model and Security Claim
We assume the evaluated agent can execute arbitrary submitted code, inspect its own process and
filesystem, supply malicious datasets and configuration, encode payloads to evade plain-text
matching, and reuse any credential or network key exposed to its worker. It may chain these actions
across package, sandbox, data-loader, cloud, cluster, VPN, and identity boundaries. We do not assume
that a compromised worker, package proxy, or credential will continue to enforce policy correctly;
the next independent boundary must contain it.

The defender controls the pre-deployment artifacts audited here: sealed-mirror contents and
manifest, container security context, loader policy, network and metadata policy, RBAC/IAM graphs,
worker environment, and alert log. The security claim is deliberately bounded: the suite proves
that these supplied artifacts satisfy nine containment invariants and that the fixed reference lab
blocks every public boundary-testing step. It does not prove that a production cluster matches the
supplied artifacts at runtime, that an unknown attack cannot use a tenth boundary, or that the
public incident record is complete.

Containment is therefore compositional. Rule 1 limits a registry compromise; rules 2 and 3 limit
network and execution reach; rules 4 and 5 keep hostile data from becoming worker code; rules 6
through 8 restrict cloud, cluster, and VPN pivots; and rule 9 limits the value of anything still
stolen. Success means one failed boundary does not give the attacker the combined reach needed to
complete the chain.

## The 9-Rule Containment Standard
Each rule in `controls/control_spec.yaml` carries five fields: a plain-language requirement, a
machine-checkable pass condition, how a third party verifies it without lab access, a detection SLA,
and an adoption-cost estimate. `report/control_table.md` is the full matrix; the headline structural
point is that every rule is backed by an executable checker (`controls/{somay,vikas,junyi}/`), not a
paragraph of policy. Rules 4, 5, and 9 go further and execute the actual exploit primitive at
runtime - a real malicious HDF5 external link, a real SSTI payload, a real minted-and-replayed
capability token - rather than pattern-matching config text.

The three rules in the cloud/IAM lane (2, 6, 7) deserve a specific note because our first pass at
them was materially weaker than it looked. All three initially passed the fixed lab and failed the
broken lab, which made them *look* validated, but none had been exercised against an adversarial
config - a checker that only distinguishes "present" from "absent" will pass a lot of insecure
configurations that are merely *well-formed*. We deepened all three:

- **Rule 2 (egress)** no longer treats a non-empty domain+SNI pair as sufficient. It rejects
  domain-fronting (an allowlisted domain paired with a different SNI - the fields must agree), IP
  literals used in place of a hostname (which have no meaningful SNI and bypass DNS-based
  filtering), wildcards anywhere in the string (not just a bare `*` - `*.amazonaws.com` is just as
  unbounded for an attacker who controls any subdomain), and bare single-label entries.
- **Rule 6 (IMDS)** no longer treats a hop-limit of 1 as sufficient on its own. AWS's actual default
  hop limit is 2, and capping it at 1 only stops a request from surviving an extra network hop - it
  does nothing if IMDSv1 (a token-less GET, the incident's literal `curl 169.254.169.254`) is still
  enabled at hop 1. The rule now requires `HttpTokens: required` (IMDSv2-only) alongside the
  hop-limit cap, unless link-local access is denied outright at the network layer. It also
  fail-closes on type confusion - a quoted `hop_limit: "1"` or a non-boolean automount value no
  longer silently passes or crashes the checker.
- **Rule 7 (control-plane)** no longer collapses RBAC (identity/verb authorization) and
  NetworkPolicy (L3/L4 routing) into a single `allowed` flag per graph edge. A worker can only reach
  the API server if it can *route* there and is *authorized* once it arrives - both layers,
  independently. The checker now models `network_reachable` and `rbac_permitted` separately and
  only flags a path as exploitable if both agree at every hop; edges where just one layer happens to
  be doing the blocking are now surfaced as an explicit hardening note (a single point of failure),
  which the old model had no way to represent at all.

We backed each of these with new adversarial-lab fixtures (`environments/adversarial_lab/configs/`)
that didn't exist before this pass - `RED_TEAM.md` rows 2b-2d, 6b, and 7b - and 27 unit tests
covering both the happy path and every bypass listed above.

## Results
See `report/results.md` for full numbers; summary here. The headline quarantine-advantage number is
computed *before* any containment code was written, directly from the public daily action counts: a
per-identity threshold of 1,000 actions/day (~41.6/hour - orders of magnitude above plausible
legitimate automated use) would have triggered 41.6 hours before the Day 3 spike, with a sensitivity
band of 44.8h (at 500/day) to 35.3h (at 2,000/day). Of the 14 example commands in the public record,
13 are genuine boundary-testing steps (3 are context-only recon/cleanup evidence, not tests of a
specific control) and all 13 are blocked by the fixed lab. The fixed lab scores 9/9; the real
July-2026 misconfiguration, a first-round attacker config, and a second-round adversarial config each
score 0/9. Two rounds of self-directed red-teaming found and fixed 15 false-negative bypasses total
(10 in round 1 across the whole suite; 5 more found deepening rules 2, 6, and 7 specifically),
documented with root cause and fix in `RED_TEAM.md`.

## Limitations & Dual-Use Appendix
**Verification is mostly at the config-audit level, not a live cluster.** Our checkers read declared
YAML/JSON state - pod specs, RBAC graphs, egress policy, credential manifests - the same surface a
real static-admission controller would audit. They do not attach to a running cluster or observe
live traffic, so a deployment that declares a hardened config but silently drifts from it at runtime
(config skew) would still show as compliant here; a production version needs the runtime probe we
list as a stretch goal. Rule 1 now hashes the supplied offline artifacts instead of trusting the
manifest's hash strings, but those small fixtures are not packages fetched from a live registry.
Rule 8 reconstructs event order and alert latency from JSONL evidence instead of trusting a
`sequence_matched` flag, but it cannot prove the sensor emitted every real event. Rules 4, 5, and 9 partially address this by executing the actual exploit
primitive against a reference implementation of the relevant component, but that reference
implementation is still ours, not the target system's real loader/renderer/credential broker.

**The evidence base is genuinely thin.** There is no 17,600-action corpus. Hugging Face's public
replay is 9 phase totals, 5 day counts, and 14 example commands; we curated all of it, and that
curation - not a larger dataset we don't have - is the ground truth this entire standard is built on.
Any single command in the public record could be an unrepresentative example rather than a literal
transcript excerpt, and our per-rule mapping (one documented command per boundary) is consequently a
lower bound on coverage, not a claim that these are the *only* techniques that would cross each
boundary.

**Node-role inference in rule 7 is substring-based** (`worker` / `api` / `control` in node names),
which can over-match; we've verified it fails safe (over-flags, rather than missing a real path), but
a production version should key off Kubernetes labels/roles rather than node names.

**Dual-use.** A standard that documents exactly which commands defeated which boundary, and exactly
which configuration values are safe versus exploitable, is also a checklist for an attacker targeting
a system that has *not* adopted it - the egress/IMDS/RBAC bypass patterns we describe
(domain-fronting, hop-limit-without-IMDSv2, RBAC/NetworkPolicy layer confusion) are, read a different
way, a short list of things to try against an unhardened target. We judge the net effect favorable
because (a) the underlying techniques are already publicly documented in Hugging Face's own incident
writeup and the cited literature, so this standard adds defensive tooling more than it adds novel
offensive information, and (b) the entire point of a Track 1 submission is third-party verifiability
- a standard nobody can independently check is not one operators can trust enough to adopt. We'd
rather defenders can run `validation/run_checks.py` in seconds and see exactly what still fails than
keep the failure modes undocumented.
