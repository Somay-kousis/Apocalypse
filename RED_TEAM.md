# Red-team log - checker hardening

Adversarial review of the round-1 checkers. Each finding is a config that is INSECURE but
originally PASSed (a false negative), plus the fix. Reproduce with `environments/adversarial_lab/`.

| # | Bypass (insecure config that passed) | Root cause | Fix |
|---|--------------------------------------|-----------|-----|
| runner | one bad value (`imds_hop_limit:"1"`) crashed the WHOLE suite -> no scorecard | only 3 exception types caught | `run_checks` now fail-closed: any checker exception = that rule FAILs, suite continues |
| 1 | `mirror_attested:"pinky-promise"` (truthy string) passed as attested | truthiness vs boolean | require `is True` / `is False` |
| 2 | `["0.0.0.0/1","128.0.0.0/1","::/0"]` covers whole internet; none is `0.0.0.0/0`/`*` | substring match only | CIDR-parse; flag prefix < /8 (v4) / /32 (v6), IPv6, whitespace, wildcards |
| 3 | `runAsUser:"0"` + `privileged:true` + `CAP_SYS_MODULE` + `seccomp:"Unconfined"` | int-only root check; cap denylist; truthy seccomp | numeric root coercion; ban privileged/allowPrivEsc; reject ANY added cap; seccomp allowlist |
| 4 | active `allow_external_links:true` with a commented `false` decoy | naive substring | parse key:value, drop comments; block family/split drivers |
| 5 | `Template(x).render()` (direct import) not matched | narrow marker list | broadened render markers incl. `.render(`, `template(`, `jinja` |
| 6 | `imds_hop_limit:"2"` (string) crashed; permissive-as-string dodged | `str > int` TypeError | int-coerce, fail-closed on non-int; default 2 |
| 8 | ephemeral+non-reusable keys with `key_expiration_hours:876000` (100y) | expiration never checked | enforce MAX_KEY_HOURS=24 |
| 9a | one raw `bearer` token hidden behind a compliant biscuit (ANY-not-ALL) | loop set flags on any cred | require EVERY cred biscuit + origin()+purpose() |
| 9a | `origin(hacker_worker)` satisfied the `"worker"` substring | substring match | origin identity must be a real node in rbac.json |
| 9b | second worker held the path; only `workers[0]` audited | single-source min-cut | audit ALL worker nodes |
| 2b | `domain: pypi.org` / `sni: attacker.example` (domain-fronting: fields disagree) | only checked fields were non-empty, never compared them | require `domain == sni` after case/trailing-dot normalization |
| 2c | IP literal (`203.0.113.5`) in the domain field | no IP-vs-hostname distinction | reject IP literals (v4/v6) in domain/sni |
| 2d | `*.amazonaws.com` (subdomain wildcard, not a bare `*`) | wildcard check only matched literal `"*"` | reject any `*` anywhere in the string, plus bare/single-label entries |
| 6b | `hop_limit:"1"` (string) paired with `http_tokens` left unset - hop-limit alone looks compliant | rule 6 originally treated hop-limit 1 as sufficient on its own | require `http_tokens: required` (IMDSv2-only) whenever relying on the hop-limit path, not link-local deny |
| 7b | round-2: RBAC and NetworkPolicy collapsed into one `allowed` flag per edge, so a compromised RBAC binding riding a permissive NetworkPolicy hop looked identical to a single-layer partial block | one boolean conflated two independent controls | model `network_reachable` / `rbac_permitted` separately; an edge is only exploitable if BOTH agree; single-layer-open edges are now surfaced as a hardening note instead of being invisible |
| runner | `controls/somay/check_hdf5.py` / `check_jinja.py` read `loader_policy.txt` / `config_pipeline.txt` from the target dir root instead of `b4_hdf5/` / `b5_jinja/` - **fixed_lab scored 7/9, not the claimed 9/9** | path didn't match the boundary-dir convention every other checker uses | pointed both at their `b4_hdf5/` / `b5_jinja/` subdirs (Vikas found this while validating the 9/9 claim; flagged for Somay to confirm - outside the vikas/ lane) |
| runner-2 | Same bug class, missed the first time: `check_registry.py` / `check_sandbox.py` / `check_tailscale.py` (rules 1/3/8) read legacy root-level `registry.json` / `pod_spec.json` / `vpn_config.json` instead of their declared `b1_registry/` / `b3_sandbox/` / `b8_tailscale/` boundary dirs. `control_spec.yaml` and every test in `tests/test_check_registry.py` / `test_check_sandbox.py` / `test_check_tailscale.py` already assumed the correct paths and schema - **`pytest tests/` was 16 failing / 48 passing** because of this, not the "10 passed" the README/HANDOFF claimed. `exploit_lab`/`adversarial_lab` had no fixtures at all in `b1_registry/`, `b3_sandbox/`, or `b8_tailscale/`, so these three rules were never actually red-teamed even though the top-line scorecard read 0/9 there (the *unused* legacy root files happened to be insecure too, masking the bug) | copy-paste of the pre-boundary-dir convention into three checkers that were never updated when the convention was introduced for rules 4/5 | repointed all three at their boundary dirs with the schema the tests already expected; added real bypass fixtures to `exploit_lab`/`adversarial_lab` for rules 1/3/8/9 |
| 9c | `check_creds.py` (rule 9) declared `depends_on: [6, 7, 8]` in `control_spec.yaml` and `run_checks.py` already auto-detects and passes a `context` kwarg to any checker whose signature declares one - but `check_creds.run()` didn't accept `context` at all, so the cross-boundary composition (an identity's declared `reach` should shrink as upstream rules 6/7/8 pass) silently never ran; the six `context=...` calls in `tests/test_check_creds.py` failed with `TypeError` | signature drift: the checker was rewritten (real Ed25519 mint/replay) without carrying forward the `context` parameter the architecture already relied on | added `context: dict | None = None` to `check_creds.run()`; reach tags (`imds`/`control-plane`/`vpn-pivot`) now drop out of an identity's effective reach only when the matching upstream rule (6/7/8) already PASSed in `context` |
| 4b | `allow_external_links: false` passed even when a forbidden construct (e.g. a commented-out `H5Pset_external` call, described as a "legacy path") was still present in the same loader-policy file - the flag alone was treated as sufficient | checker only parsed the `key: value` flag, never scanned the raw text for forbidden constructs | added a raw-text scan for forbidden constructs (`H5Pset_external`, `set_external_storage`) that fails the rule regardless of what the flag says |
| 1b | Any non-empty `sha256` value passed, and no artifact bytes were hashed; a manifest could attest to a tampered file | presence check treated a claim as evidence | require 64 hex characters, confine artifact paths to the sealed mirror, require the file, and compare its computed SHA-256 |
| 3b | A context with `runAsNonRoot:true` could still set `privileged:true`, allow privilege escalation, keep a writable root filesystem, or omit `drop: [ALL]` | checker enforced only UID, added caps, seccomp, and egress | require strict false for privileged/escalation, strict true for read-only rootfs, and `drop: ALL` |
| 8b | One event could self-report `sequence_matched:true`; events from different workers, a slow alert, or a 100-year "ephemeral" policy were not independently rejected | trusted summary booleans and never correlated event evidence or calculated latency | correlate four ordered detected events for one workload, enforce VPN alert <=60s, and require ephemeral expiry <=24h |
| 8c | Repeated base64 wrapping could hide a gzip-packed auth key from the one-pass decoder | decoder inspected only the first encoding layer | bounded recursive decoding (4 layers, 64 KiB output cap) before auth-key matching |
| 8d | A reusable Tailscale auth key encoded as hex (likewise base32, URL-safe base64, or percent-URL encoding) passed the decoder-aware scan | decoder only attempted standard base64 and gzip even though its description implied broader decoder awareness | recursively attempt the explicitly documented standard/URL-safe base64, base32, hex, percent-URL, and gzip formats under the existing depth/output bounds; add one regression per format and a hex adversarial fixture |
| 8e | A complete detected sequence for one workload masked an undetected `vpn_binary_start` on another workload | sequence validation returned PASS on the first clean workload (ANY semantics) | audit every workload containing any required attack event and require each to have the complete, ordered, detected, on-time sequence (ALL semantics) |
| 7c | round-3: a benign api-named **decoy node** listed first shadowed a real, reachable API node - only `matches[0]` was checked as the reachability target | single-target identification after the round-2 structural-id fix | identify EVERY control-plane/API node (`_find_api_nodes`) and check reachability from every worker to ALL of them; fail-closed if none identifiable |
| 8f | round-3: a reusable authkey **ascii85/base85-encoded** (or zlib-compressed) evaded the base64/base32/hex/URL/gzip decoder set | base85/zlib not attempted | added a85/b85 decoding (also trying the post-`=` env value) and a zlib layer to the bounded recursive decoder; regression tests for both |

## Post-fix scorecard (offline, seconds)
- `fixed_lab`      -> 9/9 PASS (was silently 7/9 until the hdf5/jinja path fix above)
- `broken_lab`     -> 0/9 (real July-2026 misconfig)
- `exploit_lab`    -> 0/9 (round-1 attacker configs; now includes b1/b2/b3/b6/b7/b8/b9 fixtures)
- `adversarial_lab`-> 0/9 (round-2, these bypasses; now includes b1/b2/b3/b6/b7/b8/b9 fixtures)
- malformed JSON   -> fails the affected rule, suite still completes (fail-closed)
- `pytest tests/`  -> 118/118 passing; focused Rule 8 regressions now include each supported
  encoding and the multi-workload masking case

## Known limitations (be honest in the report)
- Mock-level: checkers audit JSON/text config surfaces, not a live cluster. Same shape as a real
  static admission audit, but a real deployment needs the runtime probe (stretch goal).
- Rule 1 proves supplied-artifact integrity relative to the supplied manifest, not publisher
  authenticity. A compromised mirror can replace both bytes and hashes; closing that gap requires
  an independent trust anchor such as a verified publisher signature or transparency-log reference.
- Rule 8's decoder coverage is deliberately finite: standard/URL-safe base64, base32, hex,
  percent-URL, and gzip, recursively up to four layers and 64 KiB decoded output. It does not claim
  to recognize arbitrary encryption or every possible serialization.
- Node role inference is substring-based (`worker`/`api`/`control`) - can over-match; fails safe
  (over-flags) rather than under-flags. A real version keys off labels/roles, not names.
