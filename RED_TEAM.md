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

## Post-fix scorecard (offline, seconds)
- `fixed_lab`      -> 9/9 PASS (was silently 7/9 until the hdf5/jinja path fix above)
- `broken_lab`     -> 0/9 (real July-2026 misconfig)
- `exploit_lab`    -> 0/9 (round-1 attacker configs; now includes b2/b6/b7 fixtures)
- `adversarial_lab`-> 0/9 (round-2, these bypasses; now includes b2/b6/b7 fixtures)
- malformed JSON   -> fails the affected rule, suite still completes (fail-closed)

## Known limitations (be honest in the report)
- Mock-level: checkers audit JSON/text config surfaces, not a live cluster. Same shape as a real
  static admission audit, but a real deployment needs the runtime probe (stretch goal).
- Node role inference is substring-based (`worker`/`api`/`control`) - can over-match; fails safe
  (over-flags) rather than under-flags. A real version keys off labels/roles, not names.
