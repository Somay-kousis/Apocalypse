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

## Post-fix scorecard (offline, seconds)
- `fixed_lab`      -> 9/9 PASS
- `broken_lab`     -> 0/9 (real July-2026 misconfig)
- `exploit_lab`    -> 0/9 (round-1 attacker configs)
- `adversarial_lab`-> 0/9 (round-2, these bypasses)
- malformed JSON   -> fails the affected rule, suite still completes (fail-closed)

## Known limitations (be honest in the report)
- Mock-level: checkers audit JSON/text config surfaces, not a live cluster. Same shape as a real
  static admission audit, but a real deployment needs the runtime probe (stretch goal).
- Node role inference is substring-based (`worker`/`api`/`control`) - can over-match; fails safe
  (over-flags) rather than under-flags. A real version keys off labels/roles, not names.
