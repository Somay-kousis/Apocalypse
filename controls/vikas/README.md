# Controls - Vikas (rules 2, 6, 7)

AWS SAA-certified - owns the cloud/IAM/network controls.

- **Rule 2** Egress default-deny - allowlist by domain + SNI.
  Incident: `curl http://<internal-svc>`, `POST /<uuid> <-- env+secrets`. -> `check_egress.py`
  Deepened beyond "is the field non-empty": rejects domain/SNI mismatches (domain-fronting),
  IP literals in place of a hostname, wildcards anywhere (not just a bare `*`), bare/single-label
  entries, and an empty allowlist (fail-closed). Case/trailing-dot normalized so legitimate
  entries aren't over-flagged.
- **Rule 6** IMDS + SA-token lockdown - IMDSv2-only + hop-limit 1, or link-local deny; automount off.
  Incident: `cat .../serviceaccount/token`, `curl 169.254.169.254`. -> `check_imds.py`
  Deepened: a hop-limit of 1 alone is not sufficient - it must be paired with
  `http_tokens: required` (IMDSv2-only) unless link-local is denied outright at the network
  layer. Also fail-closed on type-confusion (`hop_limit` as a non-numeric string,
  `automountServiceAccountToken` as a non-boolean truthy string).
- **Rule 7** Control-plane unreachable from workers.
  Incident: `curl kubernetes.default.svc/api`. -> `check_controlplane.py`
  Deepened: models NetworkPolicy (`network_reachable`) and RBAC (`rbac_permitted`) as two
  independent layers per edge instead of one collapsed `allowed` flag. A path is only
  exploitable if BOTH layers agree at every hop; edges where only one layer is currently
  blocking are surfaced as a hardening note (single point of failure) even when the overall
  result is PASS. Legacy `allowed: bool` edges are still accepted for backward compatibility.

Each checker: `def run(target_dir: str) -> controls.base.CheckResult`. Also owns: 8-page report
lead, the trust-boundary figure, the video.

Red-teamed against `environments/adversarial_lab/configs/{b2_egress,b6_imds,b7_controlplane}/`
and `environments/exploit_lab/configs/{...}` (added alongside this deepening - these boundaries
had no adversarial fixtures before, so the checkers were never actually proven robust against
bypass attempts; see `RED_TEAM.md` rows 2b-2d, 6b, 7b). 27 unit tests in
`tests/test_check_{egress,imds,controlplane}.py` cover both the happy path and every bypass
above.

**Note for the team:** while validating the "fixed 9/9" headline, found that
`controls/somay/check_hdf5.py` and `check_jinja.py` were reading their config file from the
target-dir root instead of `b4_hdf5/` / `b5_jinja/`, so `fixed_lab` was silently scoring 7/9, not
9/9. Fixed the one-line path in both (see `RED_TEAM.md`) - flagging here since those files aren't
in this lane; worth a quick confirm with Somay before submission.
