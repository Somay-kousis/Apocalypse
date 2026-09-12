# Control Matrix

Maps each of the 9 trust-boundary crossings from the July 2026 incident to a verifiable control.
"Verification" columns assume NO lab network access (Track 1's literal success bar).
SoK class refers to arXiv:2607.25379 (paper 1).

| # | Boundary crossed | Requirement | Verify (no lab access) | SoK class | Tested vs spec |
|---|------------------|-------------|------------------------|-----------|----------------|
| 1 | Shared package registry (0-day) | Hash-attested read-only mirror, no path to shared proxy | Mirror-manifest audit | supply-chain & creds | spec-only |
| 2 | Public internet egress | Default-deny egress, allowlist by domain+SNI | Egress policy diff | persistent C2 | tested |
| 3 | 3rd-party sandbox, root code exec | Non-root, seccomp, dropped caps, no outbound | Container security-context audit | sandbox-boundary conflict | tested |
| 4 | HDF5 external raw storage | Loader refuses external refs; driver-restricted opens | Signed config-schema test | multi-step chains | tested |
| 5 | Jinja2 template injection | No template eval on untrusted config | Static scan of config paths | multi-step chains | tested |
| 6 | IMDS + SA token | IMDSv2 hop-limit 1 / link-local deny; automount off | Pod-spec audit | supply-chain & creds | tested |
| 7 | Cluster control-plane | Workers cannot reach API server | RBAC/NetworkPolicy reachability | multi-step chains | tested |
| 8 | Tailscale VPN pivot | No reusable authkeys; detect startup + encoded payloads | Secret-scan + decoder-aware matcher | persistent C2 | tested |
| 9 | Stolen credential reuse | Credentials bound to origin+purpose | Replay exfil vs Biscuit tokens | supply-chain & creds | tested |

Headline number (see `analysis/threshold_model.ipynb`): back-tested per-identity action-rate
threshold against the public day counts (07-11 spike = 7,677 actions) -> hours-earlier quarantine.
