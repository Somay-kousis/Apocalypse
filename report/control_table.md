# Control Matrix

Maps each of the 9 trust-boundary crossings from the July 2026 incident to a verifiable control.
"Verification" columns assume NO lab network access (Track 1's literal success bar).
SoK class refers to arXiv:2607.25379 (paper 1).

| # | Boundary crossed | Requirement | Verify (no lab access) | Detection SLA | Adoption Cost | SoK class | Tested vs spec |
|---|------------------|-------------|------------------------|---------------|---------------|-----------|----------------|
| 1 | Zero-day in shared package registry | Sealed, read-only mirrors with no shared-infra access. | Hash-attested mirror manifest audit. | Mirror-hash mismatch alerts at pull time (<1 min). | Medium - requires per-eval sealed mirror infra. | supply-chain & credential exposure | spec-only |
| 2 | Internet access | Outbound blocked by default, short allowlist. | Egress policy diff against declared allowlist. | Repeated denied egress alerts (<5 min). | Low-medium - NetworkPolicy / firewall rules. | persistent command-and-control | tested |
| 3 | Arbitrary C code execution as root | Non-root, no added capabilities, no egress. | Container security-context audit. | Privileged-syscall / seccomp violation alert (<1 min). | Low - security-context fields. | objectives conflicting with sandbox boundaries | tested |
| 4 | HDF5 external-storage access | Loader blocks external references. | Signed config-schema test suite (SHARED with #5). | External-ref load attempt logged + alert (<1 min). | Low - loader policy + schema. | multi-step offensive chains | tested |
| 5 | Jinja2 template injection | Untrusted configs are never templated. | Same signed config-schema test suite as #4. | Template-on-config attempt fails at build/pre-deploy (not runtime). | Low - parse config as data (yaml.safe_load). | multi-step offensive chains | tested |
| 6 | Cloud metadata access | IMDS blocked, SA token automount off. | Pod-spec audit. | Link-local egress / token-read attempt alert (<1 min). | Low - pod-spec + NetworkPolicy. | supply-chain & credential exposure | tested |
| 7 | Cluster API access | Workers denied control-plane access. | RBAC-graph reachability check. | API-server access from data-plane alert (<1 min). | Medium - NetworkPolicy + RBAC review. | multi-step offensive chains | tested |
| 8 | Unauthorized Tailscale startup | No reusable keys in worker env; startup detected. | Secret-scanning + alert-log schema check. (Decoder-aware matcher: unpack base64/gzip, then match sequence.) | VPN-binary startup / authkey use alert (<1 min). | Low-medium - secret scan + detection rule. | persistent command-and-control | tested |
| 9 | Stolen credentials | Credentials scoped to origin/purpose; no identity's COMBINED reach across #6-8 exceeds a declared blast-radius bound. | Credential-scope audit (replay exfil vs Biscuit-attenuated tokens) + min-cut reachability over RBAC/IAM/connector configs (networkx). | Off-origin token use rejected + alert (<1 min); blast-radius recomputed on every IAM change. | High - workload identity + IAM graph modeling. | supply-chain & credential exposure | tested |

Headline number (see `analysis/threshold_model.ipynb`): back-tested per-identity action-rate
threshold against the public day counts (07-11 spike = 7,677 actions) -> 41.6 hours-earlier quarantine.
