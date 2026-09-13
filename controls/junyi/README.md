# Controls - Junyi (rules 1, 3, 8)

Security lead. Rules and checkers (see `../control_spec.yaml` for the canonical schema).

- **Rule 1** Package registry seal - hash-attested read-only mirror; no path to shared proxy;
  validate every SHA-256 pin against the corresponding offline artifact and reject path escapes.
  Incident: `0-day in package registry cache proxy`. -> `check_registry.py`
- **Rule 3** Rootless code execution - non-root, privileged/escalation disabled, read-only rootfs,
  all capabilities dropped, confined seccomp, and no outbound access.
  Incident: `id -> uid=0(root)`, `python3 /tmp/submitted_code.c`. -> `check_sandbox.py`
- **Rule 8** No reusable VPN keys + startup/decoder detection. This is your research edge:
  the bounded decoder-aware matcher recursively unpacks nested base64/gzip before matching. The
  checker independently correlates the *sequence* (env dump -> staged binary -> IMDS -> VPN start)
  for one workload and calculates whether the VPN alert met the 60-second SLA.
  Incident: `tailscaled --socks5-server`, `exec(gzip.decompress(base64...))`. -> `check_tailscale.py`

Each checker: `def run(target_dir: str) -> controls.base.CheckResult`. Copy the pattern in
`../somay/check_hdf5.py`. Also owns: report threat-model section + dual-use appendix (required).
