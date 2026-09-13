# Controls - Junyi (rules 1, 3, 8)

Security lead. Rules and checkers (see `../control_spec.yaml` for the canonical schema).

- **Rule 1** Package registry seal - hash-attested read-only mirror; no path to shared proxy;
  validate every SHA-256 pin against the corresponding offline artifact and reject path escapes.
  This proves integrity relative to the supplied manifest, not publisher authenticity: the offline
  audit has no external signature, transparency log, or separately trusted hash reference.
  Incident: `0-day in package registry cache proxy`. -> `check_registry.py`
- **Rule 3** Rootless code execution - non-root, privileged/escalation disabled, read-only rootfs,
  all capabilities dropped, confined seccomp, and no outbound access.
  Incident: `id -> uid=0(root)`, `python3 /tmp/submitted_code.c`. -> `check_sandbox.py`
- **Rule 8** No reusable VPN keys + startup/decoder detection. This is your research edge:
  the bounded decoder-aware matcher recursively unpacks standard and URL-safe base64, base32, hex,
  percent-URL encoding, and gzip before matching. These are the exact covered formats; arbitrary
  encryption and unknown encodings are outside the claim. The checker independently correlates the
  *sequence* (env dump -> staged binary -> IMDS -> VPN start) for every workload containing an
  attack-sequence event and requires every event to be detected within the 60-second SLA.
  Incident: `tailscaled --socks5-server`, `exec(gzip.decompress(base64...))`. -> `check_tailscale.py`

Each checker: `def run(target_dir: str) -> controls.base.CheckResult`. Copy the pattern in
`../somay/check_hdf5.py`. Also owns: report threat-model section + dual-use appendix (required).
