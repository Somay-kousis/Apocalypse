# Controls - Junyi (rules 1, 3, 8)

Security lead. Rules and checkers (see `../control_spec.yaml` for the canonical schema).

- **Rule 1** Package registry seal - hash-attested read-only mirror; no path to shared proxy.
  Incident: `0-day in package registry cache proxy`. -> `check_registry.py`
- **Rule 3** Rootless code execution - non-root, seccomp, dropped caps, no outbound.
  Incident: `id -> uid=0(root)`, `python3 /tmp/submitted_code.c`. -> `check_sandbox.py`
- **Rule 8** No reusable VPN keys + startup/decoder detection. This is your research edge:
  the decoder-aware matcher unpacks nested base64/gzip before pattern-matching, then flags the
  *sequence* (env dump -> staged binary -> IMDS -> VPN start), answering HF's stated blind spot.
  Incident: `tailscaled --socks5-server`, `exec(gzip.decompress(base64...))`. -> `check_tailscale.py`

Each checker: `def run(target_dir: str) -> controls.base.CheckResult`. Copy the pattern in
`../somay/check_hdf5.py`. Also owns: report threat-model section + dual-use appendix (required).
