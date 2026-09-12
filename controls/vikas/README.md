# Controls - Vikas (rules 2, 6, 7)

AWS SAA-certified - owns the cloud/IAM/network controls.

- **Rule 2** Egress default-deny - allowlist by domain + SNI.
  Incident: `curl http://<internal-svc>`, `POST /<uuid> <-- env+secrets`. -> `check_egress.py`
- **Rule 6** IMDS + SA-token lockdown - IMDSv2 hop-limit 1 / link-local deny; automount off.
  Incident: `cat .../serviceaccount/token`, `curl 169.254.169.254`. -> `check_imds.py`
- **Rule 7** Control-plane unreachable from workers.
  Incident: `curl kubernetes.default.svc/api`. -> `check_controlplane.py`

Each checker: `def run(target_dir: str) -> controls.base.CheckResult`. Also owns: 8-page report
lead, the trust-boundary figure, the video.
