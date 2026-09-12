"""IMDS + SA-token lockdown (control 6). Type-safe: non-integer hop limit fails closed,
not crashes. Missing hop limit assumes AWS default (2) => must have link-local denied."""
from pathlib import Path
import json
from controls.base import CheckResult

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "pod_spec.json"
    if not cfg.exists():
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL", "missing pod_spec.json")
    d = json.loads(cfg.read_text())
    if d.get("automountServiceAccountToken", True) is not False:
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                           "automountServiceAccountToken must be explicitly false")
    raw = d.get("imds_hop_limit", 2)  # AWS default is 2
    try:
        hop = int(raw)
    except (TypeError, ValueError):
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                           f"imds_hop_limit not an integer: {raw!r} (fail-closed)")
    link_local_denied = d.get("link_local_denied", False) is True
    if hop > 1 and not link_local_denied:
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                           f"hop_limit={hop} reaches metadata and link-local not denied")
    return CheckResult(6, "IMDS + SA-token lockdown", "PASS", "IMDS blocked, SA-token automount false.")
