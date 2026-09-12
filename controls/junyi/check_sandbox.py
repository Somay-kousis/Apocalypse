"""Rootless code execution (control 3). Spec: non-root, NO added capabilities, no egress.
Hardened: reject string/int root, privileged, privilege-escalation, ANY added cap,
and any seccomp profile outside the safe allowlist."""
from pathlib import Path
import json
from controls.base import CheckResult

SAFE_SECCOMP = {"RuntimeDefault", "Localhost"}

def _is_root(v):
    # accept int or numeric string; root is uid 0
    try:
        return int(v) == 0
    except (TypeError, ValueError):
        return False  # non-numeric handled by runAsNonRoot below

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "pod_spec.json"
    if not cfg.exists():
        return CheckResult(3, "Rootless code execution", "FAIL", "missing pod_spec.json")
    d = json.loads(cfg.read_text())
    if d.get("runAsNonRoot") is not True:
        return CheckResult(3, "Rootless code execution", "FAIL", "runAsNonRoot must be boolean true")
    if "runAsUser" in d and _is_root(d["runAsUser"]):
        return CheckResult(3, "Rootless code execution", "FAIL", f"runAsUser resolves to root: {d['runAsUser']!r}")
    if d.get("privileged") is True:
        return CheckResult(3, "Rootless code execution", "FAIL", "privileged:true overrides all isolation")
    if d.get("allowPrivilegeEscalation") is True:
        return CheckResult(3, "Rootless code execution", "FAIL", "allowPrivilegeEscalation must not be true")
    added = d.get("added_caps", [])
    if added:  # spec: NO added capabilities (denylists always miss one)
        return CheckResult(3, "Rootless code execution", "FAIL", f"no added capabilities allowed; found {added}")
    if d.get("seccomp_profile") not in SAFE_SECCOMP:
        return CheckResult(3, "Rootless code execution", "FAIL",
                           f"seccomp_profile must be one of {SAFE_SECCOMP} (got {d.get('seccomp_profile')!r})")
    return CheckResult(3, "Rootless code execution", "PASS", "non-root, no caps, seccomp confined.")
