"""IMDS + SA-token lockdown (control 6). See controls/control_spec.yaml for pass_condition + verification.
Signature is fixed so validation/run_checks.py can call it. IMPLEMENT the body.
"""
from controls.base import CheckResult

def run(target_dir: str) -> CheckResult:
    # TODO(owner): read target config under target_dir, decide PASS/FAIL,
    # attach inspectable evidence. Pattern: controls/somay/check_hdf5.py
    raise NotImplementedError("control 6 not implemented")
