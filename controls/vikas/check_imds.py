"""Rule 6: IMDS hop-limit 1 or link-local denied; SA token automount off.

Structured YAML audit (artifact_type: yaml in control_spec.yaml).
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b6_imds"
CONFIG_FILE = "pod_spec.yaml"


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: pod spec is unconstrained (broken default)")

    spec = yaml.safe_load(cfg.read_text()) or {}
    problems = []

    if spec.get("automountServiceAccountToken"):
        problems.append("automountServiceAccountToken is true")

    imds = spec.get("imds") or {}
    imds_locked = imds.get("hop_limit") == 1 or imds.get("link_local_denied") is True
    if not imds_locked:
        problems.append(f"IMDS reachable: hop_limit={imds.get('hop_limit')}, "
                         f"link_local_denied={imds.get('link_local_denied')}")

    if problems:
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(6, "IMDS + SA-token lockdown", "PASS",
                        "IMDS blocked, SA token automount off", evidence=[str(cfg)])
