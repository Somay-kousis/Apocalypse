"""Rule 2: outbound egress default-deny, short domain+SNI allowlist.

Structured YAML audit (artifact_type: yaml in control_spec.yaml).
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b2_egress"
CONFIG_FILE = "egress_policy.yaml"


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(2, "Egress default-deny", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: egress is unconstrained (broken default)")

    policy = yaml.safe_load(cfg.read_text()) or {}
    problems = []

    if policy.get("default") != "deny":
        problems.append(f"default is {policy.get('default')!r}, not 'deny'")

    allowlist = policy.get("allowlist") or []
    bad_entries = [e for e in allowlist if not e.get("domain") or not e.get("sni") or e.get("domain") == "*"]
    if bad_entries:
        problems.append("allowlist contains wildcard or incomplete domain/SNI entries")

    if problems:
        return CheckResult(2, "Egress default-deny", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(2, "Egress default-deny", "PASS",
                        f"default-deny with {len(allowlist)} allowlisted domain(s)",
                        evidence=[str(cfg)])
