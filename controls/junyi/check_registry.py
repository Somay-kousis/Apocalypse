"""Package registry seal (control 1). Strict: attestation must be a real boolean True,
routing must be explicitly False. Truthy strings ("yes", "pinky-promise") do NOT count."""
from pathlib import Path
import json
from controls.base import CheckResult

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "registry.json"
    if not cfg.exists():
        return CheckResult(1, "Package registry seal", "FAIL", "missing registry.json")
    data = json.loads(cfg.read_text())
    # fail-closed on missing keys
    if data.get("route_to_shared_infra", True) is not False:
        return CheckResult(1, "Package registry seal", "FAIL",
                           "route_to_shared_infra must be explicitly false (missing/truthy => route open)")
    if data.get("mirror_attested") is not True:
        return CheckResult(1, "Package registry seal", "FAIL",
                           "mirror_attested must be boolean true (a hash-attested manifest, not a truthy string)")
    return CheckResult(1, "Package registry seal", "PASS",
                       "Hash-attested mirror isolated from shared infra.")
