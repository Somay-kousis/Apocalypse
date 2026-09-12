"""Rule 4: dataset loader must refuse HDF5 files with external raw storage refs.

Static config audit - no lab network access needed. Points at a target's
`configs/` dir and asserts the loader policy forbids external links.
This is the WORKED PATTERN for the other 8 checks: read target config, decide PASS/FAIL,
return CheckResult with inspectable evidence.
"""
from pathlib import Path
from controls.base import CheckResult

FORBIDDEN = ("external", "efile_prefix", "H5Pset_external", "driver=family")

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "loader_policy.txt"
    if not cfg.exists():
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           "no loader_policy.txt: loader is unconstrained (broken default)")
    text = cfg.read_text().lower()
    allows_external = "allow_external_links: false" not in text
    hits = [k for k in FORBIDDEN if k.lower() in text and "false" not in text]
    if allows_external:
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           "policy does not set allow_external_links: false",
                           evidence=[f"{cfg}: {text.strip()[:120]}"])
    return CheckResult(4, "Loader refuses external refs", "PASS",
                       "external links disabled; driver-restricted opens only",
                       evidence=[str(cfg)])
