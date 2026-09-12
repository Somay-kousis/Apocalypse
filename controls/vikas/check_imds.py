"""Rule 6: IMDS blocked (link-local denied, or IMDSv2-only + hop-limit 1); SA token
automount off.

Structured YAML audit (artifact_type: yaml in control_spec.yaml).

"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b6_imds"
CONFIG_FILE = "pod_spec.yaml"

# Any non-numeric or missing hop_limit is treated as the insecure default (AWS's
# actual default hop limit is 2), not as "unset = ok".
_INSECURE_DEFAULT_HOP_LIMIT = 2


def _hop_limit(imds: dict) -> int:
    try:
        return int(imds.get("hop_limit"))
    except (TypeError, ValueError):
        return _INSECURE_DEFAULT_HOP_LIMIT


def _http_tokens(imds: dict) -> str:
    return str(imds.get("http_tokens", imds.get("httpTokens", ""))).strip().lower()


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: pod spec is unconstrained (broken default)")

    spec = yaml.safe_load(cfg.read_text()) or {}
    problems = []

    if spec.get("automountServiceAccountToken") is not False:
        problems.append(f"automountServiceAccountToken is {spec.get('automountServiceAccountToken')!r}, "
                         f"must be boolean false")

    imds = spec.get("imds") or {}
    link_local_denied = imds.get("link_local_denied") is True
    hop_limit = _hop_limit(imds)
    http_tokens = _http_tokens(imds)

    if link_local_denied:
        imds_locked = True
    elif hop_limit == 1 and http_tokens == "required":
        imds_locked = True
    else:
        imds_locked = False
        reasons = [f"link_local_denied={imds.get('link_local_denied')!r}"]
        if http_tokens != "required":
            reasons.append(f"http_tokens={http_tokens or 'unset'!r} (IMDSv1 still reachable; must be 'required')")
        if hop_limit != 1:
            reasons.append(f"hop_limit={hop_limit} (must be 1)")
        problems.append("IMDS reachable: " + ", ".join(reasons))

    if problems:
        return CheckResult(6, "IMDS + SA-token lockdown", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(6, "IMDS + SA-token lockdown", "PASS",
                        "IMDS blocked (link-local denied or IMDSv2-only + hop-limit 1), "
                        "SA token automount off", evidence=[str(cfg)])
