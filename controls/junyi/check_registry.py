"""Package registry seal (control 1). Structured YAML audit (artifact_type: yaml
in control_spec.yaml): sealed + hash-attested mirror manifest, no route to
shared registry infra, every package pinned with a sha256.

Reads b1_registry/mirror_manifest.yaml, per control_spec.yaml's boundary_dir /
config_file for this rule - NOT a root-level registry.json (that was a stale
legacy path that never matched the declared spec or the b1_registry fixtures
red-teamed in exploit_lab/adversarial_lab).
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b1_registry"
CONFIG_FILE = "mirror_manifest.yaml"


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(1, "Package registry seal", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: registry mirror is unconstrained (broken default)")

    manifest = yaml.safe_load(cfg.read_text()) or {}
    problems = []

    # Fail-closed on missing keys: truthy strings ("pinky-promise") do NOT count,
    # only real booleans.
    if manifest.get("sealed") is not True:
        problems.append(f"sealed must be boolean true (got {manifest.get('sealed')!r})")
    if manifest.get("hash_attested") is not True:
        problems.append(f"hash_attested must be boolean true, not a truthy string (got {manifest.get('hash_attested')!r})")
    if manifest.get("route_to_shared_registry") is not False:
        problems.append("route_to_shared_registry must be explicitly false "
                         "(missing/truthy => route to shared registry infra is open)")

    packages = manifest.get("packages") or []
    if not packages:
        problems.append("no packages declared (fail-closed: an empty manifest can't be verified)")
    missing_hash = [p.get("name", "<unnamed>") for p in packages if not p.get("sha256")]
    if missing_hash:
        problems.append(f"package(s) missing sha256 pin: {', '.join(missing_hash)}")

    if problems:
        return CheckResult(1, "Package registry seal", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(1, "Package registry seal", "PASS",
                        "Hash-attested mirror isolated from shared infra.", evidence=[str(cfg)])
