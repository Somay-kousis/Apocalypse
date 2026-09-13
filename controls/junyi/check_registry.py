"""Package registry seal (control 1). Structured YAML audit (artifact_type: yaml
in control_spec.yaml): sealed + hash-attested mirror manifest, no route to
shared registry infra, every package pinned with a sha256.

Reads b1_registry/mirror_manifest.yaml, per control_spec.yaml's boundary_dir /
config_file for this rule - NOT a root-level registry.json (that was a stale
legacy path that never matched the declared spec or the b1_registry fixtures
red-teamed in exploit_lab/adversarial_lab).
"""
import hashlib
import re
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b1_registry"
CONFIG_FILE = "mirror_manifest.yaml"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

    boundary_root = cfg.parent.resolve()
    for package in packages:
        if not isinstance(package, dict):
            problems.append(f"invalid package entry: {package!r}")
            continue

        name = package.get("name", "<unnamed>")
        expected = package.get("sha256")
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            problems.append(f"package {name} has no valid 64-hex sha256 pin")
            continue

        artifact_rel = package.get("artifact")
        if not isinstance(artifact_rel, str) or not artifact_rel.strip():
            problems.append(f"package {name} has no local artifact to verify")
            continue

        artifact_path = (boundary_root / artifact_rel).resolve()
        try:
            artifact_path.relative_to(boundary_root)
        except ValueError:
            problems.append(f"package {name} artifact escapes the sealed mirror directory")
            continue
        if not artifact_path.is_file():
            problems.append(f"package {name} artifact is missing: {artifact_rel}")
            continue

        actual = _sha256(artifact_path)
        if actual.lower() != expected.lower():
            problems.append(
                f"package {name} sha256 mismatch: expected {expected.lower()}, got {actual}"
            )

    if problems:
        return CheckResult(1, "Package registry seal", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(1, "Package registry seal", "PASS",
                        "Every local artifact matches its sha256 pin; mirror is sealed and isolated from shared infra.",
                        evidence=[str(cfg)])
