"""Rootless code execution (control 3). Structured YAML audit (artifact_type: yaml
in control_spec.yaml): non-root, no added capabilities, seccomp confined, no egress.

Reads b3_sandbox/security_context.yaml, per control_spec.yaml's boundary_dir /
config_file for this rule - NOT a root-level pod_spec.json (that was a stale
legacy path with a different, JSON-shaped schema that never matched the
declared spec, the b3_sandbox fixtures, or this checker's own tests).
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b3_sandbox"
CONFIG_FILE = "security_context.yaml"
SAFE_SECCOMP = {"RuntimeDefault", "Localhost"}


def _is_root(v) -> bool:
    try:
        return int(v) == 0
    except (TypeError, ValueError):
        return False


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(3, "Rootless code execution", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: security context is unconstrained (broken default)")

    ctx = yaml.safe_load(cfg.read_text()) or {}
    problems = []

    if ctx.get("runAsNonRoot") is not True:
        problems.append(f"runAsNonRoot must be boolean true (got {ctx.get('runAsNonRoot')!r})")
    if "runAsUser" in ctx and _is_root(ctx["runAsUser"]):
        problems.append(f"runAsUser resolves to root: {ctx['runAsUser']!r}")

    if ctx.get("privileged") is not False:
        problems.append(f"privileged must be boolean false (got {ctx.get('privileged')!r})")
    if ctx.get("allowPrivilegeEscalation") is not False:
        problems.append(
            "allowPrivilegeEscalation must be boolean false "
            f"(got {ctx.get('allowPrivilegeEscalation')!r})"
        )
    if ctx.get("readOnlyRootFilesystem") is not True:
        problems.append(
            "readOnlyRootFilesystem must be boolean true "
            f"(got {ctx.get('readOnlyRootFilesystem')!r})"
        )

    caps = ctx.get("capabilities") or {}
    added = caps.get("add") or []
    if added:  # spec: NO added capabilities (a denylist always misses one)
        problems.append(f"no added capabilities allowed; found {added}")
    dropped = {str(cap).upper() for cap in (caps.get("drop") or [])}
    if "ALL" not in dropped:
        problems.append("capabilities.drop must include ALL")

    seccomp_type = (ctx.get("seccompProfile") or {}).get("type")
    if seccomp_type not in SAFE_SECCOMP:
        problems.append(f"seccompProfile.type must be one of {SAFE_SECCOMP} (got {seccomp_type!r})")

    if ctx.get("allowEgress") is not False:
        problems.append(f"allowEgress must be boolean false (got {ctx.get('allowEgress')!r})")

    if problems:
        return CheckResult(3, "Rootless code execution", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(3, "Rootless code execution", "PASS",
                        "non-root, no privilege escalation, read-only rootfs, all caps dropped, seccomp confined, egress off.",
                        evidence=[str(cfg)])
