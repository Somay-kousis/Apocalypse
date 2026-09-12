"""Rule 2: outbound egress default-deny, short domain+SNI allowlist.

Structured YAML audit (artifact_type: yaml in control_spec.yaml).

"""
import ipaddress
import re
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b2_egress"
CONFIG_FILE = "egress_policy.yaml"

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _canonical(value) -> str:
    """Lowercase + strip a trailing dot so 'PyPI.org.' and 'pypi.org' compare equal."""
    return str(value).strip().lower().rstrip(".")


def _domain_problem(domain_raw, sni_raw) -> str | None:
    """Return a reason this allowlist entry is unsafe, or None if it's fine."""
    if not domain_raw or not sni_raw:
        return "missing domain or sni"

    domain, sni = _canonical(domain_raw), _canonical(sni_raw)

    if "*" in domain or "*" in sni:
        return f"wildcard in domain/sni ({domain_raw!r}/{sni_raw!r})"
    if _is_ip_literal(domain) or _is_ip_literal(sni):
        return f"IP literal used instead of a domain ({domain_raw!r}/{sni_raw!r}) - bypasses DNS-based filtering"
    if domain != sni:
        return f"domain ({domain!r}) and sni ({sni!r}) disagree - domain-fronting shape"

    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
        return f"not a fully-qualified domain: {domain!r}"

    return None


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
    if not allowlist:
        problems.append("allowlist is empty (fail-closed: an unreachable-by-design "
                         "allowlist can't be verified, treat as unconstrained)")

    bad_entries = []
    seen_canonical = set()
    for e in allowlist:
        reason = _domain_problem(e.get("domain"), e.get("sni"))
        if reason:
            bad_entries.append(reason)
            continue
        canon = _canonical(e.get("domain"))
        if canon in seen_canonical:
            bad_entries.append(f"duplicate allowlist entry: {canon!r}")
        seen_canonical.add(canon)

    if bad_entries:
        problems.append("; ".join(bad_entries))

    if problems:
        return CheckResult(2, "Egress default-deny", "FAIL",
                            "; ".join(problems), evidence=[str(cfg)])

    return CheckResult(2, "Egress default-deny", "PASS",
                        f"default-deny with {len(allowlist)} allowlisted domain(s), "
                        f"each with matching domain+SNI, no wildcards/IP literals",
                        evidence=[str(cfg)])
