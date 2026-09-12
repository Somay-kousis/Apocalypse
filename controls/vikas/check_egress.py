"""Egress default-deny (control 2). CIDR-aware: flags wildcards AND overly broad prefixes
(e.g. 0.0.0.0/1 + 128.0.0.0/1 that together cover the whole internet), IPv6 ::/0, and
whitespace-padded evasions. Prefix shorter than MIN_PREFIX is 'overly permissive'."""
from pathlib import Path
import json, ipaddress
from controls.base import CheckResult

MIN_V4_PREFIX = 8    # anything broader than /8 is too permissive for an allowlist
MIN_V6_PREFIX = 32

def _too_broad(entry: str):
    e = entry.strip()
    if not e:
        return "empty entry"
    if "*" in e:
        return f"wildcard: {e!r}"
    try:
        net = ipaddress.ip_network(e, strict=False)
    except ValueError:
        return None  # a domain name; treated as specific (mock scope)
    limit = MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX
    if net.prefixlen < limit:
        return f"overly broad CIDR: {e!r} (/{net.prefixlen})"
    return None

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "network_policy.json"
    if not cfg.exists():
        return CheckResult(2, "Egress default-deny", "FAIL", "missing network_policy.json")
    d = json.loads(cfg.read_text())
    if str(d.get("egress_default", "")).strip().lower() != "deny":
        return CheckResult(2, "Egress default-deny", "FAIL", "egress_default is not deny")
    for a in d.get("allowlist", []):
        reason = _too_broad(str(a))
        if reason:
            return CheckResult(2, "Egress default-deny", "FAIL", f"allowlist {reason}")
    return CheckResult(2, "Egress default-deny", "PASS", "deny-all default; allowlist is specific.")
