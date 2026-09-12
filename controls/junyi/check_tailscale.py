"""No reusable VPN keys + startup detection (control 8). Adds a max key-lifetime bound so
'ephemeral' keys with 100-year expiration cannot pass."""
from pathlib import Path
import json
from controls.base import CheckResult

MAX_KEY_HOURS = 24  # ephemeral means short-lived

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "vpn_config.json"
    if not cfg.exists():
        return CheckResult(8, "No reusable VPN keys", "FAIL", "missing vpn_config.json")
    d = json.loads(cfg.read_text())
    if d.get("reusable_keys", True) is not False:
        return CheckResult(8, "No reusable VPN keys", "FAIL", "reusable_keys must be explicitly false")
    if d.get("ephemeral_keys") is not True:
        return CheckResult(8, "No reusable VPN keys", "FAIL", "ephemeral_keys must be true")
    exp = d.get("key_expiration_hours", MAX_KEY_HOURS)
    try:
        exp = float(exp)
    except (TypeError, ValueError):
        return CheckResult(8, "No reusable VPN keys", "FAIL", f"key_expiration_hours not numeric: {exp!r}")
    if exp > MAX_KEY_HOURS:
        return CheckResult(8, "No reusable VPN keys", "FAIL",
                           f"key_expiration_hours={exp} exceeds max {MAX_KEY_HOURS}h (not ephemeral)")
    if d.get("decoder_detection") is not True:
        return CheckResult(8, "No reusable VPN keys", "FAIL", "decoder-obfuscated payload detection off")
    return CheckResult(8, "No reusable VPN keys", "PASS", "ephemeral short-lived keys; startup detected.")
