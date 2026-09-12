"""No reusable VPN keys + startup detection (control 8). Text audit
(artifact_type: text in control_spec.yaml): worker env must carry no reusable
Tailscale authkey, and the alert log must show real startup detection.

Reads b8_tailscale/worker_env.txt + b8_tailscale/alert_log.jsonl, per
control_spec.yaml's boundary_dir / config_file(s) for this rule - NOT a
root-level vpn_config.json (a stale legacy path with a self-declared-boolean
schema that trusted whatever a worker's own config claimed about itself,
rather than actually scanning the worker env or the detection log).

Decoder-aware matcher (HANDOFF's rule-8 contribution): a plain substring scan
of worker_env.txt misses a key that's been base64/gzip-obfuscated. We decode
any base64 (optionally gzip-wrapped) tokens found in the file before matching,
so an attacker can't dodge the authkey scan just by encoding the value.
"""
import base64
import gzip
import json
import re
from pathlib import Path
from controls.base import CheckResult

BOUNDARY_DIR = "b8_tailscale"
ENV_FILE = "worker_env.txt"
LOG_FILE = "alert_log.jsonl"

# Tailscale reusable (non-ephemeral) auth keys look like tskey-auth-<...>.
# "REUSABLE" markers appear in this repo's fixtures; a real key has no such
# marker, so the regex alone (not the marker) is what actually matters.
_AUTHKEY_RE = re.compile(r"tskey-auth-[a-zA-Z0-9_-]+")
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_candidates(text: str):
    """Yield the raw text plus any base64 (optionally gzip-wrapped) substrings
    decoded, so an obfuscated authkey still gets caught."""
    yield text
    for tok in _B64_TOKEN_RE.findall(text):
        try:
            raw = base64.b64decode(tok, validate=True)
        except Exception:
            continue
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass  # not gzip - try the raw decoded bytes as-is
        try:
            yield raw.decode("utf-8", errors="ignore")
        except Exception:
            continue


def _find_reusable_authkey(text: str):
    for candidate in _decode_candidates(text):
        m = _AUTHKEY_RE.search(candidate)
        if m:
            return m.group(0), candidate != text
    return None, False


def run(target_dir: str) -> CheckResult:
    env_path = Path(target_dir) / BOUNDARY_DIR / ENV_FILE
    log_path = Path(target_dir) / BOUNDARY_DIR / LOG_FILE
    if not env_path.exists() or not log_path.exists():
        return CheckResult(8, "No reusable VPN keys", "FAIL",
                            f"missing {BOUNDARY_DIR}/{ENV_FILE} or {BOUNDARY_DIR}/{LOG_FILE}: "
                            "worker env / detection evidence unverified")

    problems = []
    key_hit, was_decoded = _find_reusable_authkey(env_path.read_text())
    if key_hit:
        how = "decoder-obfuscated (base64/gzip)" if was_decoded else "plaintext"
        problems.append(f"reusable authkey found in worker env ({how}): {key_hit}")

    log_lines = [l for l in log_path.read_text().splitlines() if l.strip()]
    events = []
    for line in log_lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    detected = any(
        e.get("event") == "vpn_binary_start" and e.get("detected") is True and e.get("sequence_matched") is True
        for e in events
    )
    if not detected:
        problems.append("no vpn_binary_start event with detected+sequence_matched in alert log "
                         "(startup not proven to be caught)")

    if problems:
        return CheckResult(8, "No reusable VPN keys", "FAIL",
                            "; ".join(problems), evidence=[str(env_path), str(log_path)])

    return CheckResult(8, "No reusable VPN keys", "PASS",
                        "no reusable authkey in worker env (plaintext or decoded); "
                        "VPN startup detected with sequence match.",
                        evidence=[str(env_path), str(log_path)])
