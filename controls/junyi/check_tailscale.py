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
import io
import json
import re
from pathlib import Path
from controls.base import CheckResult
from validation.sla import calculate_latency_seconds, parse_aware_timestamp

BOUNDARY_DIR = "b8_tailscale"
ENV_FILE = "worker_env.txt"
LOG_FILE = "alert_log.jsonl"

# Tailscale reusable (non-ephemeral) auth keys look like tskey-auth-<...>.
# "REUSABLE" markers appear in this repo's fixtures; a real key has no such
# marker, so the regex alone (not the marker) is what actually matters.
_AUTHKEY_RE = re.compile(r"tskey-auth-[a-zA-Z0-9_-]+")
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,16384}={0,2}")
_ENV_SETTING_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
MAX_KEY_HOURS = 24
MAX_DECODE_DEPTH = 4
MAX_DECODED_BYTES = 64 * 1024
REQUIRED_SEQUENCE = ("env_dump", "binary_stage", "imds_access", "vpn_binary_start")


def _decode_candidates(text: str):
    """Yield the raw text plus any base64 (optionally gzip-wrapped) substrings
    decoded, so an obfuscated authkey still gets caught."""
    queue = [(text, 0)]
    seen = {text}
    while queue:
        candidate, depth = queue.pop(0)
        yield candidate
        if depth >= MAX_DECODE_DEPTH:
            continue
        for tok in _B64_TOKEN_RE.findall(candidate):
            try:
                raw = base64.b64decode(tok, validate=True)
            except Exception:
                continue
            if len(raw) > MAX_DECODED_BYTES:
                continue
            if raw.startswith(b"\x1f\x8b"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                        raw = gz.read(MAX_DECODED_BYTES + 1)
                except (OSError, EOFError):
                    continue
                if len(raw) > MAX_DECODED_BYTES:
                    continue
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded and decoded not in seen:
                seen.add(decoded)
                queue.append((decoded, depth + 1))


def _find_reusable_authkey(text: str):
    for candidate in _decode_candidates(text):
        m = _AUTHKEY_RE.search(candidate)
        if m:
            return m.group(0), candidate != text
    return None, False


def _env_settings(text: str):
    settings = {}
    for line in text.splitlines():
        match = _ENV_SETTING_RE.match(line.strip())
        if match:
            settings[match.group(1)] = match.group(2).strip()
    return settings


def _validate_detection_sequence(events):
    """Independently reconstruct the attack sequence for one workload.

    The final event's `sequence_matched` claim is deliberately ignored.  The
    checker derives correlation and order from the individual evidence rows.
    """
    by_workload = {}
    for event in events:
        workload = event.get("workload_id")
        if not isinstance(workload, str) or not workload:
            continue
        by_workload.setdefault(workload, []).append(event)

    errors = []
    for workload, workload_events in by_workload.items():
        selected = []
        cursor = 0
        for event in workload_events:
            if cursor >= len(REQUIRED_SEQUENCE):
                break
            if event.get("event") != REQUIRED_SEQUENCE[cursor]:
                continue
            if event.get("detected") is not True:
                errors.append(f"{event.get('event')} for {workload} was not detected")
                break
            try:
                occurred = parse_aware_timestamp(event.get("occurred_at"), "occurred_at")
                latency = calculate_latency_seconds(
                    event.get("occurred_at"), event.get("alerted_at")
                )
            except (TypeError, ValueError) as exc:
                errors.append(f"invalid detection timestamp for {workload}: {exc}")
                break
            selected.append((event, occurred, latency))
            cursor += 1

        if cursor != len(REQUIRED_SEQUENCE):
            continue
        occurred_times = [occurred for _, occurred, _ in selected]
        if occurred_times != sorted(occurred_times):
            errors.append(f"attack sequence is out of order for {workload}")
            continue
        latency = selected[-1][2]
        if latency > 60:
            errors.append(f"vpn startup alert missed <1 min SLA for {workload}: {latency:.0f}s")
            continue
        return True, []

    if not errors:
        errors.append(
            "no single workload has the detected sequence "
            + " -> ".join(REQUIRED_SEQUENCE)
        )
    return False, errors


def run(target_dir: str) -> CheckResult:
    env_path = Path(target_dir) / BOUNDARY_DIR / ENV_FILE
    log_path = Path(target_dir) / BOUNDARY_DIR / LOG_FILE
    if not env_path.exists() or not log_path.exists():
        return CheckResult(8, "No reusable VPN keys", "FAIL",
                            f"missing {BOUNDARY_DIR}/{ENV_FILE} or {BOUNDARY_DIR}/{LOG_FILE}: "
                            "worker env / detection evidence unverified")

    problems = []
    env_text = env_path.read_text()
    key_hit, was_decoded = _find_reusable_authkey(env_text)
    if key_hit:
        how = "decoder-obfuscated (base64/gzip)" if was_decoded else "plaintext"
        problems.append(f"Tailscale authkey found in worker env ({how}): {key_hit}")

    settings = _env_settings(env_text)
    if settings.get("TS_AUTHKEY_MODE") != "ephemeral":
        problems.append("TS_AUTHKEY_MODE must be ephemeral")
    try:
        expiration_hours = int(settings.get("TS_AUTHKEY_EXPIRATION_HOURS", ""))
    except ValueError:
        expiration_hours = None
    if expiration_hours is None or not (0 < expiration_hours <= MAX_KEY_HOURS):
        problems.append(
            f"TS_AUTHKEY_EXPIRATION_HOURS must be an integer from 1 to {MAX_KEY_HOURS}"
        )

    log_lines = [l for l in log_path.read_text().splitlines() if l.strip()]
    events = []
    for line_number, line in enumerate(log_lines, 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"alert log line {line_number} is not valid JSON")
            continue
        if not isinstance(event, dict):
            problems.append(f"alert log line {line_number} is not a JSON object")
            continue
        events.append(event)

    detected, sequence_errors = _validate_detection_sequence(events)
    if not detected:
        problems.extend(sequence_errors)

    if problems:
        return CheckResult(8, "No reusable VPN keys", "FAIL",
                            "; ".join(problems), evidence=[str(env_path), str(log_path)])

    return CheckResult(8, "No reusable VPN keys", "PASS",
                        "no authkey in worker env (plaintext or decoded); ephemeral key policy <=24h; "
                        "full attack sequence correlated and VPN startup alerted within 1 minute.",
                        evidence=[str(env_path), str(log_path)])
