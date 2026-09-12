"""Replay the PUBLISHED incident steps against a target's controls.

IMPORTANT: there is NO 17,600-action corpus. HF published 8 phase totals + 14 example
commands (see analysis/data/incident_public_record.json). This replays those 14 documented
steps: each maps to the rule that should block it, and we report block-rate per target.
OFFLINE - no keys, no network.

Usage:
  python -m validation.replay_attack --target environments/broken_lab/configs
"""
import argparse, json
from pathlib import Path
from validation.run_checks import run as run_checks

RECORD = Path(__file__).resolve().parent.parent / "analysis" / "data" / "incident_public_record.json"

def main(target: str):
    rec = json.loads(RECORD.read_text())
    results = {r.rule_id: r for r in run_checks(target)}
    print(f"\n=== Replay of {len(rec['commands'])} documented attacker steps vs {target} ===")
    blocked = 0
    for cmd in rec["commands"]:
        rid = cmd["rule"]
        res = results.get(rid)
        state = res.status if res else "SKIP"
        is_blocked = state == "PASS"
        blocked += is_blocked
        tag = "BLOCKED" if is_blocked else ("open" if state == "FAIL" else "unchecked")
        print(f"  [{tag:9}] rule {rid}  {cmd['t']}  {cmd['cmd'][:64]}")
    print(f"\n  {blocked}/{len(rec['commands'])} documented steps blocked by current controls")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    main(ap.parse_args().target)
