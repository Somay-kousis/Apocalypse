"""Replay the PUBLISHED incident steps against a target's controls.

IMPORTANT: there is NO 17,600-action corpus. HF published 9 phase totals + a
handful of example commands (see analysis/data/incident_public_record.json).
This replays those documented steps: each rule-tagged step maps to the boundary
that should block it, and we report block-rate per target. Steps tagged
rule: null are context/detection-gap evidence (e.g. payload obfuscation,
generic recon) - they are shown but excluded from the block-rate denominator,
since they don't test any single boundary. OFFLINE - no keys, no network.

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

    testable = [c for c in rec["commands"] if c["rule"] is not None]
    context = [c for c in rec["commands"] if c["rule"] is None]

    print(f"\n=== Replay of {len(testable)} boundary-testing steps "
          f"({len(context)} context-only steps excluded) vs {target} ===")

    blocked = 0
    for cmd in testable:
        rid = cmd["rule"]
        res = results.get(rid)
        state = res.status if res else "SKIP"
        is_blocked = state == "PASS"
        blocked += is_blocked
        tag = "BLOCKED" if is_blocked else ("open" if state == "FAIL" else "unchecked")
        print(f"  [{tag:9}] rule {rid}  {cmd['t']}  {cmd['cmd'][:64]}")

    if context:
        print("\n  -- context-only steps (not counted, see command note) --")
        for cmd in context:
            print(f"  [context  ] {cmd['t']}  {cmd['cmd'][:64]}  -- {cmd.get('note', '')}")

    print(f"\n  {blocked}/{len(testable)} boundary-testing steps blocked by current controls")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    main(ap.parse_args().target)