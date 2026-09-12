"""OPTIONAL stretch goal - the ONLY component that needs an API key.

The core deliverable (run_checks.py + replay_attack.py) is fully offline and needs no keys;
judges run it in seconds. This adds an LLM that tries ALTERNATIVE lateral movement (not the
14 known commands) to measure whether controls hold against paths outside the public record.
Do NOT put this on the critical path. Cut first if time is short.
"""
import os

def run_adaptive_trials(n: int = 10, target: str = "environments/fixed_lab/configs"):
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("SKIP: adaptive agent needs ANTHROPIC_API_KEY. Core suite is offline; run that instead.")
        return
    raise NotImplementedError("stretch goal - implement only after all 9 offline checks pass")

if __name__ == "__main__":
    run_adaptive_trials()
