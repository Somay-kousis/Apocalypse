"""Scorecard runner. Loads control_spec.yaml, runs every checker against a target
config dir (broken or fixed), prints N-of-9. OFFLINE - no keys, no network, seconds.

Usage:
  python -m validation.run_checks --target environments/broken_lab/configs
  python -m validation.run_checks --target environments/fixed_lab/configs
"""
import argparse, importlib
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit("pip install pyyaml  (it's in requirements.txt)")

SPEC = Path(__file__).resolve().parent.parent / "controls" / "control_spec.yaml"

def load_controls():
    return yaml.safe_load(SPEC.read_text())["controls"]

def run(target: str):
    controls = load_controls()
    results, passed = [], 0
    for c in controls:
        mod_path, fn = c["check_module"].split(":")
        try:
            mod = importlib.import_module(mod_path)
            res = getattr(mod, fn)(target)
        except (ModuleNotFoundError, AttributeError):
            from controls.base import CheckResult
            res = CheckResult(c["id"], c["name"], "SKIP", "checker not implemented yet")
        results.append(res)
        if res.status == "PASS":
            passed += 1
    print(f"\n=== Containment scorecard: {target} ===")
    for r in results:
        print(" ", r)
    implemented = [r for r in results if r.status != "SKIP"]
    print(f"\n  {passed}/{len(controls)} controls PASS "
          f"({len(implemented)} implemented, {len(controls)-len(implemented)} pending)")
    return results

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="path to a target configs/ dir")
    run(ap.parse_args().target)
