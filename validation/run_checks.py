"""Scorecard runner. Loads control_spec.yaml, runs every checker against a target
config dir (broken or fixed), prints N-of-9. OFFLINE - no keys, no network, seconds.

Execution order respects each control's `depends_on` (only rule 9 declares one,
composing 6/7/8): dependencies run first, and their CheckResults are handed to
the dependent checker via a `context: dict[int, CheckResult]` kwarg. A checker
that doesn't need it just keeps the plain `run(target_dir)` signature - we only
pass `context` to callables that declare it, so rules 1-8 are untouched.

Usage:
  python -m validation.run_checks --target environments/broken_lab/configs
  python -m validation.run_checks --target environments/fixed_lab/configs
"""
import argparse
import importlib
import inspect
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit("pip install pyyaml  (it's in requirements.txt)")

from controls.base import CheckResult

SPEC = Path(__file__).resolve().parent.parent / "controls" / "control_spec.yaml"


def load_controls():
    return yaml.safe_load(SPEC.read_text())["controls"]


def _topological_order(controls):
    """Order controls so every id in a control's depends_on runs before it."""
    by_id = {c["id"]: c for c in controls}
    ordered, seen, visiting = [], set(), set()

    def visit(cid):
        if cid in seen:
            return
        if cid in visiting:
            raise ValueError(f"circular depends_on involving control {cid}")
        visiting.add(cid)
        for dep in by_id[cid].get("depends_on") or []:
            visit(dep)
        visiting.discard(cid)
        seen.add(cid)
        ordered.append(by_id[cid])

    for c in controls:
        visit(c["id"])
    return ordered


def _run_one(c: dict, target: str, context: dict) -> CheckResult:
    mod_path, fn_name = c["check_module"].split(":")
    try:
        mod = importlib.import_module(mod_path)
        fn = getattr(mod, fn_name)
    except (ModuleNotFoundError, AttributeError):
        return CheckResult(c["id"], c["name"], "SKIP", "checker not implemented yet")

    try:
        if "context" in inspect.signature(fn).parameters:
            return fn(target, context=context)
        return fn(target)
    except NotImplementedError as e:
        return CheckResult(
            c["id"],
            c["name"],
            "SKIP",
            f"checker not implemented yet ({e})",
        )
    except Exception as e:
        # FAIL-CLOSED: a checker that crashes on a hostile config must not
        # blind the whole scorecard. That one control fails; the rest still run.
        return CheckResult(
            c["id"],
            c["name"],
            "FAIL",
            f"checker raised {type(e).__name__}: {e} (fail-closed)",
        )


def run(target: str):
    controls = load_controls()
    ordered = _topological_order(controls)

    context: dict = {}  # rule_id -> CheckResult, available to controls with depends_on
    for c in ordered:
        context[c["id"]] = _run_one(c, target, context)

    # Report in the spec's declared (id) order, independent of execution order.
    results = [context[c["id"]] for c in controls]
    passed = sum(1 for r in results if r.status == "PASS")

    print(f"\n=== Containment scorecard: {target} ===")
    for r in results:
        print(" ", r)

    implemented = [r for r in results if r.status != "SKIP"]
    print(
        f"\n  {passed}/{len(controls)} controls PASS "
        f"({len(implemented)} implemented, {len(controls) - len(implemented)} pending)"
    )
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="path to a target configs/ dir")
    args = ap.parse_args()
    run(args.target)
