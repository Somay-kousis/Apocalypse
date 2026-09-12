"""Origin-scoped credentials + blast-radius bound (control 9). CROSS-BOUNDARY
(depends_on 6,7,8): composes those rules' PASS/FAIL results to decide which
reach tags in the IAM graph are actually closed off.

Reads b9_credentials/credential_scope.yaml + b9_credentials/iam_graph.json, per
control_spec.yaml's boundary_dir / config_file / graph_file for this rule -
NOT root-level rbac.json/credentials.json (a stale legacy path whose `run()`
signature didn't even accept the `context` kwarg run_checks.py passes to
depends_on controls, so the cross-boundary composition this rule is supposed
to do was never actually wired up).

Reach-tag -> upstream-rule mapping (matches the boundaries each rule closes):
  "imds"          -> rule 6 (IMDS + SA-token lockdown)
  "control-plane" -> rule 7 (control-plane unreachable from workers)
  "vpn-pivot"     -> rule 8 (no reusable VPN keys + startup detection)
A tag only drops out of an identity's *effective* reach if the corresponding
upstream rule already PASSed; otherwise it counts against the declared bound.
"""
import json
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b9_credentials"
SCOPE_FILE = "credential_scope.yaml"
GRAPH_FILE = "iam_graph.json"

_TAG_TO_RULE = {"imds": 6, "control-plane": 7, "vpn-pivot": 8}


def _fail(msg, evidence=None):
    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "FAIL", msg, evidence=evidence or [])


def run(target_dir: str, context: dict | None = None) -> CheckResult:
    context = context or {}
    scope_path = Path(target_dir) / BOUNDARY_DIR / SCOPE_FILE
    graph_path = Path(target_dir) / BOUNDARY_DIR / GRAPH_FILE
    if not scope_path.exists() or not graph_path.exists():
        return _fail(f"missing {BOUNDARY_DIR}/{SCOPE_FILE} or {BOUNDARY_DIR}/{GRAPH_FILE}: "
                     "credential scope / blast-radius unverified")

    scope = yaml.safe_load(scope_path.read_text()) or {}
    graph = json.loads(graph_path.read_text())

    # (a) credential-scope audit: a stolen token must be dead off-origin.
    if scope.get("token_type") != "biscuit-attenuated" or scope.get("off_origin_replay_blocked") is not True:
        return _fail(f"credential is {scope.get('token_type')!r} "
                     f"(off_origin_replay_blocked={scope.get('off_origin_replay_blocked')!r}) - "
                     "stolen-cred replay off-origin is not blocked",
                     evidence=[str(scope_path)])

    # (b) blast-radius: for each identity, close off any reach tag whose
    # upstream boundary rule already PASSed; whatever's left must fit the bound.
    bound = graph.get("declared_blast_radius_bound", 0)
    for identity in graph.get("identities", []):
        name = identity.get("name", "<unnamed>")
        reach = identity.get("reach", [])
        open_tags = [
            tag for tag in reach
            if not (context.get(_TAG_TO_RULE.get(tag)) and context[_TAG_TO_RULE[tag]].status == "PASS")
        ]
        if len(open_tags) > bound:
            return _fail(f"identity {name!r} exceeds declared bound ({len(open_tags)} > {bound}): "
                         f"open reach = {', '.join(open_tags)}",
                         evidence=[str(graph_path)])

    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "PASS",
                        "credential dead off-origin under replay; no identity's reach "
                        "(after upstream boundary closures) exceeds the declared bound.",
                        evidence=[str(scope_path), str(graph_path)])
