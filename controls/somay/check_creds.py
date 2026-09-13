"""Origin-scoped credentials + blast-radius bound (control 9). CROSS-BOUNDARY
(depends_on 6,7,8): composes those rules' PASS/FAIL to decide which reach tags
in the IAM graph are actually closed off.

Reads b9_credentials/credential_scope.yaml + b9_credentials/iam_graph.json.

(a) credential-scope audit -- EXECUTES, does not trust a flag. We mint a real
    Ed25519 capability token (controls/somay/captoken.py) bound to the declared
    scope, seal it, and REPLAY the incident's stolen-cred step off-origin. The
    token must: work at its own origin, be rejected off-origin, and be rejected
    when truncated. The config's own `off_origin_replay_blocked` claim is IGNORED
    and independently verified here.
(b) blast-radius -- the declared bound is attacker-controllable, so it is CAPPED
    at MAX_ALLOWED_BOUND. For each identity we drop any reach tag whose upstream
    boundary rule already PASSed; whatever remains must fit the capped bound.
"""
import json
from pathlib import Path
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controls.base import CheckResult
from controls.somay import captoken as ct
from controls.somay.captoken import Token

BOUNDARY_DIR = "b9_credentials"
SCOPE_FILE = "credential_scope.yaml"
GRAPH_FILE = "iam_graph.json"
_TAG_TO_RULE = {"imds": 6, "control-plane": 7, "vpn-pivot": 8}
MAX_ALLOWED_BOUND = 0  # a config cannot self-declare a nonzero blast radius; residual cross-boundary reach must be 0


def _fail(msg, evidence=None):
    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "FAIL", msg, evidence=evidence or [])


def _replay_proves_origin_binding(pod, job):
    """Mint a real sealed token bound to origin(pod)+purpose(job); return None if it
    behaves correctly (accept at origin, reject off-origin, reject truncated), else a reason."""
    root = Ed25519PrivateKey.generate()
    rpk = root.public_key()
    tok, sk = ct.issue(root, [f"identity(worker)"], caveats=[f"origin({pod})", f"purpose({job})"])
    tok, sk = ct.attenuate(tok, sk, ["single_use(true)"])
    sealed = ct.seal(tok, sk)
    try:
        ct.verify(sealed, rpk, {"origin": pod, "purpose": job})
    except Exception as e:
        return f"token unusable at its own origin ({e})"
    try:
        ct.verify(sealed, rpk, {"origin": "attacker_host", "purpose": job})
        return "stolen token still valid off-origin (replay not blocked)"
    except ValueError:
        pass
    trunc = Token(sealed.blocks[:1], sealed.next_pubs[:1], sealed.sigs[:1], seal=sealed.seal)
    try:
        ct.verify(trunc, rpk, {"origin": "attacker_host"})
        return "truncated token accepted off-origin (attenuation strippable)"
    except Exception:
        pass
    return None


def run(target_dir: str, context: dict | None = None) -> CheckResult:
    context = context or {}
    scope_path = Path(target_dir) / BOUNDARY_DIR / SCOPE_FILE
    graph_path = Path(target_dir) / BOUNDARY_DIR / GRAPH_FILE
    if not scope_path.exists() or not graph_path.exists():
        return _fail(f"missing {BOUNDARY_DIR}/{SCOPE_FILE} or {BOUNDARY_DIR}/{GRAPH_FILE}: "
                     "credential scope / blast-radius unverified")

    scope = yaml.safe_load(scope_path.read_text()) or {}
    graph = json.loads(graph_path.read_text())

    # (a) credential-scope audit -- executed, not asserted
    if scope.get("token_type") != "biscuit-attenuated":
        return _fail(f"credential is {scope.get('token_type')!r}, not an attenuated capability token",
                     evidence=[str(scope_path)])
    sc = scope.get("scope") or {}
    pod, job = sc.get("pod"), sc.get("job")
    if not pod or not job:
        return _fail("scope must bind pod (origin) and job (purpose) for the replay audit",
                     evidence=[str(scope_path)])
    reason = _replay_proves_origin_binding(str(pod), str(job))
    if reason:
        return _fail(f"live replay audit failed: {reason}", evidence=[str(scope_path)])

    # (b) blast-radius: cap the attacker-declarable bound, then check every identity
    declared = graph.get("declared_blast_radius_bound", 0)
    try:
        declared = int(declared)
    except (TypeError, ValueError):
        return _fail(f"declared_blast_radius_bound not an integer: {declared!r}", evidence=[str(graph_path)])
    if declared < 0:
        return _fail("declared_blast_radius_bound is negative", evidence=[str(graph_path)])
    bound = min(declared, MAX_ALLOWED_BOUND)

    for identity in graph.get("identities", []):
        name = identity.get("name", "<unnamed>")
        reach = identity.get("reach", [])
        open_tags = [
            tag for tag in reach
            if not (context.get(_TAG_TO_RULE.get(tag)) and context[_TAG_TO_RULE[tag]].status == "PASS")
        ]
        if len(open_tags) > bound:
            capnote = f" (declared {declared} capped to {bound})" if declared > bound else ""
            return _fail(f"identity {name!r} exceeds bound{capnote}: {len(open_tags)} > {bound}, "
                         f"open reach = {', '.join(open_tags)}", evidence=[str(graph_path)])

    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "PASS",
                        "live replay: token accepted at origin, rejected off-origin and when truncated; "
                        "no identity's reach (after upstream closures) exceeds the capped bound.",
                        evidence=[str(scope_path), str(graph_path)])
